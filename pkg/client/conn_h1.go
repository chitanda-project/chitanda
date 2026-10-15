package client

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpguts"

	"github.com/violetaini/chitanda/internal/h1session"
)

type plainH1Conn struct {
	raw          net.Conn
	reader       *bufio.Reader
	framedReader *h1session.FramedReader
	framedWriter *h1session.FramedWriter
	chunkWriter  *chunkedWriter
	closeOnce    sync.Once
	closed       chan struct{}
}

func (c *Client) dialPlainH1(ctx context.Context, target string) (net.Conn, error) {
	rawConn, err := c.dialRaw(ctx, "tcp", c.cfg.Server)
	if err != nil {
		return nil, fmt.Errorf("plain-h1 dial server %q: %w", c.cfg.Server, err)
	}
	if tc, ok := rawConn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(15 * time.Second)
	} else if kac, ok := rawConn.(interface {
		SetKeepAlive(bool) error
		SetKeepAlivePeriod(time.Duration) error
	}); ok {
		_ = kac.SetKeepAlive(true)
		_ = kac.SetKeepAlivePeriod(15 * time.Second)
	}

	// 1. Map context deadline to connection deadline to prevent indefinite hanging
	if deadline, ok := rawHandshakeDeadline(ctx); ok {
		_ = rawConn.SetDeadline(deadline)
	} else {
		_ = rawConn.SetDeadline(time.Now().Add(10 * time.Second))
	}

	// 2. Hook context cancellation to immediately close rawConn if caller aborts
	stopCancel := context.AfterFunc(ctx, func() {
		_ = rawConn.Close()
	})
	defer stopCancel()

	now := time.Now()
	clientHello, clientNonce, ts, err := h1session.CreateClientHello(c.cfg.PSK, now)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("create client hello: %w", err)
	}

	// Derive 0-RTT key for Flight 1 payload
	k0RTT, err := h1session.Derive0RTTKey(c.cfg.PSK, ts, clientNonce)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("derive 0-rtt key: %w", err)
	}

	openFrame, err := h1session.EncodeOpenFrame(target, nil)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("encode open frame: %w", err)
	}

	encrypted0RTT, err := h1session.Encrypt0RTTChunk(k0RTT, openFrame)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("encrypt 0-rtt chunk: %w", err)
	}

	// Assemble Flight 1 (HTTP Headers + Chunk 1 ClientHello + Chunk 2 0-RTT OPEN Frame)
	var flight1 bytes.Buffer
	reqHeaders := fmt.Sprintf(
		"POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"+
			"Content-Type: application/octet-stream\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n",
		c.cfg.Path, c.cfg.Server,
	)
	flight1.WriteString(reqHeaders)

	// Chunk 1: ClientHello
	flight1.WriteString(fmt.Sprintf("%x\r\n", len(clientHello)))
	flight1.Write(clientHello)
	flight1.WriteString("\r\n")

	// Chunk 2: 0-RTT OPEN Frame
	flight1.WriteString(fmt.Sprintf("%x\r\n", len(encrypted0RTT)))
	flight1.Write(encrypted0RTT)
	flight1.WriteString("\r\n")

	// Single 0-RTT TCP write burst!
	if _, err := rawConn.Write(flight1.Bytes()); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("write flight 1 0-rtt request: %w", err)
	}

	reader := bufio.NewReader(rawConn)
	if err := readH1ResponseHeaders(reader); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	var lineState boundedH1Line
	chunkLenLine, err := lineState.read(reader, maxH1ChunkLine)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("read server hello chunk length: %w", err)
	}
	chunkLen, err := parseH1ChunkSize(chunkLenLine)
	if err != nil || chunkLen < h1session.ServerHelloSize || chunkLen > h1session.ServerHelloSize+1024 {
		_ = rawConn.Close()
		return nil, fmt.Errorf("invalid server hello chunk length: %v", err)
	}

	var serverHello [h1session.ServerHelloSize]byte
	if _, err := io.ReadFull(reader, serverHello[:]); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("read server hello: %w", err)
	}

	clientKey, serverKey, err := h1session.VerifyServerHello(c.cfg.PSK, clientNonce, serverHello[:])
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("verify server hello failed: %w", err)
	}

	if chunkLen > h1session.ServerHelloSize {
		// Authenticated! Drain any remaining chunk padding safely without allocating dynamic slice
		if _, err := io.CopyN(io.Discard, reader, chunkLen-h1session.ServerHelloSize); err != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("read server hello remainder: %w", err)
		}
	}
	var crlf [2]byte
	if _, err := io.ReadFull(reader, crlf[:]); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("read chunk crlf: %w", err)
	}
	if crlf != [2]byte{'\r', '\n'} {
		_ = rawConn.Close()
		return nil, fmt.Errorf("invalid server hello chunk terminator")
	}

	encStream, err := h1session.NewAEADStream(clientKey, h1session.DirClientToServer)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	decStream, err := h1session.NewAEADStream(serverKey, h1session.DirServerToClient)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	cw := newChunkedWriter(rawConn)
	cr := newChunkedReader(reader)

	framedWriter := h1session.NewFramedWriter(cw, encStream)
	framedReader := h1session.NewFramedReader(cr, decStream)

	// Clear handshake deadline for established full-duplex session
	_ = rawConn.SetDeadline(time.Time{})

	conn := &plainH1Conn{
		raw:          rawConn,
		reader:       reader,
		framedReader: framedReader,
		framedWriter: framedWriter,
		chunkWriter:  cw,
		closed:       make(chan struct{}),
	}
	return conn, nil
}

type chunkedWriter struct {
	w   io.Writer
	mu  sync.Mutex
	buf []byte
}

func newChunkedWriter(w io.Writer) *chunkedWriter {
	return &chunkedWriter{w: w}
}

func (cw *chunkedWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	cw.mu.Lock()
	defer cw.mu.Unlock()

	cw.buf = strconv.AppendUint(cw.buf[:0], uint64(len(p)), 16)
	cw.buf = append(cw.buf, '\r', '\n')
	cw.buf = append(cw.buf, p...)
	cw.buf = append(cw.buf, '\r', '\n')
	n, err := cw.w.Write(cw.buf)
	if err != nil {
		return 0, err
	}
	if n != len(cw.buf) {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

func (cw *chunkedWriter) Close() error {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	_, err := cw.w.Write([]byte("0\r\n\r\n"))
	return err
}

type chunkedReader struct {
	r            *bufio.Reader
	chunkLeft    int64
	chunkEnded   bool
	line         boundedH1Line
	needCRLF     bool
	crlf         [2]byte
	crlfRead     int
	trailers     bool
	trailerBytes int
	trailerLines int
	terminal     error
}

func newChunkedReader(r *bufio.Reader) *chunkedReader {
	return &chunkedReader{r: r}
}

func (cr *chunkedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if cr.terminal != nil {
		return 0, cr.terminal
	}
	if cr.chunkEnded {
		return 0, io.EOF
	}

	if cr.needCRLF {
		n, err := io.ReadFull(cr.r, cr.crlf[cr.crlfRead:])
		cr.crlfRead += n
		if err != nil {
			return 0, cr.readError(err)
		}
		if cr.crlf != [2]byte{'\r', '\n'} {
			return 0, cr.readError(fmt.Errorf("invalid chunk terminator"))
		}
		cr.needCRLF, cr.crlfRead = false, 0
	}
	if cr.chunkLeft == 0 && !cr.trailers {
		line, err := cr.line.read(cr.r, maxH1ChunkLine)
		if err != nil {
			return 0, cr.readError(err)
		}
		size, err := parseH1ChunkSize(line)
		if err != nil || size > 65536 {
			return 0, cr.readError(fmt.Errorf("invalid chunk length"))
		}
		cr.chunkLeft = size
		cr.trailers = size == 0
	}
	if cr.trailers {
		for {
			line, err := cr.line.read(cr.r, min(maxH1HeaderLine, maxH1HeaderBytes-cr.trailerBytes))
			if err != nil {
				return 0, cr.readError(err)
			}
			cr.trailerBytes += len(line) + 2
			if line == "" {
				cr.chunkEnded = true
				return 0, io.EOF
			}
			cr.trailerLines++
			if cr.trailerLines > maxH1HeaderLines || !validH1Header(line) {
				return 0, cr.readError(fmt.Errorf("invalid chunk trailer"))
			}
		}
	}

	toRead := int64(len(p))
	if toRead > cr.chunkLeft {
		toRead = cr.chunkLeft
	}

	n, err := cr.r.Read(p[:toRead])
	cr.chunkLeft -= int64(n)

	if cr.chunkLeft == 0 {
		cr.needCRLF = true
	}
	if err != nil {
		err = cr.readError(err)
	}
	return n, err
}

func (cr *chunkedReader) readError(err error) error {
	if e, ok := err.(net.Error); ok && e.Timeout() {
		return err
	}
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	cr.terminal = err
	return err
}

const (
	maxH1HeaderBytes = 16 << 10
	maxH1HeaderLine  = 4 << 10
	maxH1HeaderLines = 64
	maxH1ChunkLine   = 1024
)

// ReadSlice avoids unbounded ReadString allocations. Keep partial input on a
// recoverable socket timeout; callers must not restart a line in the middle.
type boundedH1Line struct{ partial []byte }

func (s *boundedH1Line) read(r *bufio.Reader, limit int) (string, error) {
	for {
		part, err := r.ReadSlice('\n')
		if len(part) > limit-len(s.partial) {
			return "", fmt.Errorf("H1 line exceeds byte limit")
		}
		s.partial = append(s.partial, part...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return "", err
		}
		line := s.partial
		if len(line) < 2 || line[len(line)-2] != '\r' {
			return "", fmt.Errorf("H1 requires CRLF")
		}
		result := string(line[:len(line)-2])
		s.partial = s.partial[:0]
		return result, nil
	}
}

func parseH1ChunkSize(line string) (int64, error) {
	if len(line) == 0 || len(line) > 16 {
		return 0, fmt.Errorf("invalid chunk size")
	}
	for _, c := range []byte(line) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return 0, fmt.Errorf("invalid chunk size")
		}
	}
	return strconv.ParseInt(line, 16, 64)
}

func validH1Header(line string) bool {
	name, value, ok := strings.Cut(line, ":")
	return ok && httpguts.ValidHeaderFieldName(name) && httpguts.ValidHeaderFieldValue(value)
}

func readH1ResponseHeaders(r *bufio.Reader) error {
	var state boundedH1Line
	line, err := state.read(r, maxH1HeaderLine)
	if err != nil {
		return fmt.Errorf("read H1 response status: %w", err)
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 || parts[0] != "HTTP/1.1" || parts[1] != "200" {
		return fmt.Errorf("unexpected H1 response status")
	}
	used, count, chunked := len(line)+2, 0, false
	for {
		line, err = state.read(r, min(maxH1HeaderLine, maxH1HeaderBytes-used))
		if err != nil {
			return fmt.Errorf("read H1 response headers: %w", err)
		}
		used += len(line) + 2
		if line == "" {
			break
		}
		count++
		if count > maxH1HeaderLines || !validH1Header(line) {
			return fmt.Errorf("invalid H1 response headers")
		}
		name, value, _ := strings.Cut(line, ":")
		if strings.EqualFold(name, "Content-Length") {
			return fmt.Errorf("unexpected H1 content length")
		}
		if strings.EqualFold(name, "Transfer-Encoding") {
			if chunked || !strings.EqualFold(strings.TrimSpace(value), "chunked") {
				return fmt.Errorf("unsupported H1 transfer encoding")
			}
			chunked = true
		}
	}
	if !chunked {
		return fmt.Errorf("H1 response must use chunked transfer encoding")
	}
	return nil
}

func (c *plainH1Conn) Read(b []byte) (n int, err error) {
	return c.framedReader.Read(b)
}

func (c *plainH1Conn) Write(b []byte) (n int, err error) {
	return c.framedWriter.Write(b)
}

func (c *plainH1Conn) CloseWrite() error {
	if err := c.framedWriter.WriteEOF(); err != nil {
		return err
	}
	return c.chunkWriter.Close()
}

func (c *plainH1Conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = c.raw.Close()
		_ = c.chunkWriter.Close()
	})
	return nil
}

func (c *plainH1Conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *plainH1Conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *plainH1Conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *plainH1Conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *plainH1Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
