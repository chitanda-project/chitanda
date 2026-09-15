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
	if deadline, ok := ctx.Deadline(); ok {
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
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("read response status: %w", err)
	}
	if !strings.Contains(statusLine, "200") {
		_ = rawConn.Close()
		return nil, fmt.Errorf("server rejected plain-h1: %s", strings.TrimSpace(statusLine))
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("read response header: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	chunkLenLine, err := reader.ReadString('\n')
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("read server hello chunk length: %w", err)
	}
	chunkLenHex := strings.TrimSpace(chunkLenLine)
	chunkLen, err := strconv.ParseInt(chunkLenHex, 16, 64)
	if err != nil || chunkLen < h1session.ServerHelloSize || chunkLen > h1session.ServerHelloSize+1024 {
		_ = rawConn.Close()
		return nil, fmt.Errorf("invalid server hello chunk length %q: %w", chunkLenHex, err)
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
	w  io.Writer
	mu sync.Mutex
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

	hdr := fmt.Sprintf("%x\r\n", len(p))
	if _, err := cw.w.Write([]byte(hdr)); err != nil {
		return 0, err
	}
	if _, err := cw.w.Write(p); err != nil {
		return 0, err
	}
	if _, err := cw.w.Write([]byte("\r\n")); err != nil {
		return 0, err
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
	r          *bufio.Reader
	chunkLeft  int64
	chunkEnded bool
}

func newChunkedReader(r *bufio.Reader) *chunkedReader {
	return &chunkedReader{r: r}
}

func (cr *chunkedReader) Read(p []byte) (int, error) {
	if cr.chunkEnded {
		return 0, io.EOF
	}

	if cr.chunkLeft == 0 {
		line, err := cr.r.ReadString('\n')
		if err != nil {
			return 0, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			line, err = cr.r.ReadString('\n')
			if err != nil {
				return 0, err
			}
			line = strings.TrimSpace(line)
		}
		chunkLen, err := strconv.ParseInt(line, 16, 64)
		if err != nil || chunkLen < 0 || chunkLen > 65536 {
			return 0, fmt.Errorf("invalid chunk length %q: %w", line, err)
		}
		if chunkLen == 0 {
			cr.chunkEnded = true
			return 0, io.EOF
		}
		cr.chunkLeft = chunkLen
	}

	toRead := int64(len(p))
	if toRead > cr.chunkLeft {
		toRead = cr.chunkLeft
	}

	n, err := cr.r.Read(p[:toRead])
	cr.chunkLeft -= int64(n)

	if cr.chunkLeft == 0 && err == nil {
		var crlf [2]byte
		if _, err := io.ReadFull(cr.r, crlf[:]); err != nil {
			return n, err
		}
	}
	return n, err
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
