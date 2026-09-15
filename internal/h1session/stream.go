package h1session

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
)

// FramedWriter encrypts outgoing byte streams into length-prefixed AEAD chunks.
type FramedWriter struct {
	w       io.Writer
	stream  *AEADStream
	mu      sync.Mutex
	flusher http.Flusher
	buf     []byte
	closed  bool
}

// NewFramedWriter wraps an io.Writer with an AEAD encryption stream.
func NewFramedWriter(w io.Writer, stream *AEADStream) *FramedWriter {
	flusher, _ := w.(http.Flusher)
	return &FramedWriter{
		w:       w,
		stream:  stream,
		flusher: flusher,
		buf:     make([]byte, 0, MaxChunkWireLen+2),
	}
}

func (fw *FramedWriter) Write(p []byte) (n int, err error) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if fw.closed {
		return 0, io.ErrClosedPipe
	}

	total := len(p)
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > MaxChunkPayloadLen {
			chunkSize = MaxChunkPayloadLen
		}
		chunk := p[:chunkSize]
		p = p[chunkSize:]

		fw.buf = fw.buf[:0]
		fw.buf, err = fw.stream.EncryptChunk(fw.buf, chunk)
		if err != nil {
			return n, err
		}

		if err := fw.flush(); err != nil {
			return n, err
		}
		if fw.flusher != nil {
			fw.flusher.Flush()
		}
		n += chunkSize
	}
	return total, nil
}

func (fw *FramedWriter) flush() error {
	n, err := fw.w.Write(fw.buf)
	if err == nil && n != len(fw.buf) {
		err = io.ErrShortWrite
	}
	if err != nil {
		fw.closed = true
	}
	return err
}

// WriteEOF authenticates the end of this direction using the next AEAD nonce.
func (fw *FramedWriter) WriteEOF() error {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if fw.closed {
		return nil
	}
	fw.closed = true
	var err error
	fw.buf, err = fw.stream.EncryptChunk(fw.buf[:0], nil)
	if err == nil {
		err = fw.flush()
	}
	if err == nil && fw.flusher != nil {
		fw.flusher.Flush()
	}
	return err
}

// FramedReader decrypts incoming length-prefixed AEAD chunks into a plaintext byte stream.
type FramedReader struct {
	r          io.Reader
	stream     *AEADStream
	mu         sync.Mutex
	hdrBuf     [2]byte
	rawBuf     []byte
	decBuf     []byte
	headerRead int
	bodyRead   int
	terminal   error
}

// NewFramedReader wraps an io.Reader with an AEAD decryption stream.
func NewFramedReader(r io.Reader, stream *AEADStream) *FramedReader {
	return &FramedReader{
		r:      r,
		stream: stream,
		rawBuf: make([]byte, MaxChunkWireLen),
	}
}

func (fr *FramedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	fr.mu.Lock()
	defer fr.mu.Unlock()

	if len(fr.decBuf) > 0 {
		n := copy(p, fr.decBuf)
		fr.decBuf = fr.decBuf[n:]
		return n, nil
	}
	if fr.terminal != nil {
		return 0, fr.terminal
	}

	// Read 2-byte chunk wire length
	if fr.headerRead < len(fr.hdrBuf) {
		n, err := io.ReadFull(fr.r, fr.hdrBuf[fr.headerRead:])
		fr.headerRead += n
		if err != nil {
			return 0, fr.readError(err)
		}
	}
	wireLen := int(binary.BigEndian.Uint16(fr.hdrBuf[:]))
	if wireLen < 16 {
		fr.terminal = ErrDecryptionFailed
		return 0, fr.terminal
	}
	if wireLen > MaxChunkWireLen {
		fr.terminal = ErrChunkTooLarge
		return 0, fr.terminal
	}

	raw := fr.rawBuf[:wireLen]
	nRead, readErr := io.ReadFull(fr.r, raw[fr.bodyRead:])
	fr.bodyRead += nRead
	if readErr != nil {
		return 0, fr.readError(readErr)
	}

	decrypted, err := fr.stream.DecryptChunk(nil, raw)
	if err != nil {
		fr.terminal = err
		return 0, err
	}
	fr.headerRead, fr.bodyRead = 0, 0
	if len(decrypted) == 0 {
		fr.terminal = io.EOF
		return 0, io.EOF
	}

	n := copy(p, decrypted)
	if n < len(decrypted) {
		fr.decBuf = append(fr.decBuf[:0], decrypted[n:]...)
	}
	return n, nil
}

func (fr *FramedReader) readError(err error) error {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return err
	}
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	fr.terminal = err
	return err
}

// Conn wraps a net.Conn with bidirectional AEAD framed reading and writing.
type Conn struct {
	net.Conn
	reader *FramedReader
	writer *FramedWriter
}

// NewConn wraps a net.Conn with AEAD stream framing.
func NewConn(raw net.Conn, clientKey, serverKey [32]byte, isClient bool) (*Conn, error) {
	var encStream, decStream *AEADStream
	var err error

	if isClient {
		encStream, err = NewAEADStream(clientKey, DirClientToServer)
		if err != nil {
			return nil, err
		}
		decStream, err = NewAEADStream(serverKey, DirServerToClient)
		if err != nil {
			return nil, err
		}
	} else {
		encStream, err = NewAEADStream(serverKey, DirServerToClient)
		if err != nil {
			return nil, err
		}
		decStream, err = NewAEADStream(clientKey, DirClientToServer)
		if err != nil {
			return nil, err
		}
	}

	return &Conn{
		Conn:   raw,
		reader: NewFramedReader(raw, decStream),
		writer: NewFramedWriter(raw, encStream),
	}, nil
}

func (c *Conn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *Conn) Write(p []byte) (int, error) {
	return c.writer.Write(p)
}

func (c *Conn) CloseWrite() error {
	if err := c.writer.WriteEOF(); err != nil {
		return err
	}
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *Conn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}
