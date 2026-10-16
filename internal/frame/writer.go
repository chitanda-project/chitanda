package frame

import (
	"io"
	"sync"
)

type StreamWriter struct {
	w      io.Writer
	mu     sync.Mutex
	closed bool
	failed error
}

func NewStreamWriter(w io.Writer) *StreamWriter { return &StreamWriter{w: w} }

// Borrow per call, not per connection: idle SSH flows must not each retain a
// bulk-transfer buffer. Size classes bound small writes without allocating a
// fresh header+payload slice for every DATA frame.
var (
	streamWriteSmall  = newStreamWritePool(256)
	streamWriteMedium = newStreamWritePool(4 << 10)
	streamWriteLarge  = newStreamWritePool(32 << 10)
)

func newStreamWritePool(payload int) *sync.Pool {
	return &sync.Pool{New: func() any {
		b := make([]byte, HeaderSize+payload)
		return &b
	}}
}

func streamWritePool(payload int) *sync.Pool {
	switch {
	case payload <= 256:
		return streamWriteSmall
	case payload <= 4<<10:
		return streamWriteMedium
	case payload <= 32<<10:
		return streamWriteLarge
	default:
		return &dataChunkBufPool
	}
}

func (w *StreamWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failed != nil {
		return 0, w.failed
	}
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 {
		return 0, nil
	}
	pool := streamWritePool(min(len(p), DataChunkSize))
	buf := pool.Get().(*[]byte)
	defer pool.Put(buf)
	n := 0
	for len(p) > 0 {
		size := min(len(p), DataChunkSize)
		wire := (*buf)[:HeaderSize+size]
		encodeHeader(wire[:HeaderSize], TypeData, 0, uint32(size))
		copy(wire[HeaderSize:], p[:size])
		if err := writeFull(w.w, wire); err != nil {
			w.failed = err
			return n, err
		}
		n += size
		p = p[size:]
	}
	return n, nil
}
func (w *StreamWriter) CloseWrite() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failed != nil {
		return w.failed
	}
	if w.closed {
		return nil
	}
	w.closed = true
	w.failed = WriteFrame(w.w, TypeHalfClose, 0, nil)
	return w.failed
}
