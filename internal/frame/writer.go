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
func (w *StreamWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failed != nil {
		return 0, w.failed
	}
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	n := 0
	for len(p) > 0 {
		size := min(len(p), DataChunkSize)
		if err := WriteFrame(w.w, TypeData, 0, p[:size]); err != nil {
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
