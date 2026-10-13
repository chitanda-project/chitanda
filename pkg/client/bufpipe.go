package client

import (
	"io"
	"sync"
)

type bufferedPipe struct {
	mu       sync.Mutex
	cond     sync.Cond
	buf      []byte
	capacity int
	head     int
	tail     int
	count    int
	closed   bool
	err      error
}

type bufferedPipeReader struct {
	pipe *bufferedPipe
}

type bufferedPipeWriter struct {
	pipe *bufferedPipe
}

func newBufferedPipe(capacity int) (*bufferedPipeReader, *bufferedPipeWriter) {
	if capacity <= 0 {
		capacity = 128 * 1024
	}
	p := &bufferedPipe{
		capacity: capacity,
	}
	p.cond.L = &p.mu
	return &bufferedPipeReader{pipe: p}, &bufferedPipeWriter{pipe: p}
}

func (r *bufferedPipeReader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	p := r.pipe
	p.mu.Lock()
	defer p.mu.Unlock()

	for p.count == 0 {
		if p.err != nil {
			return 0, p.err
		}
		if p.closed {
			return 0, io.EOF
		}
		p.cond.Wait()
	}

	n := 0
	for n < len(b) && p.count > 0 {
		chunk := len(b) - n
		avail := len(p.buf) - p.head
		if avail > p.count {
			avail = p.count
		}
		if chunk > avail {
			chunk = avail
		}
		copy(b[n:n+chunk], p.buf[p.head:p.head+chunk])
		p.head = (p.head + chunk) % len(p.buf)
		p.count -= chunk
		n += chunk
	}

	p.cond.Broadcast()
	return n, nil
}

func (r *bufferedPipeReader) Close() error {
	return r.CloseWithError(io.ErrClosedPipe)
}

func (r *bufferedPipeReader) CloseWithError(err error) error {
	if err == nil {
		err = io.ErrClosedPipe
	}
	p := r.pipe
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err == nil {
		p.err = err
	}
	p.closed = true
	p.cond.Broadcast()
	return nil
}

func (w *bufferedPipeWriter) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	p := w.pipe
	p.mu.Lock()
	defer p.mu.Unlock()

	total := len(b)
	written := 0

	for written < total {
		if p.err != nil {
			return written, p.err
		}
		if p.closed {
			return written, io.ErrClosedPipe
		}
		if len(p.buf) < p.capacity && p.count+total-written > len(p.buf) {
			capacity := min(p.capacity, max(16*1024, max(len(p.buf)*2, p.count+total-written)))
			grown := make([]byte, capacity)
			if p.count > 0 {
				first := min(p.count, len(p.buf)-p.head)
				copy(grown, p.buf[p.head:p.head+first])
				copy(grown[first:], p.buf[:p.count-first])
			}
			p.buf, p.head, p.tail = grown, 0, p.count%capacity
		}
		for p.count == len(p.buf) {
			if p.err != nil {
				return written, p.err
			}
			if p.closed {
				return written, io.ErrClosedPipe
			}
			p.cond.Wait()
		}

		if p.err != nil {
			return written, p.err
		}
		if p.closed {
			return written, io.ErrClosedPipe
		}

		chunk := total - written
		space := len(p.buf) - p.count
		avail := len(p.buf) - p.tail
		if avail > space {
			avail = space
		}
		if chunk > avail {
			chunk = avail
		}

		copy(p.buf[p.tail:p.tail+chunk], b[written:written+chunk])
		p.tail = (p.tail + chunk) % len(p.buf)
		p.count += chunk
		written += chunk

		p.cond.Broadcast()
	}

	return total, nil
}

func (w *bufferedPipeWriter) Close() error {
	p := w.pipe
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.cond.Broadcast()
	return nil
}

func (w *bufferedPipeWriter) CloseWithError(err error) error {
	if err == nil {
		err = io.EOF
	}
	p := w.pipe
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err == nil {
		p.err = err
	}
	p.closed = true
	p.cond.Broadcast()
	return nil
}

type pipeWriteCloser interface {
	io.WriteCloser
	CloseWithError(err error) error
}
