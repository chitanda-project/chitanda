// Package connio adapts blocking embedded transports to recoverable deadlines.
// Queues are bounded; timeouts never spawn abandoned per-operation goroutines.
package connio

import (
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type deadline struct {
	mu      sync.Mutex
	at      time.Time
	changed chan struct{}
}

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	d.at = t
	if d.changed != nil {
		close(d.changed)
	}
	d.changed = make(chan struct{})
	d.mu.Unlock()
}
func (d *deadline) watch() (time.Time, <-chan struct{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.changed == nil {
		d.changed = make(chan struct{})
	}
	return d.at, d.changed
}
func deadlineTimer(t time.Time) (*time.Timer, <-chan time.Time) {
	if t.IsZero() {
		return nil, nil
	}
	timer := time.NewTimer(time.Until(t))
	return timer, timer.C
}
func stopTimer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}

type packet struct {
	data []byte
	addr net.Addr
	err  error
}
type writeResult struct {
	n   int
	err error
}

// Reader owns at most two chunks (one queued, one being fetched), plus the
// current partial chunk. next must return owned data, and interrupt must wake it.
type Reader struct {
	next      func() ([]byte, net.Addr, error)
	interrupt func() error
	once      sync.Once
	closeOnce sync.Once
	done      chan struct{}
	exited    chan struct{}
	queue     chan packet
	dl        deadline
	mu        sync.Mutex
	pending   packet
}

func NewReader(next func() ([]byte, net.Addr, error), interrupt func() error) *Reader {
	return &Reader{next: next, interrupt: interrupt, done: make(chan struct{}), exited: make(chan struct{}), queue: make(chan packet, 1)}
}
func (r *Reader) start() {
	r.once.Do(func() {
		go func() {
			defer close(r.exited)
			for {
				select {
				case <-r.done:
					return
				default:
				}
				b, a, e := r.next()
				select {
				case r.queue <- packet{data: b, addr: a, err: e}:
				case <-r.done:
					return
				}
				if e != nil {
					return
				}
			}
		}()
	})
}
func (r *Reader) get() (packet, error) {
	r.start()
	for {
		at, changed := r.dl.watch()
		select {
		case <-r.done:
			return packet{}, net.ErrClosed
		default:
		}
		if !at.IsZero() && !time.Now().Before(at) {
			return packet{}, os.ErrDeadlineExceeded
		}
		timer, timeout := deadlineTimer(at)
		select {
		case p := <-r.queue:
			stopTimer(timer)
			return p, nil
		case <-r.done:
			stopTimer(timer)
			return packet{}, net.ErrClosed
		case <-changed:
			stopTimer(timer)
		case <-timeout:
		}
	}
}
func (r *Reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	select {
	case <-r.done:
		return 0, net.ErrClosed
	default:
	}
	for len(r.pending.data) == 0 {
		if r.pending.err != nil {
			return 0, r.pending.err
		}
		item, err := r.get()
		if err != nil {
			return 0, err
		}
		r.pending = item
	}
	// Deadlines also apply when bytes are already buffered.
	at, _ := r.dl.watch()
	if !at.IsZero() && !time.Now().Before(at) {
		return 0, os.ErrDeadlineExceeded
	}
	n := copy(p, r.pending.data)
	r.pending.data = r.pending.data[n:]
	return n, nil
}
func (r *Reader) ReadPacket(p []byte) (int, net.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending.err != nil {
		return 0, nil, r.pending.err
	}
	item, err := r.get()
	if err != nil {
		return 0, nil, err
	}
	r.pending.err = item.err
	if len(item.data) == 0 && item.err != nil {
		return 0, nil, item.err
	}
	if len(p) < len(item.data) {
		return 0, item.addr, io.ErrShortBuffer
	}
	return copy(p, item.data), item.addr, nil
}
func (r *Reader) SetDeadline(t time.Time) error { r.dl.set(t); return nil }
func (r *Reader) Close() error {
	r.closeOnce.Do(func() {
		close(r.done)
		if r.interrupt != nil {
			_ = r.interrupt()
		}
	})
	r.start()
	<-r.exited
	return nil
}

type writeRequest struct {
	data   []byte
	bufPtr *[]byte
	addr   net.Addr
	resCh  chan writeResult
	refs   atomic.Int32
}

var writeRequestPool = sync.Pool{
	New: func() any {
		return &writeRequest{
			resCh: make(chan writeResult, 1),
		}
	},
}

var packetBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65536)
		return &b
	},
}

func (r *writeRequest) release() {
	if r.refs.Add(-1) != 0 {
		return
	}
	if r.bufPtr != nil {
		packetBufferPool.Put(r.bufPtr)
		r.bufPtr = nil
	}
	r.data = nil
	r.addr = nil
	select {
	case <-r.resCh:
	default:
	}
	writeRequestPool.Put(r)
}

// Writer accepts owned chunks into a bounded queue, like a socket send buffer.
// A successful write means accepted, not delivered. Timed-out, unaccepted bytes
// are never enqueued later. finish must half-close; abort must unblock write.
type Writer struct {
	write     func([]byte, net.Addr) (int, error)
	finish    func() error
	abort     func() error
	once      sync.Once
	closeOnce sync.Once
	done      chan struct{}
	exited    chan struct{}
	queue     chan *writeRequest
	dl        deadline
	gate      chan struct{}
	mu        sync.Mutex
	err       error
	fin       bool
}

func NewWriter(write func([]byte, net.Addr) (int, error), finish, abort func() error) *Writer {
	w := &Writer{write: write, finish: finish, abort: abort, done: make(chan struct{}), exited: make(chan struct{}), queue: make(chan *writeRequest, 1), gate: make(chan struct{}, 1)}
	w.gate <- struct{}{}
	return w
}
func (w *Writer) start() {
	w.once.Do(func() {
		go func() {
			defer close(w.exited)
			for {
				select {
				case <-w.done:
					return
				case req, ok := <-w.queue:
					if !ok {
						if w.finish != nil {
							w.setError(w.finish())
						}
						return
					}
					n, err := w.write(req.data, req.addr)
					if err == nil && n != len(req.data) {
						err = io.ErrShortWrite
					}
					if err != nil {
						w.setError(err)
						req.resCh <- writeResult{n, err}
						req.release()
						return
					}
					req.resCh <- writeResult{n, nil}
					req.release()
				}
			}
		}()
	})
}
func (w *Writer) setError(err error) {
	w.mu.Lock()
	if w.err == nil {
		w.err = err
	}
	w.mu.Unlock()
}
func (w *Writer) result() error { w.mu.Lock(); defer w.mu.Unlock(); return w.err }
func (w *Writer) acquire() error {
	w.start()
	for {
		at, changed := w.dl.watch()
		if !at.IsZero() && !time.Now().Before(at) {
			return os.ErrDeadlineExceeded
		}
		timer, timeout := deadlineTimer(at)
		select {
		case <-w.done:
			stopTimer(timer)
			return net.ErrClosed
		case <-w.exited:
			stopTimer(timer)
			if err := w.result(); err != nil {
				return err
			}
			return io.ErrClosedPipe
		case <-w.gate:
			stopTimer(timer)
			return nil
		case <-changed:
			stopTimer(timer)
		case <-timeout:
		}
	}
}
func (w *Writer) WritePacket(p []byte, addr net.Addr) (int, error) {
	if len(p) > 65535 {
		return 0, io.ErrShortBuffer
	}
	if err := w.acquire(); err != nil {
		return 0, err
	}
	defer func() { w.gate <- struct{}{} }()
	w.mu.Lock()
	fin, err := w.fin, w.err
	w.mu.Unlock()
	if err != nil {
		return 0, err
	}
	if fin {
		return 0, io.ErrClosedPipe
	}
	req := writeRequestPool.Get().(*writeRequest)
	bufPtr := packetBufferPool.Get().(*[]byte)
	copy(*bufPtr, p)
	req.data = (*bufPtr)[:len(p)]
	req.bufPtr = bufPtr
	req.addr = addr
	req.refs.Store(2)

	for {
		at, changed := w.dl.watch()
		select {
		case <-w.done:
			req.release()
			req.release()
			return 0, net.ErrClosed
		case <-w.exited:
			req.release()
			req.release()
			if err := w.result(); err != nil {
				return 0, err
			}
			return 0, net.ErrClosed
		default:
		}
		if !at.IsZero() && !time.Now().Before(at) {
			req.release()
			req.release()
			return 0, os.ErrDeadlineExceeded
		}
		timer, timeout := deadlineTimer(at)
		select {
		case w.queue <- req:
			stopTimer(timer)
			return w.awaitWrite(req)
		case <-w.done:
			stopTimer(timer)
			req.release()
			req.release()
			return 0, net.ErrClosed
		case <-w.exited:
			stopTimer(timer)
			req.release()
			req.release()
			if err := w.result(); err != nil {
				return 0, err
			}
			return 0, net.ErrClosed
		case <-changed:
			stopTimer(timer)
		case <-timeout:
		}
	}
}

func (w *Writer) awaitWrite(req *writeRequest) (int, error) {
	defer req.release()
	for {
		select {
		case result := <-req.resCh:
			return result.n, result.err
		default:
		}
		at, changed := w.dl.watch()
		// Once accepted, those bytes may still be delivered. Report them in n
		// on timeout so a caller never retries already-owned bytes as new data.
		if !at.IsZero() && !time.Now().Before(at) {
			return len(req.data), os.ErrDeadlineExceeded
		}
		timer, timeout := deadlineTimer(at)
		select {
		case result := <-req.resCh:
			stopTimer(timer)
			return result.n, result.err
		case <-w.done:
			stopTimer(timer)
			return len(req.data), net.ErrClosed
		case <-w.exited:
			stopTimer(timer)
			select {
			case result := <-req.resCh:
				return result.n, result.err
			default:
			}
			if err := w.result(); err != nil {
				return len(req.data), err
			}
			return len(req.data), net.ErrClosed
		case <-changed:
			stopTimer(timer)
		case <-timeout:
		}
	}
}
func (w *Writer) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		size := min(len(p), 65535)
		n, err := w.WritePacket(p[:size], nil)
		written += n
		p = p[n:]
		if err != nil {
			return written, err
		}
	}
	return written, nil
}
func (w *Writer) SetDeadline(t time.Time) error { w.dl.set(t); return nil }
func (w *Writer) CloseWrite() error {
	w.mu.Lock()
	fin := w.fin
	w.mu.Unlock()
	if !fin {
		if err := w.acquire(); err != nil {
			return err
		}
		w.mu.Lock()
		if !w.fin {
			w.fin = true
			close(w.queue)
		}
		w.mu.Unlock()
		w.gate <- struct{}{}
	}
	for {
		select {
		case <-w.exited:
			return w.result()
		default:
		}
		at, changed := w.dl.watch()
		if !at.IsZero() && !time.Now().Before(at) {
			return os.ErrDeadlineExceeded
		}
		timer, timeout := deadlineTimer(at)
		select {
		case <-w.exited:
			stopTimer(timer)
			return w.result()
		case <-w.done:
			stopTimer(timer)
			return net.ErrClosed
		case <-changed:
			stopTimer(timer)
		case <-timeout:
		}
	}
}
func (w *Writer) Close() error {
	w.closeOnce.Do(func() {
		close(w.done)
		if w.abort != nil {
			_ = w.abort()
		}
	})
	w.start()
	<-w.exited
	return nil
}
