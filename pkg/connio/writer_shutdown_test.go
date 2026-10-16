package connio

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// Both requests are admitted through the public API. The first is blocked in
// the underlying writer; the second waits in the bounded queue after timeout.
func TestWriterShutdownReleasesQueuedRequest(t *testing.T) {
	for _, closeWriter := range []bool{false, true} {
		name := "underlying-error"
		if closeWriter {
			name = "close"
		}
		t.Run(name, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			w := NewWriter(func([]byte, net.Addr) (int, error) {
				close(entered)
				<-release
				return 0, io.ErrUnexpectedEOF
			}, nil, func() error { unblock(); return nil })
			t.Cleanup(func() { unblock(); _ = w.Close() })
			result := make(chan error, 1)
			go func() { _, err := w.WritePacket([]byte("first"), nil); result <- err }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("underlying write did not start")
			}
			_ = w.SetDeadline(time.Now().Add(-time.Second))
			if err := <-result; !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("first write: %v", err)
			}
			_ = w.SetDeadline(time.Now().Add(20 * time.Millisecond))
			n, err := w.WritePacket([]byte("queued"), nil)
			if n != len("queued") || !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("queued write = %d, %v", n, err)
			}
			// The worker cannot read this queue until release is closed.
			req := <-w.queue
			w.queue <- req
			if closeWriter {
				_ = w.Close()
			} else {
				unblock()
				select {
				case <-w.exited:
				case <-time.After(time.Second):
					t.Fatal("worker did not exit")
				}
			}
			if len(w.queue) != 0 || req.refs.Load() != 0 || req.bufPtr != nil {
				t.Fatalf("queued buffer retained after shutdown: queued=%d refs=%d buffer=%t", len(w.queue), req.refs.Load(), req.bufPtr != nil)
			}
		})
	}
}

func TestWriterShutdownWakesQueuedCaller(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	w := NewWriter(func([]byte, net.Addr) (int, error) {
		close(entered)
		<-release
		return 0, io.ErrUnexpectedEOF
	}, nil, func() error { unblock(); return nil })
	t.Cleanup(func() { unblock(); _ = w.Close() })
	result := make(chan error, 1)
	go func() { _, err := w.WritePacket([]byte("first"), nil); result <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("underlying write did not start")
	}
	_ = w.SetDeadline(time.Now().Add(-time.Second))
	if err := <-result; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("first write: %v", err)
	}
	_ = w.SetDeadline(time.Time{})
	go func() { _, err := w.WritePacket([]byte("queued"), nil); result <- err }()
	select {
	case req := <-w.queue:
		w.queue <- req
	case <-time.After(time.Second):
		t.Fatal("second write was not queued")
	}
	unblock()
	select {
	case err := <-result:
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("queued caller lost terminal error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown waits for a caller still awaiting shutdown")
	}
	_ = w.Close()
	if len(w.queue) != 0 {
		t.Fatal("queued request retained after caller was woken")
	}
}

func TestWriterShutdownConcurrentAdmission(t *testing.T) {
	for i := 0; i < 100; i++ {
		w := NewWriter(func(p []byte, _ net.Addr) (int, error) { return len(p), nil }, nil, nil)
		start := make(chan struct{})
		var workers sync.WaitGroup
		for j := 0; j < 4; j++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-start
				_, _ = w.WritePacket([]byte("shutdown race"), nil)
			}()
		}
		close(start)
		_ = w.Close()
		workers.Wait()
		if len(w.queue) != 0 {
			t.Fatalf("iteration %d: request admitted after drain", i)
		}
	}
}
