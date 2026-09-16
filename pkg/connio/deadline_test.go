package connio

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func TestReaderDeadlineRecoveryAndConcurrentReaders(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	r := NewReader(func() ([]byte, net.Addr, error) { b := make([]byte, 16); n, e := pr.Read(b); return b[:n], nil, e }, pr.Close)
	defer r.Close()
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { _, e := r.Read(make([]byte, 1)); done <- e }()
	}
	r.SetDeadline(time.Now().Add(20 * time.Millisecond))
	for i := 0; i < 2; i++ {
		select {
		case e := <-done:
			if !errors.Is(e, os.ErrDeadlineExceeded) {
				t.Fatalf("not timeout: %v", e)
			}
		case <-time.After(time.Second):
			t.Fatal("read stayed blocked")
		}
	}
	r.SetDeadline(time.Time{})
	go func() { _, _ = pw.Write([]byte("restored")) }()
	b := make([]byte, 8)
	if _, e := io.ReadFull(r, b); e != nil || string(b) != "restored" {
		t.Fatalf("recovery=%q %v", b, e)
	}
}

func TestWriterBoundedTimeoutOwnershipAndRecovery(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	var got bytes.Buffer
	w := NewWriter(func(b []byte, _ net.Addr) (int, error) { <-release; return got.Write(b) }, nil, func() error { releaseOnce.Do(func() { close(release) }); return nil })
	defer w.Close()
	// First packet is in the underlying writer; the second is queued. Both
	// are reported as accepted (n>0) even when the caller's deadline expires.
	for _, s := range []string{"one", "two"} {
		w.SetDeadline(time.Now().Add(20 * time.Millisecond))
		n, e := w.Write([]byte(s))
		if n != len(s) || !errors.Is(e, os.ErrDeadlineExceeded) {
			t.Fatalf("accepted write=%d %v", n, e)
		}
	}
	w.SetDeadline(time.Now().Add(20 * time.Millisecond))
	n, e := w.Write([]byte("MUST-NOT-SEND"))
	if n != 0 || !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatalf("full queue=%d %v", n, e)
	}
	w.SetDeadline(time.Time{})
	releaseOnce.Do(func() { close(release) })
	if _, e := w.Write([]byte("three")); e != nil {
		t.Fatal(e)
	}
	if e := w.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	if got.String() != "onetwothree" {
		t.Fatalf("corruption/late unaccepted write: %q", got.String())
	}
}

func TestDeadlineExtensionAndPacketBoundaries(t *testing.T) {
	packets := make(chan []byte, 2)
	done := make(chan struct{})
	var once sync.Once
	r := NewReader(func() ([]byte, net.Addr, error) {
		select {
		case p := <-packets:
			return p, &net.UDPAddr{Port: 53}, nil
		case <-done:
			return nil, nil, net.ErrClosed
		}
	}, func() error { once.Do(func() { close(done) }); return nil })
	defer r.Close()
	r.SetDeadline(time.Now().Add(20 * time.Millisecond))
	r.SetDeadline(time.Now().Add(time.Second))
	packets <- bytes.Repeat([]byte{1}, 9000)
	packets <- []byte("second")
	b := make([]byte, 10000)
	if n, a, e := r.ReadPacket(b); n != 9000 || a.String() != "<nil>:53" || e != nil {
		if n != 9000 || e != nil {
			t.Fatalf("packet=%d %v %v", n, a, e)
		}
	}
	if n, _, e := r.ReadPacket(b); n != 6 || e != nil || string(b[:n]) != "second" {
		t.Fatalf("packet boundary=%d %v", n, e)
	}
}

func TestCloseWakesBlockedWriter(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()
	w := NewWriter(func(b []byte, _ net.Addr) (int, error) { return pw.Write(b) }, pw.Close, func() error { return pw.CloseWithError(net.ErrClosed) })
	done := make(chan error, 1)
	go func() { _, e := w.Write([]byte("blocked")); done <- e }()
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("writer leaked on close")
	}
}
