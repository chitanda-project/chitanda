package client

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// TestH1DialContextCancellation verifies P2 issue 9:
// dialPlainH1 must unblock and terminate when the caller context is canceled,
// even if the server accepts the TCP connection but never returns headers.
func TestH1DialContextCancellation(t *testing.T) {
	// Start a silent dummy server that accepts TCP connections but writes nothing
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			// Keep connection open without writing anything
			time.Sleep(2 * time.Second)
		}
	}()

	psk := []byte("01234567890123456789012345678901")
	c, err := New(Config{
		Server:       ln.Addr().String(),
		ServerName:   "example.com",
		Path:         "/h1-test",
		PSK:          psk,
		TCPTransport: TCPTransportH1,
	})
	if err != nil {
		t.Fatalf("create client failed: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, dialErr := c.DialContext(ctx, "tcp", "target.com:80")
	elapsed := time.Since(start)

	if dialErr == nil {
		t.Fatalf("expected error from canceled context, got nil")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("dialPlainH1 took %v, failed to honor 100ms context cancellation!", elapsed)
	}
}

// TestQUICPacketConnSetReadDeadline verifies P2 issue 10:
// SetReadDeadline immediately wakes up blocked readers.
func TestQUICPacketConnSetReadDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pconn := &quicPacketConn{
		ctx:    ctx,
		cancel: cancel,
	}

	// Test 1: Past deadline returns DeadlineExceeded immediately
	pconn.SetReadDeadline(time.Now().Add(-1 * time.Second))
	buf := make([]byte, 128)
	_, _, err := pconn.ReadFrom(buf)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded for past deadline, got %v", err)
	}

	// Test 2: SetReadDeadline wakes up active readCancel callback
	canceled := make(chan struct{})
	pconn.readCancels = map[uint64]context.CancelFunc{1: func() {
		close(canceled)
	}}
	pconn.SetReadDeadline(time.Now().Add(5 * time.Second))

	select {
	case <-canceled:
		// Succeeded: readCancel was called immediately
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("SetReadDeadline failed to invoke active readCancel within 200ms")
	}
}
