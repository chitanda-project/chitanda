package server

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type streamShutdownConn struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
	exit    <-chan struct{}
}

func (c *streamShutdownConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	n, err := c.Conn.Read(p)
	if c.exit != nil {
		<-c.exit
	}
	return n, err
}

type streamShutdownListener struct {
	net.Listener
	entered chan struct{}
}

func (l *streamShutdownListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &streamShutdownConn{Conn: c, entered: l.entered}, nil
}

func TestStreamShutdownInterruptsAcceptedHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	s := NewStreamServer(bytes.Repeat([]byte{'s'}, 32), "", nil, nil)
	defer s.Close()
	entered := make(chan struct{})
	served := make(chan error, 1)
	go func() { served <- s.Serve(&streamShutdownListener{Listener: ln, entered: entered}) }()
	peer, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("handshake did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		// Unblock old code as well, so a red regression leaves no goroutine.
		_ = peer.Close()
		<-closed
		t.Fatal("Close did not interrupt the accepted handshake; waited for its deadline")
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	if active := s.activeConns.Load(); active != 0 {
		t.Fatalf("Close returned with %d accepted connections", active)
	}
}

func TestStreamShutdownJoinsEmbeddedHandler(t *testing.T) {
	s := NewStreamServer(bytes.Repeat([]byte{'s'}, 32), "", nil, nil)
	defer s.Close()
	local, peer := net.Pipe()
	defer peer.Close()
	exit := make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(exit) })
	conn := &streamShutdownConn{Conn: local, entered: make(chan struct{}), exit: exit}
	handled := make(chan struct{})
	go func() { s.HandleConnContext(context.Background(), conn); close(handled) }()
	select {
	case <-conn.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("embedded handshake did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	// Cancellation has actually interrupted I/O, but the handler cannot exit
	// its Read until the explicit barrier is released.
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("Close did not close embedded socket: %v", err)
	}
	select {
	case <-closed:
		release.Do(func() { close(exit) })
		<-handled
		t.Fatal("Close returned before the embedded handler released its reservation")
	case <-time.After(20 * time.Millisecond):
	}
	release.Do(func() { close(exit) })
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join the released handler")
	}
	<-handled
	if s.activeConns.Load() != 0 {
		t.Fatal("embedded connection reservation leaked")
	}
}

func TestStreamShutdownConcurrentAdmission(t *testing.T) {
	for round := 0; round < 20; round++ {
		s := NewStreamServer(bytes.Repeat([]byte{'s'}, 32), "", nil, nil)
		start := make(chan struct{})
		var handlers sync.WaitGroup
		for i := 0; i < 16; i++ {
			local, peer := net.Pipe()
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer peer.Close()
				<-start
				s.HandleConn(local)
			}()
		}
		closed := make(chan struct{})
		go func() { <-start; _ = s.Close(); close(closed) }()
		close(start)
		select {
		case <-closed:
		case <-time.After(3 * time.Second):
			t.Fatal("concurrent admission and Close did not settle")
		}
		handlers.Wait()
		if active := s.activeConns.Load(); active != 0 || len(s.handshakeSem) != 0 {
			t.Fatalf("round %d: active=%d handshakes=%d after Close", round, active, len(s.handshakeSem))
		}
	}
}
