package client

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

// Deliberately does not wake readers from CancelRead/Close. Like stock HTTP
// Datagram queues, this receiver needs cancellation of its receive context.
type lifecycleH3Stream struct {
	readEntered  chan struct{}
	writeEntered chan struct{}
	writes       atomic.Int32
	closes       atomic.Int32
}

func (s *lifecycleH3Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case s.readEntered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}
func (s *lifecycleH3Stream) SendDatagram([]byte) error {
	s.writes.Add(1)
	return errors.New("unexpected uncancellable send")
}
func (s *lifecycleH3Stream) SendDatagramContext(ctx context.Context, _ []byte) error {
	s.writes.Add(1)
	select {
	case s.writeEntered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}
func (s *lifecycleH3Stream) SendDatagramsContext(ctx context.Context, _ [][]byte) error {
	return s.SendDatagramContext(ctx, nil)
}
func (*lifecycleH3Stream) CancelRead(quic.StreamErrorCode)  {}
func (*lifecycleH3Stream) CancelWrite(quic.StreamErrorCode) {}
func (s *lifecycleH3Stream) Close() error                   { s.closes.Add(1); return nil }

func TestH3PacketLifecycleCancelsPendingIO(t *testing.T) {
	for _, shutdown := range []string{"manager", "connection", "association"} {
		t.Run(shutdown, func(t *testing.T) {
			physical, closePhysical := context.WithCancel(context.Background())
			defer closePhysical()
			manager, closeManager := context.WithCancel(context.Background())
			defer closeManager()
			ctx, cancel := newH3PacketContext(physical, manager)
			stream := &lifecycleH3Stream{readEntered: make(chan struct{}, 4), writeEntered: make(chan struct{}, 2)}
			p := &quicPacketConn{ctx: ctx, cancel: cancel, stream: stream}
			defer p.Close()
			readDone, writeDone := make(chan error, 4), make(chan error, 2)
			for range 4 {
				go func() { _, _, err := p.ReadFrom(make([]byte, 32)); readDone <- err }()
			}
			addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}
			go func() { _, err := p.WriteTo([]byte("one"), addr); writeDone <- err }()
			go func() { writeDone <- p.WriteBatch([][]byte{[]byte("two"), []byte("three")}, []net.Addr{addr, addr}) }()
			for range 4 {
				waitRawTest(t, stream.readEntered, "read did not enter receive queue")
			}
			for range 2 {
				waitRawTest(t, stream.writeEntered, "write did not enter send queue")
			}
			switch shutdown {
			case "manager":
				closeManager()
			case "connection":
				closePhysical()
			case "association":
				_ = p.Close()
			}
			for _, result := range []struct {
				ch <-chan error
				n  int
			}{{readDone, 4}, {writeDone, 2}} {
				for range result.n {
					select {
					case err := <-result.ch:
						if err == nil {
							t.Fatal("shutdown returned successful I/O")
						}
					case <-time.After(time.Second):
						t.Fatal("shutdown left pending I/O blocked")
					}
				}
			}
			if _, err := p.WriteTo([]byte("late"), addr); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("late WriteTo = %v, want closed", err)
			}
			if err := p.WriteBatch([][]byte{[]byte("late"), []byte("late")}, []net.Addr{addr, addr}); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("late WriteBatch = %v, want closed", err)
			}
			if stream.writes.Load() != 2 {
				t.Fatal("closed association reached the stream send queue again")
			}
			if shutdown == "association" && (physical.Err() != nil || manager.Err() != nil) {
				t.Fatal("association close canceled its shared parent")
			}
		})
	}
}

func TestH3PacketLifecycleIndependentAssociations(t *testing.T) {
	physical, closePhysical := context.WithCancel(context.Background())
	defer closePhysical()
	manager, closeManager := context.WithCancel(context.Background())
	defer closeManager()
	first, closeFirst := newH3PacketContext(physical, manager)
	second, closeSecond := newH3PacketContext(physical, manager)
	defer closeSecond()
	closeFirst()
	closeFirst()
	if first.Err() == nil || second.Err() != nil || physical.Err() != nil || manager.Err() != nil {
		t.Fatal("association close affected another association or shared parent")
	}
	closeManager()
	waitRawTest(t, second.Done(), "manager close did not cancel remaining association")
}

func TestH3PacketLifecycleAlreadyClosedParents(t *testing.T) {
	for _, owner := range []string{"manager", "connection"} {
		t.Run(owner, func(t *testing.T) {
			physical, closePhysical := context.WithCancel(context.Background())
			defer closePhysical()
			manager, closeManager := context.WithCancel(context.Background())
			defer closeManager()
			if owner == "manager" {
				closeManager()
			} else {
				closePhysical()
			}
			ctx, cancel := newH3PacketContext(physical, manager)
			defer cancel()
			if ctx.Err() == nil {
				t.Fatal("already closed parent published a live association context")
			}
		})
	}
}

func TestH3PacketLifecycleConcurrentCloseAndDeadlines(t *testing.T) {
	physical, closePhysical := context.WithCancel(context.Background())
	defer closePhysical()
	manager, closeManager := context.WithCancel(context.Background())
	defer closeManager()
	ctx, cancel := newH3PacketContext(physical, manager)
	stream := &lifecycleH3Stream{readEntered: make(chan struct{}, 1), writeEntered: make(chan struct{}, 1)}
	p := &quicPacketConn{ctx: ctx, cancel: cancel, stream: stream}
	defer p.Close()
	readDone, writeDone := make(chan error, 1), make(chan error, 1)
	go func() { _, _, err := p.ReadFrom(make([]byte, 32)); readDone <- err }()
	go func() {
		_, err := p.WriteTo([]byte("pending"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53})
		writeDone <- err
	}()
	waitRawTest(t, stream.readEntered, "read did not enter")
	waitRawTest(t, stream.writeEntered, "write did not enter")
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch i % 4 {
			case 0:
				_ = p.Close()
			case 1:
				closePhysical()
			case 2:
				closeManager()
			case 3:
				_ = p.SetDeadline(time.Now().Add(time.Minute))
			}
		}()
	}
	wg.Wait()
	for _, done := range []<-chan error{readDone, writeDone} {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("concurrent shutdown returned successful I/O")
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent shutdown left I/O blocked")
		}
	}
	if stream.closes.Load() != 1 {
		t.Fatal("concurrent Close reached the stream more than once")
	}
}

type observingH3Stream struct {
	packetStream
	entered chan struct{}
}

func (s *observingH3Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	s.entered <- struct{}{}
	return s.packetStream.ReceiveDatagram(ctx)
}

func TestH3PacketLifecyclePhysicalShutdownAndDialHandoff(t *testing.T) {
	release := make(chan struct{})
	c, cleanup := reviewH3(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderSessionOK, "1")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer cleanup()
	defer close(release)
	dialCtx, cancelDial := context.WithCancel(context.Background())
	defer cancelDial()
	pc, err := c.ListenPacket(dialCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	p := pc.(*quicPacketConn)
	cancelDial()
	if p.ctx.Err() != nil {
		t.Fatal("dial caller cancellation killed an established association")
	}
	entered := make(chan struct{}, 1)
	p.stream = &observingH3Stream{packetStream: p.stream, entered: entered}
	readDone := make(chan error, 1)
	go func() { _, _, err := p.ReadFrom(make([]byte, 32)); readDone <- err }()
	waitRawTest(t, entered, "real HTTP Datagram receiver not entered")
	p.manager.mu.Lock()
	physical := p.manager.currentUDP
	p.manager.mu.Unlock()
	if err := physical.quic.CloseWithError(0, "lifecycle regression"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("closed physical connection returned successful read")
		}
	case <-time.After(time.Second):
		t.Fatal("physical connection close did not cancel HTTP Datagram receive")
	}
	if p.manager.lifetime.Err() != nil {
		t.Fatal("physical connection test accidentally closed the manager")
	}
	_ = p.Close()
	replacement, err := c.ListenPacket(context.Background())
	if err != nil {
		t.Fatalf("manager failed to reconnect after physical shutdown: %v", err)
	}
	defer replacement.Close()
	if replacement.(*quicPacketConn).ctx.Err() != nil {
		t.Fatal("replacement association inherited the old connection cancellation")
	}
}
