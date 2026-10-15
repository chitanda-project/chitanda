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
)

type carrierLifecycleSocket struct {
	net.PacketConn
	closes atomic.Int32
	once   sync.Once
	closed chan struct{}
}

func (p *carrierLifecycleSocket) Close() error {
	p.closes.Add(1)
	err := p.PacketConn.Close()
	p.once.Do(func() { close(p.closed) })
	return err
}

type carrierDialValueKey struct{}

func TestH3CarrierLifecycleRetainsEmbeddingContext(t *testing.T) {
	for _, finish := range []string{"manager", "physical"} {
		t.Run(finish, func(t *testing.T) {
			c, cleanup := reviewH3(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(HeaderSessionOK, "1")
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}))
			defer cleanup()
			m := c.h3Managers[0]
			var retained context.Context
			var socket *carrierLifecycleSocket
			m.dialPacket = func(ctx context.Context, _ *net.UDPAddr) (net.PacketConn, error) {
				pc, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					return nil, err
				}
				retained = ctx
				socket = &carrierLifecycleSocket{PacketConn: pc, closed: make(chan struct{})}
				return socket, nil
			}
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), carrierDialValueKey{}, "route-value"))
			defer cancel()
			pc, err := c.ListenPacket(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			cancel()
			if retained.Err() != nil || retained.Value(carrierDialValueKey{}) != "route-value" {
				t.Fatal("successful carrier lost its embedding context lifetime or values")
			}
			_ = pc.Close()
			if retained.Err() != nil {
				t.Fatal("closing a logical association canceled its shared carrier")
			}
			m.mu.Lock()
			physical := m.currentUDP
			m.mu.Unlock()
			if finish == "manager" {
				c.Close()
			} else {
				_ = physical.quic.CloseWithError(0, "peer closed")
			}
			waitRawTest(t, retained.Done(), "carrier shutdown retained embedding context")
			waitRawTest(t, socket.closed, "carrier shutdown retained physical packet socket")
			physical.close()
			c.Close()
			if socket.closes.Load() != 1 {
				t.Fatalf("physical Close calls=%d, want 1", socket.closes.Load())
			}
		})
	}
}

func TestH3CarrierLifecyclePrewarmHandoff(t *testing.T) {
	c, cleanup := reviewH3(t, http.NotFoundHandler())
	defer cleanup()
	var retained context.Context
	c.cfg.DialPacket = func(ctx context.Context, _ *net.UDPAddr) (net.PacketConn, error) {
		retained = ctx
		return net.ListenPacket("udp", "127.0.0.1:0")
	}
	probe, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.AddCarrier(probe, "h3"); err != nil {
		t.Fatal(err)
	}
	cancel()
	if retained == nil || retained.Err() != nil {
		t.Fatal("successful prewarm canceled its physical forwarding context")
	}
	if removed, err := c.RemoveIdleCarrier("h3", 0); err != nil || !removed {
		t.Fatalf("idle carrier removal = %v, %v", removed, err)
	}
	waitRawTest(t, retained.Done(), "evicted carrier retained forwarding context")
}

func TestH3CarrierLifecycleRejectsLatePacketSocket(t *testing.T) {
	c, cleanup := reviewH3(t, http.NotFoundHandler())
	defer cleanup()
	m := c.h3Managers[0]
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var socket *carrierLifecycleSocket
	m.dialPacket = func(context.Context, *net.UDPAddr) (net.PacketConn, error) {
		close(entered)
		<-release
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		socket = &carrierLifecycleSocket{PacketConn: pc, closed: make(chan struct{})}
		return socket, nil
	}
	result := make(chan error, 1)
	go func() { _, err := m.ensureUDP(context.Background()); result <- err }()
	waitRawTest(t, entered, "packet dial did not start")
	m.close()
	unblock()
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("late dial error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("late packet dial blocked")
	}
	if socket == nil || socket.closes.Load() != 1 {
		t.Fatal("late packet socket escaped or was closed repeatedly")
	}
}

func TestH3CarrierLifecycleCancelsPendingHandshake(t *testing.T) {
	c, cleanup := reviewH3(t, http.NotFoundHandler())
	defer cleanup()
	m := c.h3Managers[0]
	silent, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	m.server = silent.LocalAddr().String()
	entered := make(chan struct{})
	m.dialPacket = func(context.Context, *net.UDPAddr) (net.PacketConn, error) {
		close(entered)
		return net.ListenPacket("udp", "127.0.0.1:0")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := m.ensureUDP(ctx); done <- err }()
	waitRawTest(t, entered, "packet dial did not start")
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("caller cancellation did not stop pending handshake")
	}
}
