package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/violetaini/chitanda/internal/frame"
	"github.com/violetaini/chitanda/internal/plainudp"
)

func TestRegressionClosedH3ManagerDoesNotDial(t *testing.T) {
	calls := 0
	m := newH3TransportManager("127.0.0.1:443", "localhost", "https://localhost/", "https://localhost/test", "/test", bytes.Repeat([]byte{7}, 32), nil, 1200, true,
		func(context.Context, string, string) (net.PacketConn, error) {
			calls++
			return nil, errors.New("dial happened after close")
		},
		func(context.Context, string, string) (*net.UDPAddr, error) {
			return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, nil
		})
	m.close()
	_, err := m.ensureUDP(context.Background())
	if calls != 0 {
		t.Fatalf("closed/evicted H3 manager reached packet dialer: calls=%d err=%v", calls, err)
	}
}

func TestRegressionH3TCPUDPResolutionIsIndependent(t *testing.T) {
	entered := make(chan struct{}, 2)
	var calls atomic.Int32
	m := newH3TransportManager("example.invalid:443", "localhost", "https://localhost/", "https://localhost/test", "/test", bytes.Repeat([]byte{7}, 32), nil, 1200, true, nil,
		func(ctx context.Context, _, _ string) (*net.UDPAddr, error) {
			calls.Add(1)
			entered <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		})
	defer m.close()
	done := make(chan struct{}, 2)
	go func() { _, _ = m.ensureUDP(context.Background()); done <- struct{}{} }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("UDP resolver not entered")
	}
	go func() { _, _ = m.ensureTCP(context.Background()); done <- struct{}{} }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("TCP resolver blocked behind UDP")
	}
	m.close()
	for range 2 {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("dial not canceled")
		}
	}
	if calls.Load() != 2 {
		t.Fatal("unexpected dial count")
	}
}

func TestRegressionH3PoolReservationPreventsIdleEviction(t *testing.T) {
	c, err := New(Config{Server: "127.0.0.1:443", ServerName: "localhost", Path: "/test", PSK: bytes.Repeat([]byte{7}, 32), TCPTransport: "h3", TCPPoolSize: 1, UDPPoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	dynamic := newH3TransportManager(c.cfg.Server, c.cfg.ServerName, c.rootURL, c.requestURL, c.cfg.Path, c.cfg.PSK, nil, 1200, true, nil, nil)
	dynamic.isDynamic = true
	c.carrierMu.Lock()
	c.h3Managers[0].activeStreams.Store(100)
	c.h3Managers = append(c.h3Managers, dynamic)
	c.carrierMu.Unlock()
	reserved := c.pickBestH3Manager()
	if reserved != dynamic || reserved.activeStreams.Load() != 1 {
		t.Fatal("pool selection did not reserve under carrier lock")
	}
	if removed, err := c.RemoveIdleCarrier("h3", 0); err != nil || removed {
		t.Fatal("reserved carrier evicted")
	}
	reserved.activeStreams.Add(-1)
	if removed, err := c.RemoveIdleCarrier("h3", 0); err != nil || !removed {
		t.Fatal("released carrier not reclaimed")
	}
	if _, err := dynamic.ensureUDP(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatal("evicted carrier can dial")
	}
}

func TestRegressionClientCloseCancelsPendingH3Resolution(t *testing.T) {
	entered := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := New(Config{Server: "audit.invalid:443", ServerName: "localhost", Path: "/test", PSK: bytes.Repeat([]byte{7}, 32), TCPTransport: "h3", TCPPoolSize: 1, UDPPoolSize: 1,
		ResolveUDP: func(ctx context.Context, _, _ string) (*net.UDPAddr, error) {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		}})
	if err != nil {
		t.Fatal(err)
	}
	dialDone := make(chan struct{})
	go func() { defer close(dialDone); _, _ = c.ListenPacket(ctx) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("resolver was not entered")
	}
	closeDone := make(chan struct{})
	go func() { defer close(closeDone); c.Close() }()
	blocked := false
	select {
	case <-closeDone:
	case <-time.After(300 * time.Millisecond):
		blocked = true
	}
	cancel()
	select {
	case <-dialDone:
	case <-time.After(time.Second):
		t.Fatal("dial failed to clean up")
	}
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("close failed to clean up")
	}
	if blocked {
		t.Fatal("Client.Close did not cancel pending H3 resolver; caller cancellation was required")
	}
}

func TestRegressionH2ClientCloseTerminatesActiveStream(t *testing.T) {
	psk := bytes.Repeat([]byte{7}, 32)
	ts, cleanup := startMockH2Server(t, psk)
	defer cleanup()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		c, err := listener.Accept()
		if err == nil {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}
	}()
	c, err := New(Config{Server: ts.Listener.Addr().String(), ServerName: "localhost", Path: "/test", PSK: psk, TCPTransport: "h2", TCPPoolSize: 1, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := c.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echo := func(s string) error {
		if _, err := conn.Write([]byte(s)); err != nil {
			return err
		}
		b := make([]byte, len(s))
		_, err := io.ReadFull(conn, b)
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if err := echo("before"); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if err := echo("after"); err == nil {
		t.Fatal("H2 stream still transferred authenticated data after Client.Close")
	}
}

type regressionPackets struct {
	packets [][]byte
	server  net.Addr
}

func (p *regressionPackets) ReadFrom(b []byte) (int, net.Addr, error) {
	if len(p.packets) == 0 {
		return 0, nil, io.EOF
	}
	n := copy(b, p.packets[0])
	p.packets = p.packets[1:]
	return n, p.server, nil
}
func (*regressionPackets) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (*regressionPackets) Close() error                              { return nil }
func (p *regressionPackets) LocalAddr() net.Addr                     { return p.server }
func (*regressionPackets) SetDeadline(time.Time) error               { return nil }
func (*regressionPackets) SetReadDeadline(time.Time) error           { return nil }
func (*regressionPackets) SetWriteDeadline(time.Time) error          { return nil }

func TestRegressionPlainUDPIndependentAssociationsKeepReorderWindow(t *testing.T) {
	psk := bytes.Repeat([]byte{7}, 32)
	now := time.Now()
	sender, _ := plainudp.NewCodec(psk, "audit")
	receiver, _ := plainudp.NewCodec(psk, "audit")
	encode := func(sid uint64, payload string) []byte {
		packet, err := sender.EncodePacket(nil, plainudp.DirServerToClient, sid, "1.1.1.1:53", []byte(payload), now)
		if err != nil {
			t.Fatal(err)
		}
		return packet
	}
	delayed := encode(1, "old-A")
	for i := 0; i < frame.ReplayWindowSize; i++ {
		_ = encode(2, "other-client-B")
	}
	recent := encode(1, "new-A")
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	conn := &plainUDPConn{sessionID: 1, codec: receiver, serverAddr: addr, conn: &regressionPackets{packets: [][]byte{recent, delayed}, server: addr}}
	b := make([]byte, 100)
	n, _, err := conn.ReadFrom(b)
	if err != nil || string(b[:n]) != "new-A" {
		t.Fatal("first response failed")
	}
	n, _, err = conn.ReadFrom(b)
	if err != nil || string(b[:n]) != "old-A" {
		t.Fatalf("legitimate A response rejected after B-only traffic: n=%d err=%v", n, err)
	}
}
