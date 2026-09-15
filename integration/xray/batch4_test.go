package chitanda

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/server"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func newTestContextWithDispatcher(t *testing.T, disp routing.Dispatcher) context.Context {
	v, err := core.New(&core.Config{})
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	if disp == nil {
		disp = &mockTestDispatcher{}
	}
	if err := v.AddFeature(disp); err != nil {
		t.Fatalf("AddFeature: %v", err)
	}
	return context.WithValue(context.Background(), core.XrayKey(1), v)
}

func TestH3InboundInitialization(t *testing.T) {
	ctx := newTestContextWithDispatcher(t, nil)
	psk := "test-psk-must-be-at-least-32-bytes-long!!"

	// 1. H3 transport -> H3 enabled
	h3Handler, err := newTestInboundHandler(t, ctx, &InboundConfig{
		Psk:       psk,
		Path:      "/api/sync",
		Transport: "h3",
		StrictSni: "localhost",
	})
	if err != nil {
		t.Fatalf("NewInboundHandler h3: %v", err)
	}
	if h3Handler.h3Server == nil || h3Handler.vconn == nil {
		t.Fatal("expected h3Server and vconn to be initialized for transport=h3")
	}
	_ = h3Handler.Close()

	// 2. Stream transport -> H3 disabled
	streamHandler, err := newTestInboundHandler(t, ctx, &InboundConfig{
		Psk:       psk,
		Path:      "/api/sync",
		Transport: "stream",
	})
	if err != nil {
		t.Fatalf("NewInboundHandler stream: %v", err)
	}
	if streamHandler.h3Server != nil || streamHandler.vconn != nil {
		t.Fatal("expected h3Server and vconn to be nil for transport=stream")
	}
	_ = streamHandler.Close()

	// 3. Auto transport -> H3 enabled
	autoHandler, err := newTestInboundHandler(t, ctx, &InboundConfig{
		Psk:       psk,
		Path:      "/api/sync",
		Transport: "auto",
		StrictSni: "localhost",
	})
	if err != nil {
		t.Fatalf("NewInboundHandler auto: %v", err)
	}
	if autoHandler.h3Server == nil || autoHandler.vconn == nil {
		t.Fatal("expected h3Server and vconn to be initialized for transport=auto")
	}
	_ = autoHandler.Close()

	// 4. H2 transport -> H3 enabled (for H3 UDP)
	h2Handler, err := newTestInboundHandler(t, ctx, &InboundConfig{
		Psk:       psk,
		Path:      "/api/sync",
		Transport: "h2",
		StrictSni: "localhost",
	})
	if err != nil {
		t.Fatalf("NewInboundHandler h2: %v", err)
	}
	if h2Handler.h3Server == nil || h2Handler.vconn == nil {
		t.Fatal("expected h3Server and vconn to be initialized for transport=h2")
	}
	_ = h2Handler.Close()
}

func TestQUICPacketDetection(t *testing.T) {
	// Too short (< 20 bytes)
	if isQUICPacket([]byte{0xc0, 0x01, 0x02}) {
		t.Error("expected false for short packet")
	}

	// Long Header Initial packet with Fixed Bit set (0xc0 = 1100 0000)
	initialPkt := make([]byte, 1200)
	initialPkt[0] = 0xc0 // Long header + Fixed bit (0x40)
	initialPkt[1] = 0x00
	initialPkt[2] = 0x00
	initialPkt[3] = 0x00
	initialPkt[4] = 0x01 // QUIC version 1
	if !isQUICPacket(initialPkt) {
		t.Error("expected true for QUIC Initial packet")
	}

	// Short Header 1-RTT packet with Fixed Bit set (0x40 = 0100 0000)
	oneRttPkt := make([]byte, 32)
	oneRttPkt[0] = 0x40 // Short header + Fixed bit (0x40)
	if !isQUICPacket(oneRttPkt) {
		t.Error("expected true for QUIC 1-RTT packet")
	}

	// Invalid packet with Fixed Bit clear (0x00 = 0000 0000)
	invalidPkt := make([]byte, 32)
	invalidPkt[0] = 0x00
	if isQUICPacket(invalidPkt) {
		t.Error("expected false when fixed bit is 0")
	}
}

func TestVirtualPacketConn(t *testing.T) {
	vconn := newVirtualPacketConn()
	defer vconn.Close()

	clientAddr := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 54321}
	mockConn := &mockStatConn{
		remoteAddr: clientAddr,
		localAddr:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
	}

	vconn.registerConn(clientAddr.String(), mockConn)

	// Feed a packet
	testPayload := []byte("hello quic")
	vconn.feed(testPayload, clientAddr)

	buf := make([]byte, 1024)
	n, addr, err := vconn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}
	if n != len(testPayload) || string(buf[:n]) != string(testPayload) {
		t.Fatalf("unexpected data: got %q, want %q", string(buf[:n]), string(testPayload))
	}
	if addr.String() != clientAddr.String() {
		t.Fatalf("unexpected addr: got %v, want %v", addr, clientAddr)
	}

	// WriteTo back to client
	reply := []byte("quic response")
	wn, err := vconn.WriteTo(reply, clientAddr)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	if wn != len(reply) {
		t.Fatalf("WriteTo short write: %d vs %d", wn, len(reply))
	}
	if len(mockConn.written) != 1 || string(mockConn.written[0]) != string(reply) {
		t.Fatalf("unexpected mockConn written data: %v", mockConn.written)
	}

	// Unregister
	vconn.unregisterConn(clientAddr.String(), mockConn)
	_, err = vconn.WriteTo(reply, clientAddr)
	if err == nil {
		t.Fatal("expected error after unregistering conn")
	}
}

func TestH3AndPlainUDPDemuxing(t *testing.T) {
	psk := []byte("test-psk-must-be-at-least-32-bytes-long!!")
	var plainDispatched atomic.Bool
	mockDispatcher := &mockTestDispatcher{
		dispatchFn: func(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
			if dest.Network == xnet.Network_UDP && dest.Address.String() == "8.8.8.8" {
				plainDispatched.Store(true)
			}
			pReader, pWriter := pipe.New()
			return &transport.Link{Reader: pReader, Writer: pWriter}, nil
		},
	}

	ctx := newTestContextWithDispatcher(t, mockDispatcher)

	h, err := newTestInboundHandler(t, ctx, &InboundConfig{
		Psk:       string(psk),
		Path:      "/api/sync",
		Transport: "stream",
		StrictSni: "localhost",
	})
	if err != nil {
		t.Fatalf("NewInboundHandler: %v", err)
	}
	defer h.Close()
	// Test the demultiplexer alone. A live HTTP/3 server would race this test's
	// ReadFrom and consume the same synthetic QUIC packet.
	h.config.Transport = "auto"
	h.vconn = newVirtualPacketConn()

	codec, err := server.NewPlainUDPCodec(psk)
	if err != nil {
		t.Fatalf("NewPlainUDPCodec: %v", err)
	}

	clientAddr := &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 12345}
	plainConn := &mockStatConn{
		remoteAddr: clientAddr,
		localAddr:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
	}

	// Create an authentic Plain-UDP packet
	plainPkt, err := codec.EncodeClientPacket(1001, "8.8.8.8:53", []byte("dns query"), time.Now())
	if err != nil {
		t.Fatalf("EncodeClientPacket: %v", err)
	}

	// Create a QUIC packet
	quicPkt := make([]byte, 1200)
	quicPkt[0] = 0xc0 // Long Header + Fixed Bit
	quicPkt[1] = 0x00
	quicPkt[2] = 0x00
	quicPkt[3] = 0x00
	quicPkt[4] = 0x01
	copy(quicPkt[20:], []byte("quic initial payload"))

	// Feed plain packet to plainConn reader
	mb1 := buf.MergeBytes(nil, plainPkt)
	plainConn.readBuf = append(plainConn.readBuf, mb1...)

	// Feed quic packet to plainConn reader
	mb2 := buf.MergeBytes(nil, quicPkt)
	plainConn.readBuf = append(plainConn.readBuf, mb2...)

	done := make(chan error, 1)
	go func() {
		done <- h.handleUDP(context.Background(), plainConn, mockDispatcher)
	}()

	// The QUIC packet should arrive at h.vconn
	readBuf := make([]byte, 1500)
	readDone := make(chan struct{})
	go func() {
		n, addr, err := h.vconn.ReadFrom(readBuf)
		if err == nil && n == len(quicPkt) && addr.String() == clientAddr.String() {
			close(readDone)
		}
	}()

	select {
	case <-readDone:
		// QUIC packet was successfully demuxed and received via vconn!
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for QUIC packet to arrive at vconn")
	}

	// Verify Plain-UDP packet was dispatched through Xray dispatcher
	if !plainDispatched.Load() {
		t.Fatal("expected Plain-UDP packet to be dispatched through dispatcher")
	}

	_ = plainConn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
	}
}

type mockTestDispatcher struct {
	dispatchFn func(ctx context.Context, dest xnet.Destination) (*transport.Link, error)
}

func (m *mockTestDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

func (m *mockTestDispatcher) Start() error { return nil }
func (m *mockTestDispatcher) Close() error { return nil }

func (m *mockTestDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	if m.dispatchFn != nil {
		return m.dispatchFn(ctx, dest)
	}
	pReader, pWriter := pipe.New()
	return &transport.Link{Reader: pReader, Writer: pWriter}, nil
}

func (m *mockTestDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	return nil
}

type mockStatConn struct {
	remoteAddr net.Addr
	localAddr  net.Addr
	readBuf    buf.MultiBuffer
	written    [][]byte
	closed     bool
	mu         sync.Mutex
	cond       *sync.Cond
}

func (m *mockStatConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for len(m.readBuf) == 0 && !m.closed {
		if m.cond == nil {
			m.cond = sync.NewCond(&m.mu)
		}
		m.cond.Wait()
	}
	if m.closed && len(m.readBuf) == 0 {
		return nil, net.ErrClosed
	}
	mb := m.readBuf
	m.readBuf = nil
	return mb, nil
}

func (m *mockStatConn) Read(b []byte) (int, error) {
	return 0, nil
}

func (m *mockStatConn) Write(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := make([]byte, len(b))
	copy(copied, b)
	m.written = append(m.written, copied)
	return len(b), nil
}

func (m *mockStatConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	if m.cond != nil {
		m.cond.Broadcast()
	}
	return nil
}

func (m *mockStatConn) RemoteAddr() net.Addr               { return m.remoteAddr }
func (m *mockStatConn) LocalAddr() net.Addr                { return m.localAddr }
func (m *mockStatConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockStatConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockStatConn) SetWriteDeadline(t time.Time) error { return nil }

func TestH3DialTargetRouting(t *testing.T) {
	srv := server.NewServer("/test", []byte("01234567890123456789012345678901"), nil, nil, 10)
	srv.SetDialTargetForTest(func(ctx context.Context, address string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	})

	cert, err := generateSelfSignedCert("localhost")
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}
	h3Srv := server.NewHTTP3Server(srv, tlsConfig, 0)
	if h3Srv == nil {
		t.Fatal("expected NewHTTP3Server to return non-nil server")
	}
}
