package client

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/violetaini/chitanda/internal/frame"
	"github.com/violetaini/chitanda/internal/icmpmsg"
)

func TestICMPAddr_Basics(t *testing.T) {
	ip4 := net.ParseIP("1.1.1.1")
	addr4 := &ICMPAddr{IP: ip4}
	if addr4.Network() != "icmp" {
		t.Errorf("expected Network() == 'icmp', got %q", addr4.Network())
	}
	if addr4.String() != "1.1.1.1" {
		t.Errorf("expected String() == '1.1.1.1', got %q", addr4.String())
	}
	if !isICMPAddr(addr4) {
		t.Errorf("isICMPAddr(addr4) should be true")
	}
	if formatted := formatDatagramAddress(addr4); formatted != "icmp:1.1.1.1" {
		t.Errorf("formatDatagramAddress(addr4) = %q, want 'icmp:1.1.1.1'", formatted)
	}

	ip6 := net.ParseIP("2606:4700:4700::1111")
	addr6 := &ICMPAddr{IP: ip6}
	if addr6.Network() != "icmp" {
		t.Errorf("expected Network() == 'icmp', got %q", addr6.Network())
	}
	if addr6.String() != "2606:4700:4700::1111" {
		t.Errorf("expected String() == '2606:4700:4700::1111', got %q", addr6.String())
	}
	if !isICMPAddr(addr6) {
		t.Errorf("isICMPAddr(addr6) should be true")
	}
	if formatted := formatDatagramAddress(addr6); formatted != "icmp:2606:4700:4700::1111" {
		t.Errorf("formatDatagramAddress(addr6) = %q, want 'icmp:2606:4700:4700::1111'", formatted)
	}

	// Normal UDP address should not be treated as ICMP
	udpAddr := &net.UDPAddr{IP: ip4, Port: 53}
	if isICMPAddr(udpAddr) {
		t.Errorf("isICMPAddr(udpAddr) should be false")
	}
	if formatted := formatDatagramAddress(udpAddr); formatted != "1.1.1.1:53" {
		t.Errorf("formatDatagramAddress(udpAddr) = %q, want '1.1.1.1:53'", formatted)
	}
}

func TestParseUDPAddr_ICMP(t *testing.T) {
	// IPv4 ICMP
	parsed4 := parseUDPAddr("icmp:8.8.8.8")
	icmp4, ok := parsed4.(*ICMPAddr)
	if !ok {
		t.Fatalf("expected *ICMPAddr, got %T", parsed4)
	}
	if icmp4.IP.String() != "8.8.8.8" {
		t.Errorf("expected 8.8.8.8, got %s", icmp4.IP.String())
	}
	if icmp4.Network() != "icmp" {
		t.Errorf("expected network 'icmp', got %s", icmp4.Network())
	}

	// IPv6 ICMP
	parsed6 := parseUDPAddr("icmp:2001:4860:4860::8888")
	icmp6, ok := parsed6.(*ICMPAddr)
	if !ok {
		t.Fatalf("expected *ICMPAddr, got %T", parsed6)
	}
	if icmp6.IP.String() != "2001:4860:4860::8888" {
		t.Errorf("expected 2001:4860:4860::8888, got %s", icmp6.IP.String())
	}

	// Regular UDP address
	parsedUDP := parseUDPAddr("8.8.8.8:53")
	if _, ok := parsedUDP.(*net.UDPAddr); !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", parsedUDP)
	}
}

type mockPacketStream struct {
	sentCh chan []byte
	recvCh chan []byte
}

func newMockPacketStream() *mockPacketStream {
	return &mockPacketStream{
		sentCh: make(chan []byte, 10),
		recvCh: make(chan []byte, 10),
	}
}

func (m *mockPacketStream) SendDatagram(b []byte) error {
	cp := append([]byte(nil), b...)
	m.sentCh <- cp
	return nil
}

func (m *mockPacketStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case pkt, ok := <-m.recvCh:
		if !ok {
			return nil, net.ErrClosed
		}
		return pkt, nil
	}
}

func (m *mockPacketStream) CancelRead(quic.StreamErrorCode)  {}
func (m *mockPacketStream) CancelWrite(quic.StreamErrorCode) {}
func (m *mockPacketStream) Close() error                     { return nil }

func TestQuicPacketConn_ICMPWriteAndRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := newMockPacketStream()
	pconn := &quicPacketConn{
		stream: stream,
		ctx:    ctx,
		cancel: cancel,
	}
	defer pconn.Close()

	targetIP := net.ParseIP("9.9.9.9")
	echoReq := icmpmsg.BuildEchoRequest(0x1111, 1, []byte("test icmp write"), false)

	// Write ICMP packet via WriteTo
	n, err := pconn.WriteTo(echoReq, &ICMPAddr{IP: targetIP})
	if err != nil {
		t.Fatalf("pconn.WriteTo failed: %v", err)
	}
	if n != len(echoReq) {
		t.Errorf("WriteTo returned %d, want %d", n, len(echoReq))
	}

	select {
	case sentDatagram := <-stream.sentCh:
		_, address, payload, err := frame.DecodeDatagram(sentDatagram)
		if err != nil {
			t.Fatalf("DecodeDatagram failed: %v", err)
		}
		if address != "icmp:9.9.9.9" {
			t.Errorf("expected address 'icmp:9.9.9.9', got %q", address)
		}
		if !bytes.Equal(payload, echoReq) {
			t.Errorf("payload mismatch")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for datagram from WriteTo")
	}

	// Test ReadFrom receives ICMP reply
	echoReply := icmpmsg.BuildEchoReply(0x1111, 1, []byte("test icmp write"), false)
	replyDatagram, err := frame.EncodeDatagram(1, "icmp:9.9.9.9", echoReply)
	if err != nil {
		t.Fatalf("EncodeDatagram failed: %v", err)
	}
	stream.recvCh <- replyDatagram

	buf := make([]byte, 1024)
	readN, from, err := pconn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("pconn.ReadFrom failed: %v", err)
	}
	icmpAddr, ok := from.(*ICMPAddr)
	if !ok {
		t.Fatalf("expected *ICMPAddr from ReadFrom, got %T", from)
	}
	if !icmpAddr.IP.Equal(targetIP) {
		t.Errorf("expected IP %s, got %s", targetIP, icmpAddr.IP)
	}
	if !bytes.Equal(buf[:readN], echoReply) {
		t.Errorf("read payload mismatch")
	}
}

func TestQuicPacketConn_WriteBatchICMP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := newMockPacketStream()
	pconn := &quicPacketConn{
		stream: stream,
		ctx:    ctx,
		cancel: cancel,
	}
	defer pconn.Close()

	payloads := [][]byte{
		icmpmsg.BuildEchoRequest(1, 1, []byte("req1"), false),
		icmpmsg.BuildEchoRequest(1, 2, []byte("req2"), false),
	}
	addrs := []net.Addr{
		&ICMPAddr{IP: net.ParseIP("1.1.1.1")},
		&ICMPAddr{IP: net.ParseIP("8.8.8.8")},
	}

	if err := pconn.WriteBatch(payloads, addrs); err != nil {
		t.Fatalf("WriteBatch failed: %v", err)
	}

	for i := 0; i < 2; i++ {
		select {
		case sentDatagram := <-stream.sentCh:
			_, address, payload, err := frame.DecodeDatagram(sentDatagram)
			if err != nil {
				t.Fatalf("DecodeDatagram packet %d failed: %v", i, err)
			}
			expectedAddr := "icmp:" + addrs[i].String()
			if address != expectedAddr {
				t.Errorf("packet %d address = %q, want %q", i, address, expectedAddr)
			}
			if !bytes.Equal(payload, payloads[i]) {
				t.Errorf("packet %d payload mismatch", i)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for batch datagram %d", i)
		}
	}
}

type mockEchoPacketConn struct {
	readCh chan struct {
		data []byte
		from net.Addr
	}
	closed bool
	mu     sync.Mutex
}

func newMockEchoPacketConn() *mockEchoPacketConn {
	return &mockEchoPacketConn{
		readCh: make(chan struct {
			data []byte
			from net.Addr
		}, 10),
	}
}

func (m *mockEchoPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	item, ok := <-m.readCh
	if !ok {
		return 0, nil, net.ErrClosed
	}
	n = copy(p, item.data)
	return n, item.from, nil
}

func (m *mockEchoPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	echo, err := icmpmsg.ParseEcho(p)
	if err != nil {
		return 0, err
	}
	var targetIP net.IP
	if ia, ok := addr.(*ICMPAddr); ok {
		targetIP = ia.IP
	} else if ipa, ok := addr.(*net.IPAddr); ok {
		targetIP = ipa.IP
	}
	isIPv6 := targetIP != nil && targetIP.To4() == nil
	reply := icmpmsg.BuildEchoReply(echo.ID, echo.Seq, echo.Data, isIPv6)
	m.readCh <- struct {
		data []byte
		from net.Addr
	}{
		data: reply,
		from: &ICMPAddr{IP: targetIP},
	}
	return len(p), nil
}

func (m *mockEchoPacketConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		close(m.readCh)
	}
	return nil
}

func (m *mockEchoPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (m *mockEchoPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockEchoPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockEchoPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func TestClient_Ping_Mock(t *testing.T) {
	c, err := New(Config{
		Server:       "127.0.0.1:11322",
		ServerName:   "example.com",
		Path:         "/sync",
		PSK:          bytes.Repeat([]byte("k"), 32),
		TCPTransport: TCPTransportH2,
	})
	if err != nil {
		t.Fatalf("New client failed: %v", err)
	}
	defer c.Close()

	c.SetListenPacketForTest(func(ctx context.Context) (net.PacketConn, error) {
		return newMockEchoPacketConn(), nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Test IPv4 Ping
	payload := []byte("hello icmp ping")
	resData, rtt, err := c.Ping(ctx, "8.8.8.8", 0x1234, 1, payload)
	if err != nil {
		t.Fatalf("Ping IPv4 failed: %v", err)
	}
	if !bytes.Equal(resData, payload) {
		t.Errorf("expected response data %q, got %q", payload, resData)
	}
	if rtt < 0 {
		t.Errorf("expected positive RTT duration, got %v", rtt)
	}

	// Test IPv6 Ping
	resData6, rtt6, err := c.Ping(ctx, "2001:4860:4860::8888", 0x5678, 2, payload)
	if err != nil {
		t.Fatalf("Ping IPv6 failed: %v", err)
	}
	if !bytes.Equal(resData6, payload) {
		t.Errorf("expected response data %q, got %q", payload, resData6)
	}
	if rtt6 < 0 {
		t.Errorf("expected positive RTT duration, got %v", rtt6)
	}
}

