package server

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/chitanda/internal/frame"
	"github.com/violetaini/chitanda/internal/icmpmsg"
	"github.com/violetaini/chitanda/internal/plainudp"
)

type mockDatagramStream struct {
	mu     sync.Mutex
	sent   [][]byte
	sentCh chan []byte
}

func newMockDatagramStream() *mockDatagramStream {
	return &mockDatagramStream{
		sentCh: make(chan []byte, 10),
	}
}

func (m *mockDatagramStream) SendDatagram(b []byte) error {
	m.mu.Lock()
	cp := append([]byte(nil), b...)
	m.sent = append(m.sent, cp)
	m.mu.Unlock()
	select {
	case m.sentCh <- cp:
	default:
	}
	return nil
}

type mockICMPPacketConn struct {
	remoteIP net.IP
	readCh   chan []byte
	writeCh  chan []byte
	closed   bool
	mu       sync.Mutex
}

func newMockICMPPacketConn(remoteIP net.IP) *mockICMPPacketConn {
	return &mockICMPPacketConn{
		remoteIP: remoteIP,
		readCh:   make(chan []byte, 10),
		writeCh:  make(chan []byte, 10),
	}
}

func (m *mockICMPPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	pkt, ok := <-m.readCh
	if !ok {
		return 0, nil, net.ErrClosed
	}
	n = copy(p, pkt)
	return n, &net.IPAddr{IP: m.remoteIP}, nil
}

func (m *mockICMPPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	cp := append([]byte(nil), p...)
	m.writeCh <- cp
	return len(p), nil
}

func (m *mockICMPPacketConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		close(m.readCh)
	}
	return nil
}

func (m *mockICMPPacketConn) LocalAddr() net.Addr                { return &net.IPAddr{IP: net.IPv4zero} }
func (m *mockICMPPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockICMPPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockICMPPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func TestUDPRelay_ICMPForwardAndReceive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := newMockDatagramStream()
	relay := newUDPRelay(ctx, stream)

	mockConn := newMockICMPPacketConn(net.ParseIP("8.8.8.8"))
	relay.dialICMP = func(ctx context.Context, address string) (net.PacketConn, error) {
		return mockConn, nil
	}
	defer relay.Close()

	id := uint16(0x4321)
	seq := uint16(0x0001)
	payload := []byte("ping test payload")
	reqPkt := icmpmsg.BuildEchoRequest(id, seq, payload, false)

	datagram, err := frame.EncodeDatagram(1, "icmp:8.8.8.8", reqPkt)
	if err != nil {
		t.Fatalf("EncodeDatagram failed: %v", err)
	}

	if err := relay.Forward(datagram); err != nil {
		t.Fatalf("relay.Forward failed: %v", err)
	}

	select {
	case written := <-mockConn.writeCh:
		msg, err := icmpmsg.ParseEcho(written)
		if err != nil {
			t.Fatalf("ParseEcho on forwarded packet failed: %v", err)
		}
		if msg.Type != icmpmsg.IPv4EchoRequest || msg.ID != id || msg.Seq != seq {
			t.Fatalf("forwarded ICMP packet mismatch: type=%d, id=%04x, seq=%04x", msg.Type, msg.ID, msg.Seq)
		}
		if !bytes.Equal(msg.Data, payload) {
			t.Fatalf("forwarded ICMP data mismatch: %q vs %q", msg.Data, payload)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ICMP packet to be written to upstream")
	}

	// Send Echo Reply from mock upstream
	replyPkt := icmpmsg.BuildEchoReply(id, seq, payload, false)
	mockConn.readCh <- replyPkt

	select {
	case replyDatagram := <-stream.sentCh:
		frameSeq, address, retPayload, err := frame.DecodeDatagram(replyDatagram)
		if err != nil {
			t.Fatalf("DecodeDatagram failed: %v", err)
		}
		if frameSeq == 0 {
			t.Errorf("expected sequence > 0")
		}
		if address != "icmp:8.8.8.8" {
			t.Errorf("expected address %q, got %q", "icmp:8.8.8.8", address)
		}
		echoMsg, err := icmpmsg.ParseEcho(retPayload)
		if err != nil {
			t.Fatalf("ParseEcho on reply datagram failed: %v", err)
		}
		if echoMsg.Type != icmpmsg.IPv4EchoReply || echoMsg.ID != id || echoMsg.Seq != seq {
			t.Errorf("echo reply mismatch: type=%d, id=%04x, seq=%04x", echoMsg.Type, echoMsg.ID, echoMsg.Seq)
		}
		if !bytes.Equal(echoMsg.Data, payload) {
			t.Errorf("echo reply payload mismatch")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ICMP reply datagram to client")
	}
}

func TestUDPRelay_IPv6ICMP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := newMockDatagramStream()
	relay := newUDPRelay(ctx, stream)

	remoteIP := net.ParseIP("2001:4860:4860::8888")
	mockConn := newMockICMPPacketConn(remoteIP)
	relay.dialICMP = func(ctx context.Context, address string) (net.PacketConn, error) {
		return mockConn, nil
	}
	defer relay.Close()

	id := uint16(0x5678)
	seq := uint16(0x0002)
	payload := []byte("ipv6 ping test")
	reqPkt := icmpmsg.BuildEchoRequest(id, seq, payload, true)

	datagram, err := frame.EncodeDatagram(2, "icmp:2001:4860:4860::8888", reqPkt)
	if err != nil {
		t.Fatalf("EncodeDatagram failed: %v", err)
	}

	if err := relay.Forward(datagram); err != nil {
		t.Fatalf("relay.Forward failed: %v", err)
	}

	select {
	case written := <-mockConn.writeCh:
		msg, err := icmpmsg.ParseEcho(written)
		if err != nil {
			t.Fatalf("ParseEcho IPv6 failed: %v", err)
		}
		if msg.Type != icmpmsg.IPv6EchoRequest {
			t.Fatalf("expected IPv6EchoRequest type %d, got %d", icmpmsg.IPv6EchoRequest, msg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for IPv6 ICMP write")
	}

	replyPkt := icmpmsg.BuildEchoReply(id, seq, payload, true)
	mockConn.readCh <- replyPkt

	select {
	case replyDatagram := <-stream.sentCh:
		_, address, retPayload, err := frame.DecodeDatagram(replyDatagram)
		if err != nil {
			t.Fatalf("DecodeDatagram failed: %v", err)
		}
		if address != "icmp:2001:4860:4860::8888" {
			t.Errorf("expected address icmp:2001:4860:4860::8888, got %s", address)
		}
		echoMsg, err := icmpmsg.ParseEcho(retPayload)
		if err != nil {
			t.Fatalf("ParseEcho on reply datagram failed: %v", err)
		}
		if echoMsg.Type != icmpmsg.IPv6EchoReply {
			t.Errorf("expected IPv6EchoReply, got %d", echoMsg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for IPv6 reply datagram")
	}
}

func TestServer_SetDialICMP(t *testing.T) {
	psk := bytes.Repeat([]byte("k"), 32)
	srv := NewServer("/sync", psk, nil, nil, 1024)

	called := false
	srv.SetDialICMP(func(ctx context.Context, address string) (net.PacketConn, error) {
		called = true
		return newMockICMPPacketConn(net.ParseIP("1.1.1.1")), nil
	})

	if srv.dialICMP == nil {
		t.Fatal("dialICMP was not stored on Server")
	}

	conn, err := srv.dialICMP(context.Background(), "1.1.1.1")
	if err != nil || conn == nil || !called {
		t.Fatalf("dialICMP failed: err=%v, called=%v", err, called)
	}
}

func TestPlainUDPServer_ICMP(t *testing.T) {
	psk := bytes.Repeat([]byte("p"), 32)
	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer udpLn.Close()

	srv, err := NewPlainUDPServer(udpLn, psk)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	targetIP := net.ParseIP("8.8.8.8")
	mockConn := newMockICMPPacketConn(targetIP)
	srv.SetDialICMP(func(ctx context.Context, address string) (net.PacketConn, error) {
		return mockConn, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = srv.Serve(ctx)
	}()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	codec, err := plainudp.NewCodec(psk)
	if err != nil {
		t.Fatal(err)
	}

	sessionID := uint64(0x9876543210abcdef)
	echoReq := icmpmsg.BuildEchoRequest(0x3344, 1, []byte("plain-udp-ping"), false)
	clientPacket, err := codec.EncodePacket(nil, plainudp.DirClientToServer, sessionID, "icmp:8.8.8.8", echoReq, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := clientConn.WriteToUDP(clientPacket, udpLn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}

	// Verify mockConn received the Echo Request
	select {
	case written := <-mockConn.writeCh:
		msg, err := icmpmsg.ParseEcho(written)
		if err != nil {
			t.Fatalf("ParseEcho on written data failed: %v", err)
		}
		if msg.ID != 0x3344 || msg.Seq != 1 {
			t.Errorf("ID/Seq mismatch: got id=%x, seq=%d", msg.ID, msg.Seq)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ICMP request written to raw socket")
	}

	// Send simulated Echo Reply back to server
	echoReply := icmpmsg.BuildEchoReply(0x3344, 1, []byte("plain-udp-ping"), false)
	mockConn.readCh <- echoReply

	// Client receives the Plain-UDP response
	recvBuf := make([]byte, 2048)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := clientConn.ReadFrom(recvBuf)
	if err != nil {
		t.Fatalf("client read reply failed: %v", err)
	}

	replySid, targetAddr, replyPayload, _, _, err := codec.DecodePacket(recvBuf[:n], plainudp.DirServerToClient, time.Now())
	if err != nil {
		t.Fatalf("DecodePacket failed: %v", err)
	}
	if replySid != sessionID {
		t.Errorf("session ID mismatch: got %x, want %x", replySid, sessionID)
	}
	if targetAddr != "icmp:8.8.8.8" {
		t.Errorf("target address mismatch: got %q, want 'icmp:8.8.8.8'", targetAddr)
	}
	echoMsg, err := icmpmsg.ParseEcho(replyPayload)
	if err != nil {
		t.Fatalf("ParseEcho on reply payload failed: %v", err)
	}
	if echoMsg.ID != 0x3344 || echoMsg.Seq != 1 || !bytes.Equal(echoMsg.Data, []byte("plain-udp-ping")) {
		t.Errorf("unexpected echo reply: %+v", echoMsg)
	}
}
