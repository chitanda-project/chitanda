package sing_tun

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/sing"
	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
)

type failingICMPTunnel struct{ C.Tunnel }

func (failingICMPTunnel) OpenChitandaICMP(context.Context, netip.Addr, netip.Addr) (net.PacketConn, bool, error) {
	return nil, false, errors.New("simulated proxy failure")
}

func TestChitandaICMPProxyFailureDropsInsteadOfFakeReply(t *testing.T) {
	handler := &ListenerHandler{ListenerHandler: &sing.ListenerHandler{
		ListenerConfig: sing.ListenerConfig{Tunnel: failingICMPTunnel{}},
	}}
	_, handled, err := handler.prepareChitandaICMP(netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("1.1.1.1"), nil, time.Second)
	if !handled || !errors.Is(err, tun.ErrDrop) {
		t.Fatalf("expected fail-closed ICMP drop, handled=%v err=%v", handled, err)
	}
}

type testICMPPacketConn struct {
	packet []byte
	addr   net.Addr
}

func (c *testICMPPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (c *testICMPPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.packet = append([]byte(nil), p...)
	c.addr = addr
	return len(p), nil
}
func (c *testICMPPacketConn) Close() error                     { return nil }
func (c *testICMPPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *testICMPPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *testICMPPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testICMPPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestChitandaICMPDestinationIPv4(t *testing.T) {
	source := netip.MustParseAddr("10.0.0.2")
	target := netip.MustParseAddr("8.8.8.8")
	conn := &testICMPPacketConn{}
	d := &chitandaICMPDestination{conn: conn, source: source, target: target}
	request := []byte{8, 0, 0, 0, 0x12, 0x34, 0, 1}
	binary.BigEndian.PutUint16(request[2:4], checksum(request))
	ip := make([]byte, 20+len(request))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[9] = 1
	copy(ip[12:16], source.AsSlice())
	copy(ip[16:20], target.AsSlice())
	copy(ip[20:], request)
	if err := d.WritePacket(buf.As(ip)); err != nil {
		t.Fatal(err)
	}
	addr, ok := conn.addr.(*net.UDPAddr)
	if !ok || addr.Port != 0 || !addr.IP.Equal(target.AsSlice()) {
		t.Fatalf("unexpected proxy destination: %v", conn.addr)
	}
	if string(conn.packet) != string(request) {
		t.Fatal("ICMP payload changed before proxying")
	}
	reply := []byte{0, 0, 0, 0, 0x12, 0x34, 0, 1}
	binary.BigEndian.PutUint16(reply[2:4], checksum(reply))
	packet, err := d.buildReply(reply)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != 28 || checksum(packet[:20]) != 0 || !net.IP(packet[12:16]).Equal(target.AsSlice()) || !net.IP(packet[16:20]).Equal(source.AsSlice()) {
		t.Fatal("invalid IPv4 reply header")
	}
}

func TestChitandaICMPDestinationIPv6(t *testing.T) {
	source := netip.MustParseAddr("2001:db8::2")
	target := netip.MustParseAddr("2001:4860:4860::8888")
	d := &chitandaICMPDestination{conn: &testICMPPacketConn{}, source: source, target: target}
	reply := []byte{129, 0, 0, 0, 0x12, 0x34, 0, 1}
	packet, err := d.buildReply(reply)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != 48 || packet[6] != 58 || !net.IP(packet[8:24]).Equal(target.AsSlice()) || !net.IP(packet[24:40]).Equal(source.AsSlice()) {
		t.Fatal("invalid IPv6 reply header")
	}
	pseudo := make([]byte, 40+len(reply))
	copy(pseudo[:16], packet[8:24])
	copy(pseudo[16:32], packet[24:40])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(reply)))
	pseudo[39] = 58
	copy(pseudo[40:], packet[40:])
	if checksum(pseudo) != 0 {
		t.Fatal("invalid ICMPv6 pseudo-header checksum")
	}
}
