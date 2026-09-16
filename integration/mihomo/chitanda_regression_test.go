package outbound

import (
	"context"
	"errors"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type auditRotatingResolver struct {
	resolver.Resolver
	calls int
}

func (r *auditRotatingResolver) Invalid() bool { return true }
func (r *auditRotatingResolver) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	r.calls++
	if r.calls == 1 {
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}
	return []netip.Addr{netip.MustParseAddr("192.0.2.2")}, nil
}

type auditPacketDialer struct {
	route netip.AddrPort
	pc    auditPacketSocket
}

func (d *auditPacketDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("no TCP")
}
func (d *auditPacketDialer) ListenPacket(_ context.Context, _ string, _ string, remote netip.AddrPort) (net.PacketConn, error) {
	d.route = remote
	return &d.pc, nil
}

type auditPacketSocket struct{ sent net.Addr }

func (p *auditPacketSocket) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (p *auditPacketSocket) WriteTo(b []byte, a net.Addr) (int, error) {
	p.sent = a
	return len(b), nil
}
func (*auditPacketSocket) Close() error                     { return nil }
func (*auditPacketSocket) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*auditPacketSocket) SetDeadline(time.Time) error      { return nil }
func (*auditPacketSocket) SetReadDeadline(time.Time) error  { return nil }
func (*auditPacketSocket) SetWriteDeadline(time.Time) error { return nil }

func TestRegressionMihomoUDPResolvedPeer(t *testing.T) {
	old := resolver.ProxyServerHostResolver
	defer func() { resolver.ProxyServerHostResolver = old }()
	r := &auditRotatingResolver{}
	resolver.ProxyServerHostResolver = r
	d := &auditPacketDialer{}
	c, err := NewChitanda(ChitandaOption{BasicOption: BasicOption{IPVersion: C.IPv4Only, DialerForAPI: d}, Name: "audit", Server: "audit.invalid", Port: 443, PSK: strings.Repeat("p", 32), Transport: "stream"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	pc, err := c.ListenPacketContext(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_, err = pc.WriteTo([]byte("data"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 3), Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	if d.route.String() != d.pc.sent.String() {
		t.Errorf("dialer peer=%s, actual UDP destination=%s (DNS calls=%d)", d.route, d.pc.sent, r.calls)
	}
}
func TestRegressionMihomoRejectInvalidConfig(t *testing.T) {
	for _, kind := range []string{"short-psk", "invalid-mode", "invalid-port"} {
		t.Run(kind, func(t *testing.T) {
			opt := ChitandaOption{Name: "audit", Server: "127.0.0.1", Port: 443, PSK: strings.Repeat("p", 32), Transport: "stream"}
			switch kind {
			case "short-psk":
				opt.PSK = "short"
			case "invalid-mode":
				opt.Transport = "typo"
			case "invalid-port":
				opt.Port = 65536
			}
			c, err := NewChitanda(opt)
			if c != nil {
				c.Close()
			}
			if err == nil {
				t.Error("invalid node accepted at config validation")
			}
		})
	}
}
