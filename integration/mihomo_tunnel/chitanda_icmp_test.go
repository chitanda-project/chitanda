package tunnel

import (
	"context"
	"errors"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

type icmpRoutePacketConn struct {
	C.PacketConn
	chain []string
}

func (pc *icmpRoutePacketConn) AppendToChains(proxy C.ProxyAdapter) {
	pc.chain = append(pc.chain, proxy.Name())
}

type icmpRouteLeaf struct {
	C.Proxy
	pc *icmpRoutePacketConn
}

func (p *icmpRouteLeaf) Type() C.AdapterType { return C.Chitanda }
func (p *icmpRouteLeaf) Name() string        { return "checked-chitanda" }
func (p *icmpRouteLeaf) SupportUDP() bool    { return true }
func (p *icmpRouteLeaf) ListenPacketContext(context.Context, *C.Metadata) (C.PacketConn, error) {
	return p.pc, nil
}

type icmpRouteGroup struct {
	C.Proxy
	selected C.Proxy
	dials    int
}

func (p *icmpRouteGroup) Type() C.AdapterType { return C.Selector }
func (p *icmpRouteGroup) Name() string        { return "group" }
func (p *icmpRouteGroup) Unwrap(*C.Metadata, bool) C.Proxy {
	return p.selected
}
func (p *icmpRouteGroup) ListenPacketContext(context.Context, *C.Metadata) (C.PacketConn, error) {
	p.dials++
	return nil, errors.New("group re-selected a different outbound")
}

func TestChitandaICMPDialsCheckedLeafOnly(t *testing.T) {
	pc := &icmpRoutePacketConn{chain: []string{"checked-chitanda"}}
	group := &icmpRouteGroup{selected: &icmpRouteLeaf{pc: pc}}
	got, handled, err := openChitandaICMPPacket(context.Background(), group, &C.Metadata{})
	if err != nil || !handled || got != pc {
		t.Fatalf("checked leaf not used: conn=%v handled=%v err=%v", got, handled, err)
	}
	if group.dials != 0 {
		t.Fatal("group dial was called and could re-select an unverified outbound")
	}
	if len(pc.chain) != 2 || pc.chain[1] != "group" {
		t.Fatalf("group chain lost: %v", pc.chain)
	}
}

// Mihomo's wrappers expose SupportUDP but not optional methods on the
// underlying Chitanda adapter. Embed the remainder of the proxy interface to
// simulate that wrapper without creating a test import cycle.
type wrappedChitandaProxy struct {
	C.Proxy
	udp bool
}

func (p wrappedChitandaProxy) Type() C.AdapterType     { return C.Chitanda }
func (p wrappedChitandaProxy) SupportUDP() bool        { return p.udp }
func (p wrappedChitandaProxy) Adapter() C.ProxyAdapter { return nil }

func TestChitandaICMPCapabilitySurvivesProxyWrapper(t *testing.T) {
	if !chitandaICMPSupported(wrappedChitandaProxy{udp: true}) {
		t.Fatal("wrapped Chitanda proxy lost ICMP capability")
	}
	if chitandaICMPSupported(wrappedChitandaProxy{udp: false}) {
		t.Fatal("ICMP was enabled despite UDP being disabled")
	}
}
