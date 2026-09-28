package outbound

import (
	"context"
	"net"
	"testing"

	"github.com/violetaini/chitanda/pkg/client"
)

func TestMihomoSupportICMP(t *testing.T) {
	udpEnabled := true
	udpDisabled := false

	cDefault := &Chitanda{
		option: &ChitandaOption{},
	}
	if !cDefault.SupportICMP() {
		t.Fatal("expected SupportICMP() == true by default")
	}

	cEnabled := &Chitanda{
		option: &ChitandaOption{UDP: &udpEnabled},
	}
	if !cEnabled.SupportICMP() {
		t.Fatal("expected SupportICMP() == true when UDP enabled")
	}

	cDisabled := &Chitanda{
		option: &ChitandaOption{UDP: &udpDisabled},
	}
	if cDisabled.SupportICMP() {
		t.Fatal("expected SupportICMP() == false when UDP disabled")
	}

	// Verify ListenPacketContext rejects when UDP/ICMP is disabled
	_, err := cDisabled.ListenPacketContext(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error when UDP is disabled")
	}
}

func TestMihomoICMPPortZeroMapsToProtocolAddress(t *testing.T) {
	underlying := &auditPacketSocket{}
	conn := &chitandaICMPPacketConn{PacketConn: underlying}
	request := []byte{8, 0, 0xf7, 0xff, 0, 0, 0, 0}
	n, err := conn.WriteTo(request, &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 0})
	if err != nil || n != len(request) {
		t.Fatalf("ICMP WriteTo failed: n=%d err=%v", n, err)
	}
	if addr, ok := underlying.sent.(*client.ICMPAddr); !ok || !addr.IP.Equal(net.IPv4(8, 8, 8, 8)) {
		t.Fatalf("expected ICMP address, got %T %v", underlying.sent, underlying.sent)
	}
	if _, err := conn.WriteTo([]byte("not icmp"), &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 0}); err == nil {
		t.Fatal("invalid ICMP payload was accepted")
	}
}

func TestMihomoChitandaBatchWriteCountsAndValidates(t *testing.T) {
	underlying := &auditPacketSocket{}
	conn := &chitandaICMPPacketConn{PacketConn: underlying}
	request := []byte{8, 0, 0xf7, 0xff, 0, 0, 0, 0}
	addrs := []net.Addr{
		&net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 0},
		&net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53},
	}
	written, err := conn.ChitandaBatchWrite([][]byte{request, []byte("dns")}, addrs)
	if err != nil || written != len(request)+3 {
		t.Fatalf("batch write: bytes=%d err=%v", written, err)
	}
	if written, err = conn.ChitandaBatchWrite([][]byte{request}, addrs); err == nil || written != 0 {
		t.Fatalf("mismatched batch accepted: bytes=%d err=%v", written, err)
	}
}
