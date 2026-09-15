package client

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestPacketDialFailureReturnsNilInterface(t *testing.T) {
	c, err := New(Config{Server: "127.0.0.1:9999", PSK: []byte(strings.Repeat("x", 32)), TCPTransport: "stream", DialPacket: func(context.Context, *net.UDPAddr) (net.PacketConn, error) { return nil, errors.New("denied") }})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p, err := c.ListenPacket(context.Background())
	if err == nil || p != nil {
		t.Fatal("failed ListenPacket must return a nil interface")
	}
}

func TestUDPDomainAddressPreserved(t *testing.T) {
	const address = "preserve.invalid:53"
	if got := parseUDPAddr(address); got.String() != address || got.Network() != "udp" {
		t.Fatalf("domain response metadata lost: %v", got)
	}
}
