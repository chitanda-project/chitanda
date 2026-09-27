// Package icmp exposes ICMP relay primitives to embedding cores.
package icmp

import (
	"context"
	"net"

	"github.com/violetaini/chitanda/internal/icmpmsg"
	"github.com/violetaini/chitanda/internal/target"
)

type EchoTracker = icmpmsg.EchoTracker

func ValidateEchoRequest(packet []byte, ipv6 bool) error {
	return icmpmsg.ValidateEchoRequest(packet, ipv6)
}

func BuildEchoRequest(id, seq uint16, data []byte, ipv6 bool) []byte {
	return icmpmsg.BuildEchoRequest(id, seq, data, ipv6)
}

func ResolveIP(ctx context.Context, host string, allowPrivate bool) (net.IP, error) {
	return target.ResolveICMPIP(ctx, host, allowPrivate)
}
