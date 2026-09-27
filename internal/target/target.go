package target

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

var ErrForbidden = errors.New("target is not a public unicast address")

var specialUseNetworks = mustNetworks(
	"0.0.0.0/8",
	"100.64.0.0/10",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"240.0.0.0/4",
	"100::/64",
	"2001:2::/48",
	"2001:db8::/32",
)

func DialContext(ctx context.Context, address string) (net.Conn, error) {
	_, portText, addresses, err := resolve(ctx, address)
	if err != nil {
		return nil, err
	}
	for _, candidate := range addresses {
		if !allowed(candidate.IP) {
			continue
		}
		dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}
		conn, dialErr := dialer.DialContext(ctx, "tcp", net.JoinHostPort(candidate.IP.String(), portText))
		if dialErr == nil {
			return conn, nil
		}
		err = dialErr
	}
	if err != nil {
		return nil, err
	}
	return nil, ErrForbidden
}

func ResolveUDPAddr(ctx context.Context, address string) (*net.UDPAddr, error) {
	_, portText, addresses, err := resolve(ctx, address)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(portText)
	for _, candidate := range addresses {
		if allowed(candidate.IP) {
			return &net.UDPAddr{IP: candidate.IP, Port: port, Zone: candidate.Zone}, nil
		}
	}
	return nil, ErrForbidden
}

// ResolveICMPIP resolves one ICMP destination and applies the same public-target
// policy as TCP and UDP unless private targets were explicitly enabled.
func ResolveICMPIP(ctx context.Context, host string, allowPrivate bool) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !allowPrivate && !allowed(ip) {
			return nil, ErrForbidden
		}
		if !ip.IsGlobalUnicast() && !ip.IsLoopback() {
			return nil, ErrForbidden
		}
		return ip, nil
	}
	resolver := net.Resolver{}
	addresses, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, candidate := range addresses {
		if (allowPrivate || allowed(candidate.IP)) && (candidate.IP.IsGlobalUnicast() || candidate.IP.IsLoopback()) {
			return candidate.IP, nil
		}
	}
	return nil, ErrForbidden
}

func resolve(ctx context.Context, address string) (string, string, []net.IPAddr, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", "", nil, fmt.Errorf("invalid target: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", "", nil, errors.New("invalid target port")
	}
	resolver := net.Resolver{}
	addresses, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", "", nil, err
	}
	return host, portText, addresses, nil
}

func allowed(ip net.IP) bool {
	if ip == nil ||
		!ip.IsGlobalUnicast() ||
		ip.IsPrivate() ||
		ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() {
		return false
	}
	for _, network := range specialUseNetworks {
		if network.Contains(ip) {
			return false
		}
	}
	return true
}

func mustNetworks(values ...string) []*net.IPNet {
	networks := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			panic(err)
		}
		networks = append(networks, network)
	}
	return networks
}
