package client

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ValidateConfig performs no network I/O or background initialization. Embedded
// cores call it during config loading, rather than accepting unusable nodes.
func ValidateConfig(cfg Config) error {
	host, portText, err := net.SplitHostPort(cfg.Server)
	if err != nil || strings.TrimSpace(host) == "" {
		return fmt.Errorf("chitanda: server must be host:port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("chitanda: server port must be 1..65535")
	}
	if len(cfg.PSK) < 32 {
		return fmt.Errorf("chitanda: PSK must contain at least 32 bytes")
	}
	switch cfg.TCPTransport {
	case "", TCPTransportH2, TCPTransportH3, TCPTransportAuto, TCPTransportH1, TCPTransportPlainH1, TCPTransportStream:
	default:
		return fmt.Errorf("chitanda: invalid transport %q", cfg.TCPTransport)
	}
	if cfg.TCPTransport != TCPTransportStream {
		if err := ValidatePath(cfg.Path); err != nil {
			return err
		}
	}
	if cfg.TCPTransport != "stream" && cfg.TCPTransport != "h1" && cfg.TCPTransport != "plain-h1" && cfg.ServerName == "" {
		return fmt.Errorf("chitanda: serverName is required for TLS carriers")
	}
	return nil
}

func ValidatePath(path string) error {
	u, err := url.ParseRequestURI(path)
	if err != nil || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || u == nil || u.RawQuery != "" || u.Fragment != "" || u.Path != path {
		return fmt.Errorf("chitanda: path must be an absolute unescaped URL path without query or fragment")
	}
	return nil
}
