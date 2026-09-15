package conf

import (
	"github.com/xtls/xray-core/proxy/chitanda"
	"testing"
)

func TestChitandaTLSInheritanceAndDefaults(t *testing.T) {
	c := ChitandaInboundConfig{PSK: "test-only-key-that-is-at-least-32-bytes", Transport: "h3"}
	c.InheritTLS(&StreamConfig{TLSSettings: &TLSConfig{Certs: []*TLSCertConfig{{CertFile: "server.pem", KeyFile: "server.key"}}}})
	m, err := c.Build()
	if err != nil {
		t.Fatal(err)
	}
	cfg := m.(*chitanda.InboundConfig)
	if cfg.CertFile != "server.pem" || cfg.KeyFile != "server.key" || cfg.Path != "/api/v1/sync" {
		t.Fatal("inheritance/default failed")
	}
	c.InheritTLS(&StreamConfig{TLSSettings: &TLSConfig{Certs: []*TLSCertConfig{{CertFile: "other.pem", KeyFile: "other.key"}}}})
	if c.CertFile != "server.pem" {
		t.Fatal("explicit certificate overwritten")
	}
	out := ChitandaOutboundConfig{Server: "example.com:443", PSK: c.PSK}
	om, err := out.Build()
	if err != nil {
		t.Fatal(err)
	}
	if om.(*chitanda.OutboundConfig).ServerName != "example.com" {
		t.Fatal("server_name default lost")
	}
	if _, err := (&ChitandaInboundConfig{PSK: c.PSK, CertFile: "only-cert"}).Build(); err == nil {
		t.Fatal("incomplete key pair accepted")
	}
	if _, err := (&ChitandaOutboundConfig{PSK: c.PSK, Server: "example.com:443", Transport: "typo"}).Build(); err == nil {
		t.Fatal("invalid transport accepted")
	}
}
