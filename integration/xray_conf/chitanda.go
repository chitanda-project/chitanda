package conf

import (
	"fmt"
	"github.com/violetaini/chitanda/pkg/client"
	"github.com/xtls/xray-core/proxy/chitanda"
	"google.golang.org/protobuf/proto"
	"net"
	"strings"
)

type ChitandaInboundConfig struct {
	PSK           string `json:"psk"`
	Path          string `json:"path"`
	Transport     string `json:"transport"`
	StrictSNI     string `json:"strict_sni"`
	Fallback      string `json:"fallback"`
	ServerID      string `json:"server_id"`
	ServerId      string `json:"serverId"`
	ServerHyphen  string `json:"server-id"`
	ReplayFile    string `json:"replay_file"`
	CertFile      string `json:"cert_file"`
	CertFileCamel string `json:"certFile"`
	KeyFile       string `json:"key_file"`
	KeyFileCamel  string `json:"keyFile"`
}

// InheritTLS reuses an explicitly configured Xray server certificate for the
// native QUIC listener. Never manufacture a protocol-identifying certificate.
func (c *ChitandaInboundConfig) InheritTLS(stream *StreamConfig) {
	if c.CertFile != "" || c.CertFileCamel != "" || c.KeyFile != "" || c.KeyFileCamel != "" {
		return
	}
	if stream == nil || stream.TLSSettings == nil {
		return
	}
	for _, cert := range stream.TLSSettings.Certs {
		if cert != nil && (cert.Usage == "" || strings.EqualFold(cert.Usage, "encipherment")) && cert.CertFile != "" && cert.KeyFile != "" {
			c.CertFile, c.KeyFile = cert.CertFile, cert.KeyFile
			return
		}
	}
}

func validateChitanda(psk, mode string) error {
	if len(psk) < 32 {
		return fmt.Errorf("chitanda: psk must contain at least 32 bytes")
	}
	switch mode {
	case "", "stream", "h1", "plain-h1", "h2", "h3", "auto":
		return nil
	default:
		return fmt.Errorf("chitanda: unsupported transport %q", mode)
	}
}

func (c *ChitandaInboundConfig) Build() (proto.Message, error) {
	if err := validateChitanda(c.PSK, c.Transport); err != nil {
		return nil, err
	}
	if c.Path == "" {
		c.Path = "/api/v1/sync"
	}
	if err := client.ValidatePath(c.Path); err != nil {
		return nil, err
	}
	sid := c.ServerID
	if sid == "" {
		sid = c.ServerId
	}
	if sid == "" {
		sid = c.ServerHyphen
	}
	certFile := c.CertFile
	if certFile == "" {
		certFile = c.CertFileCamel
	}
	keyFile := c.KeyFile
	if keyFile == "" {
		keyFile = c.KeyFileCamel
	}
	if (certFile == "") != (keyFile == "") {
		return nil, fmt.Errorf("chitanda: cert_file and key_file must be supplied together")
	}
	return &chitanda.InboundConfig{
		Psk:        c.PSK,
		Path:       c.Path,
		Transport:  c.Transport,
		StrictSni:  c.StrictSNI,
		Fallback:   c.Fallback,
		ServerId:   sid,
		ReplayFile: c.ReplayFile,
		CertFile:   certFile,
		KeyFile:    keyFile,
	}, nil
}

type ChitandaOutboundConfig struct {
	Server             string `json:"server"`
	ServerName         string `json:"server_name"`
	PSK                string `json:"psk"`
	Path               string `json:"path"`
	Transport          string `json:"transport"`
	PoolSize           int32  `json:"pool_size"`
	ServerID           string `json:"server_id"`
	ServerId           string `json:"serverId"`
	ServerHyphen       string `json:"server-id"`
	AllowInsecure      bool   `json:"allow_insecure"`
	AllowInsecureCamel bool   `json:"allowInsecure"`
}

func (c *ChitandaOutboundConfig) Build() (proto.Message, error) {
	if err := validateChitanda(c.PSK, c.Transport); err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(c.Server)
	if err != nil {
		return nil, fmt.Errorf("chitanda: server must be host:port: %w", err)
	}
	if c.ServerName == "" {
		c.ServerName = host
	}
	if c.Path == "" {
		c.Path = "/api/v1/sync"
	}
	if err := client.ValidateConfig(client.Config{Server: c.Server, ServerName: c.ServerName, PSK: []byte(c.PSK), Path: c.Path, TCPTransport: c.Transport}); err != nil {
		return nil, err
	}
	sid := c.ServerID
	if sid == "" {
		sid = c.ServerId
	}
	if sid == "" {
		sid = c.ServerHyphen
	}
	return &chitanda.OutboundConfig{
		Server:        c.Server,
		ServerName:    c.ServerName,
		Psk:           c.PSK,
		Path:          c.Path,
		Transport:     c.Transport,
		PoolSize:      c.PoolSize,
		ServerId:      sid,
		AllowInsecure: c.AllowInsecure || c.AllowInsecureCamel,
	}, nil
}
