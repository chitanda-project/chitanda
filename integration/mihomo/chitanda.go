package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/violetaini/chitanda/pkg/client"
	"github.com/violetaini/chitanda/pkg/plugin/autoscaler"

	C "github.com/metacubex/mihomo/constant"
)

type ChitandaOption struct {
	BasicOption
	Name           string `proxy:"name"`
	Server         string `proxy:"server"`
	Port           int    `proxy:"port"`
	PSK            string `proxy:"psk"`
	Path           string `proxy:"path,omitempty"`
	Transport      string `proxy:"transport,omitempty"` // "h2" (default), "h3", "auto", "h1", "stream", "plain-h1"
	SNI            string `proxy:"sni,omitempty"`
	ServerID       string `proxy:"server-id,omitempty"`
	PoolSize       int    `proxy:"pool-size,omitempty"`
	UDPPoolSize    int    `proxy:"udp-pool-size,omitempty"`
	MaxPoolSize    int    `proxy:"max-pool-size,omitempty"`
	AutoScale      *bool  `proxy:"auto-scale,omitempty"`
	UDP            *bool  `proxy:"udp,omitempty"`
	SkipCertVerify bool   `proxy:"skip-cert-verify,omitempty"`
}

type Chitanda struct {
	*Base
	option *ChitandaOption
	client *client.Client
	initMu sync.Mutex
}

func (c *Chitanda) ProxyInfo() C.ProxyInfo {
	info := c.Base.ProxyInfo()
	info.DialerProxy = c.option.DialerProxy
	return info
}

func NewChitanda(option ChitandaOption) (*Chitanda, error) {
	if option.Server == "" || option.Port == 0 {
		return nil, errors.New("chitanda: server and port are required")
	}
	if option.PSK == "" {
		return nil, errors.New("chitanda: psk is required")
	}
	if option.Path == "" {
		option.Path = "/api/v1/sync"
	}
	if option.Transport == "" {
		option.Transport = "h2"
	}
	if option.PoolSize <= 0 {
		option.PoolSize = 4
	}

	udpEnabled := true
	if option.UDP != nil {
		udpEnabled = *option.UDP
	} else {
		option.UDP = &udpEnabled
	}

	serverAddr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	sni := option.SNI
	if sni == "" && option.Transport != "h1" && option.Transport != "plain-h1" {
		sni = option.Server
	}
	if err := client.ValidateConfig(client.Config{Server: serverAddr, ServerName: sni, PSK: []byte(option.PSK), Path: option.Path, TCPTransport: option.Transport}); err != nil {
		return nil, err
	}

	c := &Chitanda{
		Base: NewBase(BaseOption{
			Name:        option.Name,
			Addr:        serverAddr,
			Type:        C.Chitanda,
			UDP:         udpEnabled,
			TFO:         false,
			Interface:   option.Interface,
			RoutingMark: option.RoutingMark,
			Prefer:      option.IPVersion,
		}),
		option: &option,
	}
	c.dialer = option.NewDialer(c.DialOptions())

	return c, nil
}

func (c *Chitanda) getClient() (*client.Client, error) {
	c.initMu.Lock()
	defer c.initMu.Unlock()

	if c.client != nil {
		return c.client, nil
	}

	serverAddr := net.JoinHostPort(c.option.Server, strconv.Itoa(c.option.Port))
	sni := c.option.SNI
	if sni == "" && c.option.Transport != "h1" && c.option.Transport != "plain-h1" {
		sni = c.option.Server
	}

	var scaler client.AutoscalerPlugin
	autoScaleEnabled := false
	if c.option.AutoScale != nil && *c.option.AutoScale {
		autoScaleEnabled = true
	} else if c.option.MaxPoolSize > c.option.PoolSize && c.option.MaxPoolSize > 0 {
		autoScaleEnabled = true
	}
	if autoScaleEnabled {
		maxCarriers := c.option.MaxPoolSize
		if maxCarriers <= 0 {
			maxCarriers = 8
		}
		scaler = autoscaler.New(autoscaler.Config{
			MaxCarriers: maxCarriers,
		})
	}

	cli, err := client.New(client.Config{
		Server:             serverAddr,
		ServerName:         sni,
		ServerID:           c.option.ServerID,
		PSK:                []byte(c.option.PSK),
		Path:               c.option.Path,
		TCPTransport:       c.option.Transport,
		TCPPoolSize:        c.option.PoolSize,
		UDPPoolSize:        c.option.UDPPoolSize,
		MaxPoolSize:        c.option.MaxPoolSize,
		Autoscaler:         scaler,
		InsecureSkipVerify: c.option.SkipCertVerify,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return c.dialer.DialContext(ctx, network, addr)
		},
		DialPacket: func(ctx context.Context, remote *net.UDPAddr) (net.PacketConn, error) {
			return c.dialer.ListenPacket(ctx, "udp", ":0", remote.AddrPort())
		},
		ResolveUDP: func(ctx context.Context, network, addr string) (*net.UDPAddr, error) {
			return resolveUDPAddr(ctx, network, addr, c.option.IPVersion)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("init chitanda client sdk: %w", err)
	}

	c.client = cli
	return c.client, nil
}

func (c *Chitanda) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	cli, err := c.getClient()
	if err != nil {
		return nil, err
	}

	targetAddr := metadata.RemoteAddress()
	conn, err := cli.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("chitanda dial tcp %q: %w", targetAddr, err)
	}

	return NewConn(conn, c), nil
}

func (c *Chitanda) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if c.option.UDP != nil && !*c.option.UDP {
		return nil, errors.New("chitanda: udp is disabled for this node")
	}

	if metadata != nil {
		if err := c.ResolveUDP(ctx, metadata); err != nil {
			return nil, err
		}
	}

	cli, err := c.getClient()
	if err != nil {
		return nil, err
	}

	pconn, err := cli.ListenPacket(ctx)
	if err != nil {
		return nil, fmt.Errorf("chitanda listen udp: %w", err)
	}

	return NewPacketConn(pconn, c), nil
}

func (c *Chitanda) SupportUDP() bool {
	if c.option.UDP != nil {
		return *c.option.UDP
	}
	return true
}

func (c *Chitanda) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"type":      C.Chitanda.String(),
		"server":    c.option.Server,
		"port":      c.option.Port,
		"path":      c.option.Path,
		"transport": c.option.Transport,
		"sni":       c.option.SNI,
		"server-id": c.option.ServerID,
		"udp":       c.option.UDP,
	})
}

func (c *Chitanda) Close() error {
	c.initMu.Lock()
	defer c.initMu.Unlock()

	if c.client != nil {
		c.client.Close()
		c.client = nil
	}
	return nil
}
