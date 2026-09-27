package outbound

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/violetaini/chitanda/pkg/client"
	"github.com/violetaini/chitanda/pkg/plugin/autoscaler"

	C "github.com/metacubex/mihomo/constant"
	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
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
	AutoScale        *bool `proxy:"auto-scale,omitempty"`
	ScaleUpThreshold int   `proxy:"scale-up-threshold,omitempty"`
	ScaleDownIdle    int   `proxy:"scale-down-idle,omitempty"`
	Cooldown         int   `proxy:"cooldown,omitempty"`
	UDP              *bool `proxy:"udp,omitempty"`
	SkipCertVerify   bool  `proxy:"skip-cert-verify,omitempty"`
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
	if shouldAutoScale(c.option) {
		maxCarriers := c.option.MaxPoolSize
		if maxCarriers <= 0 {
			maxCarriers = 8
		}
		scalerCfg := autoscaler.Config{
			MaxCarriers: maxCarriers,
		}
		if c.option.ScaleUpThreshold > 0 {
			scalerCfg.ScaleUpThreshold = int64(c.option.ScaleUpThreshold)
		}
		if c.option.ScaleDownIdle > 0 {
			scalerCfg.ScaleDownIdle = time.Duration(c.option.ScaleDownIdle) * time.Second
		}
		if c.option.Cooldown > 0 {
			scalerCfg.Cooldown = time.Duration(c.option.Cooldown) * time.Millisecond
		}
		scaler = autoscaler.New(scalerCfg)
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

func shouldAutoScale(option *ChitandaOption) bool {
	if option.AutoScale != nil {
		return *option.AutoScale
	}
	if option.MaxPoolSize > 0 && option.MaxPoolSize <= option.PoolSize {
		return false
	}
	return true
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

func (c *Chitanda) SupportICMP() bool {
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

func (c *Chitanda) CreateICMPDestination(sourceAddr, destinationAddr netip.Addr, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	if c.option.UDP != nil && !*c.option.UDP {
		return nil, errors.New("chitanda: udp/icmp is disabled for this node")
	}

	cli, err := c.getClient()
	if err != nil {
		return nil, fmt.Errorf("chitanda get client: %w", err)
	}

	pconn, err := cli.ListenPacket(context.Background())
	if err != nil {
		return nil, fmt.Errorf("chitanda listen icmp packet: %w", err)
	}

	dest := &chitandaICMPDestination{
		pconn:        pconn,
		clientIP:     sourceAddr,
		targetIP:     destinationAddr,
		routeContext: routeContext,
		timeout:      timeout,
		done:         make(chan struct{}),
	}

	go dest.loopRead()
	return dest, nil
}

type chitandaICMPDestination struct {
	pconn        net.PacketConn
	clientIP     netip.Addr
	targetIP     netip.Addr
	routeContext tun.DirectRouteContext
	timeout      time.Duration
	closed       atomic.Bool
	done         chan struct{}
}

func (d *chitandaICMPDestination) WritePacket(packet *buf.Buffer) error {
	if d.closed.Load() {
		return errors.New("chitanda icmp destination closed")
	}
	raw := packet.Bytes()
	var icmpPayload []byte
	if d.targetIP.Is4() {
		if len(raw) < 20 {
			return errors.New("chitanda icmp: ipv4 packet too short")
		}
		ihl := int(raw[0]&0x0f) * 4
		if len(raw) < ihl+8 {
			return errors.New("chitanda icmp: packet shorter than ihl+icmp")
		}
		icmpPayload = raw[ihl:]
	} else {
		if len(raw) < 48 {
			return errors.New("chitanda icmp: ipv6 packet too short")
		}
		icmpPayload = raw[40:]
	}

	_ = d.pconn.SetWriteDeadline(time.Now().Add(d.timeout))
	targetAddr := &client.ICMPAddr{IP: d.targetIP.AsSlice()}
	_, err := d.pconn.WriteTo(icmpPayload, targetAddr)
	return err
}

func (d *chitandaICMPDestination) loopRead() {
	defer d.Close()
	buf := make([]byte, 2048)
	for {
		if d.closed.Load() {
			return
		}
		_ = d.pconn.SetReadDeadline(time.Now().Add(d.timeout))
		n, _, err := d.pconn.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < 8 {
			continue
		}
		replyPkt := buf[:n]
		var ipPacket []byte
		if d.targetIP.Is4() {
			ipPacket = buildIPv4Packet(d.targetIP, d.clientIP, replyPkt)
		} else {
			ipPacket = buildIPv6Packet(d.targetIP, d.clientIP, replyPkt)
		}
		_ = d.routeContext.WritePacket(ipPacket)
	}
}

func (d *chitandaICMPDestination) Close() error {
	if d.closed.CompareAndSwap(false, true) {
		close(d.done)
		return d.pconn.Close()
	}
	return nil
}

func (d *chitandaICMPDestination) IsClosed() bool {
	return d.closed.Load()
}

func buildIPv4Packet(srcIP, dstIP netip.Addr, icmpPkt []byte) []byte {
	totalLen := 20 + len(icmpPkt)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45 // Version 4, IHL 5
	pkt[1] = 0
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // DF
	pkt[8] = 64                                  // TTL
	pkt[9] = 1                                   // Protocol: ICMP
	src4 := srcIP.As4()
	dst4 := dstIP.As4()
	copy(pkt[12:16], src4[:])
	copy(pkt[16:20], dst4[:])

	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(sum))

	copy(pkt[20:], icmpPkt)
	return pkt
}

func buildIPv6Packet(srcIP, dstIP netip.Addr, icmpPkt []byte) []byte {
	totalLen := 40 + len(icmpPkt)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(icmpPkt)))
	pkt[6] = 58 // ICMPv6
	pkt[7] = 64 // Hop Limit
	src16 := srcIP.As16()
	dst16 := dstIP.As16()
	copy(pkt[8:24], src16[:])
	copy(pkt[24:40], dst16[:])
	copy(pkt[40:], icmpPkt)
	return pkt
}

