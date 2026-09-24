// Package client provides the core MyXray client SDK for embedding into
// proxy frameworks (such as Xray-core and Mihomo/Clash.Meta) or standalone binaries.
// It exposes standard Go net.Conn (TCP) and net.PacketConn (UDP) interfaces.
package client

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/violetaini/chitanda/internal/auth"
	"github.com/violetaini/chitanda/internal/quicconfig"
	"github.com/violetaini/chitanda/internal/sessioncache"
)

const (
	HeaderTarget         = "X-Session-Target"
	HeaderTimestamp      = "X-Session-Time"
	HeaderNonce          = "X-Session-Nonce"
	HeaderSignature      = "X-Session-Auth"
	HeaderSessionOK      = "X-Session-OK"
	HeaderFraming        = "X-Session-Framing"
	HeaderMode           = "X-Session-Mode"
	ModeTCPv2            = "tcp-v2"
	ModeUDPv2            = "udp-v2"
	UDPAssociationTarget = "udp-association"

	TCPTransportAuto    = "auto"
	TCPTransportH2      = "h2"
	TCPTransportH3      = "h3"
	TCPTransportPlainH1 = "plain-h1"
	TCPTransportH1      = "h1"
	TCPTransportStream  = "stream"
	DefaultTCPTransport = TCPTransportH2
	DefaultTCPPoolSize  = 4

	defaultCarrierTimeout = 15 * time.Second
	autoH2ConnectTimeout  = 4 * time.Second
)

// Config holds the client configuration.
type Config struct {
	Server                string // e.g. "170.9.59.149:11322"
	ServerName            string // e.g. "status.chitanda.org"
	PSK                   []byte // 32+ bytes PSK
	Path                  string // e.g. "/your-private-path"
	TCPTransport          string // "h2" (default), "auto", "h3", or "h1" (alias: "plain-h1")
	TCPPoolSize           int    // Number of independent physical TCP carriers (H2 or H3, default 4)
	UDPPoolSize           int    // Number of independent physical UDP carriers (H3, default TCPPoolSize or 4)
	SessionCacheFile      string // optional persistent session cache path
	QUICInitialPacketSize uint16 // 1200 - 1452, default 1452
	InsecureSkipVerify    bool   // skip TLS certificate verification
	ServerID              string // optional target server ID for RawStream cross-node replay protection
	DialContext           func(ctx context.Context, network, addr string) (net.Conn, error)
	ListenPacket          func(ctx context.Context, network, addr string) (net.PacketConn, error)
	// DialPacket optionally opens a packet socket to the resolved tunnel peer.
	// Embedding cores can route this through their own UDP dispatcher.
	DialPacket func(ctx context.Context, remote *net.UDPAddr) (net.PacketConn, error)
	ResolveUDP func(ctx context.Context, network, addr string) (*net.UDPAddr, error)
	Autoscaler AutoscalerPlugin // optional dynamic auto-scaling plugin
	MaxPoolSize int // max allowed carriers under scaling (default 8, max 16)
}

// Client is the MyXray core client engine.
type Client struct {
	cfg          Config
	rootURL      string
	requestURL   string
	carrierMu    sync.RWMutex
	scaleMu      sync.Mutex
	h2Clients    []*h2TransportClient
	nextH2Idx    atomic.Uint64
	h3Managers   []*h3TransportManager
	nextH3Idx    atomic.Uint64
	sessionCache *sessioncache.Cache
	prober       *h2Prober
	autoscaler   AutoscalerPlugin
	maxCarriers  int
	mu           sync.Mutex
	closed       bool
}

func (c *Client) dialRaw(ctx context.Context, network, addr string) (net.Conn, error) {
	if c.cfg.DialContext != nil {
		return c.cfg.DialContext(ctx, network, addr)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, addr)
}

// New creates and initializes a new MyXray Client.
func New(cfg Config) (*Client, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	if cfg.TCPTransport == TCPTransportStream {
		if cfg.Server == "" || len(cfg.PSK) < 32 {
			return nil, errors.New("server and valid PSK (>=32 bytes) are required for stream")
		}
		if cfg.ServerName == "" {
			cfg.ServerName = cfg.Server
		}
	} else if cfg.TCPTransport == TCPTransportPlainH1 || cfg.TCPTransport == TCPTransportH1 {
		if cfg.Server == "" || len(cfg.PSK) < 32 || cfg.Path == "" {
			return nil, errors.New("server, path, and valid PSK (>=32 bytes) are required for h1")
		}
		if cfg.ServerName == "" {
			cfg.ServerName = cfg.Server
		}
	} else {
		if cfg.Server == "" || cfg.ServerName == "" || len(cfg.PSK) < 32 || cfg.Path == "" {
			return nil, errors.New("server, serverName, path, and valid PSK (>=32 bytes) are required")
		}
	}
	if cfg.TCPTransport == "" {
		cfg.TCPTransport = DefaultTCPTransport
	}
	if cfg.TCPTransport != TCPTransportH2 && cfg.TCPTransport != TCPTransportAuto && cfg.TCPTransport != TCPTransportH3 && cfg.TCPTransport != TCPTransportPlainH1 && cfg.TCPTransport != TCPTransportH1 && cfg.TCPTransport != TCPTransportStream {
		return nil, fmt.Errorf("invalid tcp transport %q: must be h2, auto, h3, h1, or stream", cfg.TCPTransport)
	}
	if cfg.TCPPoolSize <= 0 {
		cfg.TCPPoolSize = DefaultTCPPoolSize
	}
	if cfg.TCPPoolSize > 16 {
		cfg.TCPPoolSize = 16
	}
	if cfg.UDPPoolSize <= 0 {
		cfg.UDPPoolSize = cfg.TCPPoolSize
	}
	if cfg.UDPPoolSize > 16 {
		cfg.UDPPoolSize = 16
	}
	if cfg.QUICInitialPacketSize == 0 {
		cfg.QUICInitialPacketSize = quicconfig.DefaultInitialPacketSize
	}

	port := portOf(cfg.Server)
	scheme := "https://"
	if cfg.TCPTransport == TCPTransportPlainH1 || cfg.TCPTransport == TCPTransportH1 {
		scheme = "http://"
	}
	rootURL := scheme + net.JoinHostPort(cfg.ServerName, port) + "/"
	requestURL := strings.TrimSuffix(rootURL, "/") + cfg.Path

	var cache *sessioncache.Cache
	if cfg.SessionCacheFile != "" {
		c, err := sessioncache.Open(cfg.SessionCacheFile)
		if err == nil {
			cache = c
		}
	}

	var h2Clients []*h2TransportClient
	var h3Managers []*h3TransportManager

	if cfg.TCPTransport != TCPTransportPlainH1 && cfg.TCPTransport != TCPTransportH1 && cfg.TCPTransport != TCPTransportStream {
		// H2 / H3 initialization
		h2Count := cfg.TCPPoolSize
		if cfg.TCPTransport == TCPTransportH3 {
			h2Count = 0
		}
		for i := 0; i < h2Count; i++ {
			h2Cli, err := newH2TransportClient(cfg.Server, cfg.ServerName, rootURL, requestURL, cfg.Path, cfg.PSK, cfg.InsecureSkipVerify, cfg.DialContext)
			if err != nil {
				return nil, fmt.Errorf("init h2 client %d: %w", i, err)
			}
			h2Clients = append(h2Clients, h2Cli)
		}

		h3Count := cfg.UDPPoolSize
		if cfg.TCPTransport == TCPTransportH3 || cfg.TCPTransport == TCPTransportAuto {
			if cfg.TCPPoolSize > h3Count {
				h3Count = cfg.TCPPoolSize
			}
		}
		for i := 0; i < h3Count; i++ {
			h3Managers = append(h3Managers, newH3TransportManager(
				cfg.Server, cfg.ServerName, rootURL, requestURL, cfg.Path, cfg.PSK, cache, cfg.QUICInitialPacketSize, cfg.InsecureSkipVerify, cfg.ListenPacket, cfg.ResolveUDP, cfg.DialPacket,
			))
		}
	}

	maxCarriers := cfg.MaxPoolSize
	if maxCarriers <= 0 {
		maxCarriers = 8
	}
	if maxCarriers > 16 {
		maxCarriers = 16
	}
	if maxCarriers < cfg.TCPPoolSize {
		maxCarriers = cfg.TCPPoolSize
	}
	if maxCarriers < cfg.UDPPoolSize {
		maxCarriers = cfg.UDPPoolSize
	}

	c := &Client{
		cfg:          cfg,
		rootURL:      rootURL,
		requestURL:   requestURL,
		h2Clients:    h2Clients,
		h3Managers:   h3Managers,
		sessionCache: cache,
		maxCarriers:  maxCarriers,
		autoscaler:   cfg.Autoscaler,
	}
	if cfg.TCPTransport == TCPTransportAuto {
		c.prober = newH2Prober(c)
	}
	if c.autoscaler != nil {
		if err := c.autoscaler.Init(c); err != nil {
			c.Close()
			return nil, fmt.Errorf("init autoscaler plugin: %w", err)
		}
	}
	return c, nil
}

// DialContext establishes an outbound TCP connection to target (host:port).
// Returns a standard net.Conn that can be directly used by Xray or Mihomo.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("client closed")
	}
	c.mu.Unlock()

	if c.cfg.TCPTransport == TCPTransportStream {
		return c.dialRawStream(ctx, address)
	}

	if c.cfg.TCPTransport == TCPTransportPlainH1 || c.cfg.TCPTransport == TCPTransportH1 {
		return c.dialPlainH1(ctx, address)
	}

	if c.cfg.TCPTransport == TCPTransportH2 || (c.cfg.TCPTransport == TCPTransportAuto && !c.prober.h2Degraded.Load()) {
		if h2Cli := c.pickBestH2Client(); h2Cli != nil {
			h2Ctx := ctx
			var cancel context.CancelFunc
			if c.cfg.TCPTransport == TCPTransportAuto {
				h2Ctx, cancel = context.WithTimeout(ctx, autoH2ConnectTimeout)
			}
			conn, err := h2Cli.dialH2TCP(h2Ctx, address)
			if cancel != nil {
				cancel()
			}
			if err == nil {
				return conn, nil
			}
			if c.cfg.TCPTransport == TCPTransportH2 {
				return nil, fmt.Errorf("h2 tcp dial failed: %w", err)
			}
			// In auto mode, fallback to H3 if caller's root context is not canceled
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
	}
	h3Mgr := c.reserveH3Manager()
	if h3Mgr == nil {
		return nil, errors.New("no H3 transport available")
	}
	conn, err := h3Mgr.dialH3TCP(ctx, address)
	if err != nil {
		h3Mgr.activeStreams.Add(-1)
		return nil, err
	}
	return conn, nil
}

func (c *Client) pickBestH2Client() *h2TransportClient {
	c.carrierMu.RLock()
	n := len(c.h2Clients)
	if n == 0 {
		c.carrierMu.RUnlock()
		return nil
	}
	if n == 1 {
		cli := c.h2Clients[0]
		c.carrierMu.RUnlock()
		if c.autoscaler != nil {
			c.autoscaler.OnActivity("h2", cli.activeStreams.Load(), 1)
		}
		return cli
	}

	start := int(c.nextH2Idx.Add(1) % uint64(n))
	best := c.h2Clients[start]
	minActive := best.activeStreams.Load()

	for i := 1; i < n; i++ {
		idx := (start + i) % n
		cli := c.h2Clients[idx]
		active := cli.activeStreams.Load()
		if active < minActive {
			minActive = active
			best = cli
		}
	}
	c.carrierMu.RUnlock()

	if c.autoscaler != nil {
		c.autoscaler.OnActivity("h2", minActive, n)
	}
	return best
}

func (c *Client) pickBestH3Manager() *h3TransportManager {
	c.carrierMu.RLock()
	n := len(c.h3Managers)
	if n == 0 {
		c.carrierMu.RUnlock()
		return nil
	}
	if n == 1 {
		mgr := c.h3Managers[0]
		c.carrierMu.RUnlock()
		if c.autoscaler != nil {
			c.autoscaler.OnActivity("h3", mgr.activeStreams.Load(), 1)
		}
		return mgr
	}

	start := int(c.nextH3Idx.Add(1) % uint64(n))
	best := c.h3Managers[start]
	minActive := best.activeStreams.Load()

	for i := 1; i < n; i++ {
		idx := (start + i) % n
		manager := c.h3Managers[idx]
		active := manager.activeStreams.Load()
		if active < minActive {
			minActive = active
			best = manager
		}
	}
	c.carrierMu.RUnlock()

	if c.autoscaler != nil {
		c.autoscaler.OnActivity("h3", minActive, n)
	}
	return best
}

func (c *Client) reserveH3Manager() *h3TransportManager {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	manager := c.pickBestH3Manager()
	if manager != nil {
		manager.activeStreams.Add(1)
	}
	return manager
}

// ListenPacket creates a net.PacketConn for native UDP proxying over QUIC Datagrams (or Plain-UDP Datagrams).
// Returns a net.PacketConn that can be directly used by Xray or Mihomo for UDP associate / datagram dispatch.
func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("client closed")
	}
	c.mu.Unlock()

	if c.cfg.TCPTransport == TCPTransportPlainH1 || c.cfg.TCPTransport == TCPTransportH1 || c.cfg.TCPTransport == TCPTransportStream {
		pconn, err := newPlainUDPConn(ctx, c.cfg.Server, c.cfg.PSK, c.cfg.ListenPacket, c.cfg.ResolveUDP, c.cfg.DialPacket)
		if err != nil {
			return nil, err
		}
		return pconn, nil
	}

	h3Mgr := c.reserveH3Manager()
	if h3Mgr == nil {
		return nil, errors.New("no H3 transport available")
	}
	pconn, err := h3Mgr.createPacketConn(ctx)
	if err != nil {
		h3Mgr.activeStreams.Add(-1)
		return nil, err
	}
	return pconn, nil
}

// Prewarm optionally warms the H2 TLS connections in the pool concurrently.
func (c *Client) Prewarm(ctx context.Context) error {
	prewarmCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	c.carrierMu.RLock()
	clients := make([]*h2TransportClient, len(c.h2Clients))
	copy(clients, c.h2Clients)
	c.carrierMu.RUnlock()

	var wg sync.WaitGroup
	for _, cli := range clients {
		wg.Add(1)
		go func(h *h2TransportClient) {
			defer wg.Done()
			_ = h.prewarm(prewarmCtx)
		}(cli)
	}
	wg.Wait()
	return nil
}

// Close terminates the client and all background connections.
func (c *Client) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()

	if c.autoscaler != nil {
		_ = c.autoscaler.Close()
	}

	if c.prober != nil {
		c.prober.Close()
	}

	c.carrierMu.Lock()
	h2List := c.h2Clients
	c.h2Clients = nil
	h3List := c.h3Managers
	c.h3Managers = nil
	c.carrierMu.Unlock()

	for _, cli := range h2List {
		cli.close()
	}
	for _, manager := range h3List {
		manager.close()
	}
}

func portOf(address string) string {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return "443"
	}
	return port
}

func signRequest(request *http.Request, psk []byte, path, target, mode string) error {
	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set(HeaderMode, mode)
	request.Header.Set(HeaderTarget, target)
	request.Header.Set(HeaderTimestamp, timestamp)
	request.Header.Set(HeaderNonce, nonce)
	request.Header.Set(HeaderSignature, auth.Signature(psk, mode, request.Method, path, target, timestamp, nonce))
	return nil
}

type domainUDPAddr string

func (domainUDPAddr) Network() string  { return "udp" }
func (a domainUDPAddr) String() string { return string(a) }

// parseUDPAddr preserves domain metadata without inventing 0.0.0.0 or invoking
// the host's DNS resolver. Datagram codecs have already validated the address.
func parseUDPAddr(addrStr string) net.Addr {
	if ap, err := netip.ParseAddrPort(addrStr); err == nil {
		return net.UDPAddrFromAddrPort(ap)
	}
	host, portStr, err := net.SplitHostPort(addrStr)
	if err == nil {
		if port, err := strconv.Atoi(portStr); err == nil {
			if ip := net.ParseIP(host); ip != nil {
				return &net.UDPAddr{IP: ip, Port: port}
			}
			return domainUDPAddr(addrStr)
		}
	}
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

// resolveUDP resolves an address string into *net.UDPAddr.
// It checks literal IP first to avoid unnecessary DNS calls, invokes the custom resolver if supplied,
// and falls back to net.Resolver to ensure Go's net.DefaultResolver is not directly relied upon.
func resolveUDP(ctx context.Context, addrStr string, fn func(context.Context, string, string) (*net.UDPAddr, error)) (*net.UDPAddr, error) {
	if ap, err := netip.ParseAddrPort(addrStr); err == nil {
		return net.UDPAddrFromAddrPort(ap), nil
	}
	host, portStr, err := net.SplitHostPort(addrStr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}
	if fn != nil {
		return fn(ctx, "udp", addrStr)
	}
	var r net.Resolver
	ips, err := r.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("no IP resolved")
	}
	return &net.UDPAddr{IP: ips[0], Port: port}, nil
}
