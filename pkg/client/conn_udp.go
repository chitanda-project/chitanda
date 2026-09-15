package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/violetaini/chitanda/internal/frame"
	"github.com/violetaini/chitanda/internal/quicconfig"
	"github.com/violetaini/chitanda/internal/sessioncache"
)

type h3Connection struct {
	quic  *quic.Conn
	h3    *http3.ClientConn
	pconn net.PacketConn
}

type h3TransportManager struct {
	mu            sync.Mutex
	server        string
	serverName    string
	rootURL       string
	requestURL    string
	path          string
	psk           []byte
	tlsConfig     *tls.Config
	quicConfig    *quic.Config
	transport     *http3.Transport
	sessionCache  *sessioncache.Cache
	activeStreams atomic.Int64
	listenPacket  func(ctx context.Context, network, addr string) (net.PacketConn, error)
	resolveUDP    func(ctx context.Context, network, addr string) (*net.UDPAddr, error)

	// Separate physical connections for TCP and UDP
	currentTCP *h3Connection
	currentUDP *h3Connection
}

func newH3TransportManager(
	server, serverName, rootURL, requestURL, path string,
	psk []byte,
	sessionCache *sessioncache.Cache,
	initialPacketSize uint16,
	insecureSkipVerify bool,
	listenPacket func(ctx context.Context, network, addr string) (net.PacketConn, error),
	resolveUDPFn func(ctx context.Context, network, addr string) (*net.UDPAddr, error),
) *h3TransportManager {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         serverName,
		InsecureSkipVerify: insecureSkipVerify,
		NextProtos:         []string{http3.NextProtoH3},
	}
	if sessionCache != nil {
		tlsConfig.ClientSessionCache = sessionCache
	}
	return &h3TransportManager{
		server:       server,
		serverName:   serverName,
		rootURL:      rootURL,
		requestURL:   requestURL,
		path:         path,
		psk:          psk,
		tlsConfig:    tlsConfig,
		quicConfig:   quicconfig.Client(initialPacketSize),
		transport:    &http3.Transport{EnableDatagrams: true, DisableCompression: true},
		sessionCache: sessionCache,
		listenPacket: listenPacket,
		resolveUDP:   resolveUDPFn,
	}
}

func (m *h3TransportManager) ensureConnection(ctx context.Context, current **h3Connection) (*h3Connection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if *current != nil && (*current).quic.Context().Err() == nil {
		return *current, nil
	}
	if *current != nil {
		oldConn := *current
		_ = oldConn.quic.CloseWithError(0, "replaced")
		if oldConn.pconn != nil {
			_ = oldConn.pconn.Close()
		}
		*current = nil
	}
	udpAddr, err := resolveUDP(ctx, m.server, m.resolveUDP)
	if err != nil {
		return nil, err
	}
	var pconn net.PacketConn
	if m.listenPacket != nil {
		pconn, err = m.listenPacket(ctx, "udp", ":0")
	} else {
		pconn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	}
	if err != nil {
		return nil, err
	}
	if uc, ok := pconn.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(8 << 20)
		_ = uc.SetWriteBuffer(8 << 20)
	}

	quicConn, err := quic.DialEarly(ctx, pconn, udpAddr, m.tlsConfig.Clone(), m.quicConfig.Clone())
	if err != nil {
		_ = pconn.Close()
		return nil, err
	}
	*current = &h3Connection{quic: quicConn, h3: m.transport.NewClientConn(quicConn), pconn: pconn}
	return *current, nil
}

func (m *h3TransportManager) ensureTCP(ctx context.Context) (*h3Connection, error) {
	return m.ensureConnection(ctx, &m.currentTCP)
}

func (m *h3TransportManager) ensureUDP(ctx context.Context) (*h3Connection, error) {
	return m.ensureConnection(ctx, &m.currentUDP)
}

func (m *h3TransportManager) invalidate(c *h3Connection) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.currentTCP == c {
		m.currentTCP = nil
		_ = c.quic.CloseWithError(0, "reconnect")
		if c.pconn != nil {
			_ = c.pconn.Close()
		}
	}
	if m.currentUDP == c {
		m.currentUDP = nil
		_ = c.quic.CloseWithError(0, "reconnect")
		if c.pconn != nil {
			_ = c.pconn.Close()
		}
	}
}

func (m *h3TransportManager) dialH3TCP(ctx context.Context, target string) (net.Conn, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := m.dialH3TCPOnce(ctx, target)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if errors.Is(err, quic.Err0RTTRejected) && m.sessionCache != nil {
			_ = m.sessionCache.Clear()
		}
		if attempt == 0 {
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			}
		}
	}
	return nil, fmt.Errorf("H3 TCP dial failed: %w", lastErr)
}

func (m *h3TransportManager) dialH3TCPOnce(ctx context.Context, target string) (net.Conn, error) {
	h3Conn, err := m.ensureTCP(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := h3Conn.h3.OpenRequestStream(ctx)
	if err != nil {
		if h3Conn.quic.Context().Err() != nil {
			m.invalidate(h3Conn)
		}
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, m.requestURL, nil)
	if err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}
	if err := signRequest(request, m.psk, m.path, target, ModeTCPv2); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}
	if err := stream.SendRequestHeader(request); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		if h3Conn.quic.Context().Err() != nil {
			m.invalidate(h3Conn)
		}
		return nil, err
	}

	type respResult struct {
		resp *http.Response
		err  error
	}
	respCh := make(chan respResult, 1)
	go func() {
		r, err := stream.ReadResponse()
		respCh <- respResult{resp: r, err: err}
	}()

	var response *http.Response
	select {
	case <-ctx.Done():
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, ctx.Err()
	case res := <-respCh:
		if res.err != nil {
			stream.CancelRead(0)
			stream.CancelWrite(0)
			if h3Conn.quic.Context().Err() != nil {
				m.invalidate(h3Conn)
			}
			return nil, res.err
		}
		response = res.resp
	}

	if response.StatusCode != http.StatusOK || response.Header.Get(HeaderSessionOK) != "1" {
		_ = response.Body.Close()
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, fmt.Errorf("server rejected H3 TCP session with status %d", response.StatusCode)
	}

	return newRawH3Conn(target, stream, m), nil
}

func (m *h3TransportManager) createPacketConn(ctx context.Context) (net.PacketConn, error) {
	for attempt := 0; attempt < 2; attempt++ {
		pconn, err := m.createPacketConnOnce(ctx)
		if err == nil {
			return pconn, nil
		}
		if errors.Is(err, quic.Err0RTTRejected) && m.sessionCache != nil {
			_ = m.sessionCache.Clear()
		}
		if attempt == 0 {
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			}
		}
	}
	return nil, errors.New("establish H3 UDP packet connection failed")
}

func (m *h3TransportManager) createPacketConnOnce(ctx context.Context) (net.PacketConn, error) {
	h3Conn, err := m.ensureUDP(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := h3Conn.h3.OpenRequestStream(ctx)
	if err != nil {
		if h3Conn.quic.Context().Err() != nil {
			m.invalidate(h3Conn)
		}
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodConnect, m.requestURL, nil)
	if err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}
	request.Proto = "connect-udp"
	if err := signRequest(request, m.psk, m.path, UDPAssociationTarget, ModeUDPv2); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}
	if err := stream.SendRequestHeader(request); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		if h3Conn.quic.Context().Err() != nil {
			m.invalidate(h3Conn)
		}
		return nil, err
	}

	type respResult struct {
		resp *http.Response
		err  error
	}
	respCh := make(chan respResult, 1)
	go func() {
		r, err := stream.ReadResponse()
		respCh <- respResult{resp: r, err: err}
	}()

	var response *http.Response
	select {
	case <-ctx.Done():
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, ctx.Err()
	case res := <-respCh:
		if res.err != nil {
			stream.CancelRead(0)
			stream.CancelWrite(0)
			if h3Conn.quic.Context().Err() != nil {
				m.invalidate(h3Conn)
			}
			return nil, res.err
		}
		response = res.resp
	}

	if response.StatusCode != http.StatusOK || response.Header.Get(HeaderSessionOK) != "1" {
		_ = response.Body.Close()
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, fmt.Errorf("server rejected UDP association: status=%d", response.StatusCode)
	}

	pconnCtx, pconnCancel := context.WithCancel(context.Background())
	return &quicPacketConn{
		stream:  stream,
		ctx:     pconnCtx,
		cancel:  pconnCancel,
		manager: m,
	}, nil
}

func (m *h3TransportManager) close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.currentTCP != nil {
		_ = m.currentTCP.quic.CloseWithError(0, "shutdown")
		if m.currentTCP.pconn != nil {
			_ = m.currentTCP.pconn.Close()
		}
		m.currentTCP = nil
	}
	if m.currentUDP != nil {
		_ = m.currentUDP.quic.CloseWithError(0, "shutdown")
		if m.currentUDP.pconn != nil {
			_ = m.currentUDP.pconn.Close()
		}
		m.currentUDP = nil
	}
	_ = m.transport.Close()
}

// rawH3Conn wraps an HTTP/3 request stream directly into a net.Conn.
type rawH3Conn struct {
	target  string
	stream  *http3.RequestStream
	manager *h3TransportManager
	closed  bool
	mu      sync.Mutex
}

func newRawH3Conn(target string, stream *http3.RequestStream, manager *h3TransportManager) *rawH3Conn {
	return &rawH3Conn{
		target:  target,
		stream:  stream,
		manager: manager,
	}
}

func (c *rawH3Conn) Read(b []byte) (int, error) {
	return c.stream.Read(b)
}

func (c *rawH3Conn) Write(b []byte) (int, error) {
	return c.stream.Write(b)
}

func (c *rawH3Conn) CloseWrite() error {
	// Close() sends QUIC FIN (graceful half-close).
	// CancelWrite() would send RESET_STREAM causing peer data loss.
	return c.stream.Close()
}

func (c *rawH3Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	if c.manager != nil {
		c.manager.activeStreams.Add(-1)
	}
	c.stream.CancelRead(0)
	c.stream.CancelWrite(0)
	return c.stream.Close()
}

func (c *rawH3Conn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (c *rawH3Conn) RemoteAddr() net.Addr {
	host, portStr, err := net.SplitHostPort(c.target)
	if err == nil {
		var port int
		_, _ = fmt.Sscanf(portStr, "%d", &port)
		return &net.TCPAddr{IP: net.ParseIP(host), Port: port}
	}
	return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}
}

func (c *rawH3Conn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *rawH3Conn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *rawH3Conn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

// quicPacketConn wraps HTTP/3 extended CONNECT-UDP + Datagrams into standard net.PacketConn.
type quicPacketConn struct {
	stream        *http3.RequestStream
	ctx           context.Context
	cancel        context.CancelFunc
	manager       *h3TransportManager
	sequence      atomic.Uint64
	readMu        sync.Mutex
	replay        frame.ReplayWindow
	decoder       frame.DatagramCache
	mu            sync.Mutex
	closed        bool
	readDeadline  time.Time
	writeDeadline time.Time
	readCancel    context.CancelFunc
}

func (c *quicPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		if c.ctx.Err() != nil {
			return 0, nil, c.ctx.Err()
		}
		c.mu.Lock()
		readDl := c.readDeadline
		if !readDl.IsZero() && time.Now().After(readDl) {
			c.mu.Unlock()
			return 0, nil, context.DeadlineExceeded
		}
		recvCtx, cancel := context.WithCancel(c.ctx)
		if !readDl.IsZero() {
			recvCtx, cancel = context.WithDeadline(c.ctx, readDl)
		}
		c.readCancel = cancel
		c.mu.Unlock()

		rawPacket, err := c.stream.ReceiveDatagram(recvCtx)
		cancel()

		c.mu.Lock()
		c.readCancel = nil
		currentDl := c.readDeadline
		c.mu.Unlock()

		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				if c.ctx.Err() != nil {
					return 0, nil, c.ctx.Err()
				}
				if !currentDl.IsZero() && time.Now().After(currentDl) {
					return 0, nil, context.DeadlineExceeded
				}
				// Deadline updated dynamically, loop and try with new deadline
				continue
			}
			return 0, nil, err
		}

		c.readMu.Lock()
		seq, address, payload, decodeErr := c.decoder.Decode(rawPacket)
		accepted := decodeErr == nil && c.replay.Accept(seq)
		c.readMu.Unlock()
		if !accepted {
			continue
		}

		n = copy(p, payload)
		udpAddr := parseUDPAddr(address)
		return n, udpAddr, nil
	}
}

func (c *quicPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, errors.New("use of closed network connection")
	}
	if !c.writeDeadline.IsZero() && time.Now().After(c.writeDeadline) {
		c.mu.Unlock()
		return 0, context.DeadlineExceeded
	}
	c.mu.Unlock()

	address := addr.String()
	packet, err := frame.EncodeDatagram(c.sequence.Add(1), address, p)
	if err != nil {
		return 0, err
	}
	if err := c.stream.SendDatagram(packet); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *quicPacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.manager != nil {
		c.manager.activeStreams.Add(-1)
	}
	c.cancel()
	c.stream.CancelRead(0)
	c.stream.CancelWrite(0)
	return c.stream.Close()
}

func (c *quicPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (c *quicPacketConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *quicPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	cancel := c.readCancel
	c.readCancel = nil
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	return nil
}

func (c *quicPacketConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return nil
}
