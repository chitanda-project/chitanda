package chitanda

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/violetaini/chitanda/pkg/auth"
	"github.com/violetaini/chitanda/pkg/server"

	"golang.org/x/net/http2"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/udp"
)

// InboundHandler implements proxy.Inbound for Chitanda protocol in Xray
type InboundHandler struct {
	config       *InboundConfig
	server       *server.Server
	streamServer *server.StreamServer
	h3Server     *http3.Server
	vconn        *virtualPacketConn
	plainCodec   *server.PlainUDPCodec
	replays      *auth.ReplayCache
	udpReplays   sync.Map // uint64(sessionID) -> *server.UDPReplayWindow
	dispatcher   routing.Dispatcher
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex
}

func NewInboundHandler(ctx context.Context, config *InboundConfig) (*InboundHandler, error) {
	v := core.MustFromContext(ctx)
	dispatcher := v.GetFeature(routing.DispatcherType()).(routing.Dispatcher)

	var replays *auth.ReplayCache
	var err error
	if config.ReplayFile != "" {
		replays, err = auth.OpenReplayCache(config.ReplayFile, time.Now())
		if err != nil {
			return nil, fmt.Errorf("open replay cache: %w", err)
		}
	} else {
		replays = auth.NewReplayCache()
	}

	var fbHandler http.Handler
	if config.Fallback != "" {
		fb, err := server.NewFallback(config.Fallback, config.StrictSni)
		if err != nil {
			_ = replays.Close()
			return nil, fmt.Errorf("init fallback handler: %w", err)
		}
		fbHandler = fb
	}

	dialTargetFn := func(ctx context.Context, network, address string) (net.Conn, error) {
		if network == "" {
			network = "tcp"
		}
		dest, err := xnet.ParseDestination(network + ":" + address)
		if err != nil {
			return nil, err
		}

		inbound := session.InboundFromContext(ctx)
		if inbound == nil {
			inbound = &session.Inbound{
				Tag: "chitanda-inbound",
			}
			ctx = session.ContextWithInbound(ctx, inbound)
		} else if inbound.Tag == "" {
			inbound.Tag = "chitanda-inbound"
		}

		link, err := dispatcher.Dispatch(ctx, dest)
		if err != nil {
			return nil, err
		}

		return newPipeConn(link.Reader, link.Writer), nil
	}

	srv := server.NewServer(config.Path, []byte(config.Psk), replays, fbHandler, 1024)
	srv.SetDialTargetForTest(func(ctx context.Context, address string) (net.Conn, error) {
		return dialTargetFn(ctx, "tcp", address)
	})

	streamSrv := server.NewStreamServer([]byte(config.Psk), config.ServerId, replays, func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialTargetFn(ctx, network, address)
	})

	var plainCodec *server.PlainUDPCodec
	if len(config.Psk) >= 32 {
		codec, err := server.NewPlainUDPCodec([]byte(config.Psk))
		if err != nil {
			_ = replays.Close()
			return nil, fmt.Errorf("init plain-udp codec: %w", err)
		}
		plainCodec = codec
	}

	var h3Server *http3.Server
	var vconn *virtualPacketConn
	if config.Transport != "stream" && config.Transport != "h1" && config.Transport != "plain-h1" {
		tlsConfig, err := buildServerTLSConfig(config)
		if err != nil {
			_ = replays.Close()
			return nil, fmt.Errorf("build h3 tls config: %w", err)
		}
		vconn = newVirtualPacketConn()
		h3Server = server.NewHTTP3Server(srv, tlsConfig, 0)
		go func() {
			_ = h3Server.Serve(vconn)
		}()
	}

	inCtx, inCancel := context.WithCancel(context.Background())
	h := &InboundHandler{
		config:       config,
		server:       srv,
		streamServer: streamSrv,
		h3Server:     h3Server,
		vconn:        vconn,
		plainCodec:   plainCodec,
		replays:      replays,
		dispatcher:   dispatcher,
		ctx:          inCtx,
		cancel:       inCancel,
	}

	return h, nil
}

func (h *InboundHandler) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP, xnet.Network_UDP}
}

type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.br.Read(p)
}

type singleListener struct {
	conn   net.Conn
	once   sync.Once
	done   chan struct{}
	closed atomic.Bool
}

func (l *singleListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() {
		c = &closeNotifyConn{
			Conn: l.conn,
			onClose: func() {
				_ = l.Close()
			},
		}
	})
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleListener) Close() error {
	if l.closed.CompareAndSwap(false, true) {
		close(l.done)
		_ = l.conn.Close()
	}
	return nil
}

func (l *singleListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

type closeNotifyConn struct {
	net.Conn
	once    sync.Once
	onClose func()
}

func (c *closeNotifyConn) Close() error {
	c.once.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})
	return c.Conn.Close()
}

func (h *InboundHandler) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	if network == xnet.Network_UDP {
		return h.handleUDP(ctx, conn, dispatcher)
	}
	if network != xnet.Network_TCP {
		return nil
	}
	defer conn.Close()

	if h.config.Transport == "stream" {
		h.streamServer.HandleConnContext(ctx, conn)
		return nil
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(conn)
	prefix, err := br.Peek(4)
	if err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Time{})

	bconn := &bufferedConn{Conn: conn, br: br}

	if string(prefix) == "PRI " {
		// HTTP/2 Connection Preface
		h2Server := &http2.Server{}
		h2Server.ServeConn(bconn, &http2.ServeConnOpts{
			Handler: h.server,
			Context: ctx,
		})
		return nil
	}

	// HTTP/1.x
	sl := &singleListener{conn: bconn, done: make(chan struct{})}
	httpServer := &http.Server{
		Handler: h.server,
	}

	go func() {
		select {
		case <-ctx.Done():
			_ = sl.Close()
		case <-h.ctx.Done():
			_ = sl.Close()
		case <-sl.done:
		}
	}()

	return httpServer.Serve(sl)
}

func (h *InboundHandler) handleUDP(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher) error {
	defer conn.Close()
	if h.plainCodec == nil && h.h3Server == nil {
		return fmt.Errorf("neither chitanda plain-udp nor h3 initialized")
	}

	key := conn.RemoteAddr().String()
	if h.vconn != nil {
		h.vconn.registerConn(key, conn)
		defer h.vconn.unregisterConn(key, conn)
	}

	var targetSessions sync.Map // string(targetAddr) -> uint64(sessionID)
	var lastSessionID atomic.Uint64

	var udpServer *udp.Dispatcher
	if h.plainCodec != nil {
		udpServer = udp.NewDispatcher(dispatcher, func(ctx context.Context, packet *udp_proto.Packet) {
			payload := packet.Payload
			if payload == nil {
				return
			}
			defer payload.Release()

			srcAddr := packet.Source.NetAddr()
			sessionID := lastSessionID.Load()
			if v, ok := targetSessions.Load(srcAddr); ok {
				sessionID = v.(uint64)
			}

			encoded, err := h.plainCodec.EncodeServerPacket(sessionID, srcAddr, payload.Bytes(), time.Now())
			if err != nil {
				return
			}
			_, _ = conn.Write(encoded)
		})
		defer udpServer.RemoveRay()
	}

	reader := buf.NewPacketReader(conn)
	for {
		mpayload, err := reader.ReadMultiBuffer()
		if err != nil {
			return err
		}

		for _, payload := range mpayload {
			data := payload.Bytes()
			if len(data) == 0 {
				payload.Release()
				continue
			}

			// If transport is strictly h3, route directly to H3
			if h.config.Transport == "h3" {
				if h.vconn != nil {
					h.vconn.feed(data, conn.RemoteAddr())
				}
				payload.Release()
				continue
			}

			// Try Plain-UDP decode first if codec initialized
			if h.plainCodec != nil {
				sessionID, targetAddr, rawData, _, seq, err := h.plainCodec.DecodeClientPacket(data, time.Now())
				if err == nil {
					var replay *server.UDPReplayWindow
					if val, ok := h.udpReplays.Load(sessionID); ok {
						replay = val.(*server.UDPReplayWindow)
					} else {
						actual, _ := h.udpReplays.LoadOrStore(sessionID, server.NewUDPReplayWindow())
						replay = actual.(*server.UDPReplayWindow)
					}

					if !replay.Accept(seq) {
						payload.Release()
						continue // drop replayed packet across any connection/association!
					}

					lastSessionID.Store(sessionID)
					targetSessions.Store(targetAddr, sessionID)

					dest, err := xnet.ParseDestination("udp:" + targetAddr)
					if err != nil {
						payload.Release()
						continue
					}

					var packetCtx context.Context
					inbound := session.InboundFromContext(ctx)
					if inbound == nil {
						inbound = &session.Inbound{
							Tag: "chitanda-inbound",
						}
						packetCtx = session.ContextWithInbound(ctx, inbound)
					} else {
						if inbound.Tag == "" {
							inbound.Tag = "chitanda-inbound"
						}
						packetCtx = ctx
					}

					b := buf.New()
					_, _ = b.Write(rawData)
					b.UDP = &dest
					payload.Release()
					if udpServer != nil {
						udpServer.Dispatch(packetCtx, dest, b)
					}
					continue
				}
			}

			// If not Plain-UDP, check if H3 is enabled and if packet looks like QUIC
			if h.vconn != nil && isQUICPacket(data) {
				h.vconn.feed(data, conn.RemoteAddr())
				payload.Release()
				continue
			}

			payload.Release()
		}
	}
}

func (h *InboundHandler) Close() error {
	h.cancel()
	if h.h3Server != nil {
		_ = h.h3Server.Close()
	}
	if h.vconn != nil {
		_ = h.vconn.Close()
	}
	if h.streamServer != nil {
		_ = h.streamServer.Close()
	}
	if h.replays != nil {
		_ = h.replays.Close()
	}
	return nil
}

type pipeConn struct {
	reader      *buf.BufferedReader
	writer      buf.Writer
	readCloser  interface{}
	writeCloser interface{}
	readTimer   *time.Timer
	timerMu     sync.Mutex
}

func newPipeConn(reader buf.Reader, writer buf.Writer) *pipeConn {
	return &pipeConn{
		reader:      &buf.BufferedReader{Reader: reader},
		writer:      writer,
		readCloser:  reader,
		writeCloser: writer,
	}
}

func (c *pipeConn) Read(b []byte) (n int, err error) {
	return c.reader.Read(b)
}

func (c *pipeConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	// Older Xray BufferedWriter.Write returns ErrBufferFull for inputs larger
	// than buf.Size (8 KiB), aborting valid RawStream frames of up to 32 KiB.
	// MergeBytes copies into owned buffers; WriteMultiBuffer transfers their
	// ownership to the dispatcher, including on error. Do not retain b or
	// release those buffers here: the caller may immediately reuse b.
	if err := c.writer.WriteMultiBuffer(buf.MergeBytes(nil, b)); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *pipeConn) Close() error {
	c.timerMu.Lock()
	if c.readTimer != nil {
		c.readTimer.Stop()
		c.readTimer = nil
	}
	c.timerMu.Unlock()

	var err1, err2 error
	if c.writeCloser != nil {
		err1 = common.Close(c.writeCloser)
	}
	if c.readCloser != nil {
		_ = common.Interrupt(c.readCloser)
		err2 = common.Close(c.readCloser)
	}
	if err1 != nil {
		return err1
	}
	return err2
}

func (c *pipeConn) CloseWrite() error {
	if c.writeCloser != nil {
		return common.Close(c.writeCloser)
	}
	return nil
}

func (c *pipeConn) CloseRead() error {
	c.timerMu.Lock()
	if c.readTimer != nil {
		c.readTimer.Stop()
		c.readTimer = nil
	}
	c.timerMu.Unlock()

	if c.readCloser != nil {
		_ = common.Interrupt(c.readCloser)
		return common.Close(c.readCloser)
	}
	return nil
}

func (c *pipeConn) LocalAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }
func (c *pipeConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }

func (c *pipeConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *pipeConn) SetReadDeadline(t time.Time) error {
	c.timerMu.Lock()
	defer c.timerMu.Unlock()

	if c.readTimer != nil {
		c.readTimer.Stop()
		c.readTimer = nil
	}

	if t.IsZero() {
		return nil
	}

	d := time.Until(t)
	if d <= 0 {
		if c.readCloser != nil {
			_ = common.Interrupt(c.readCloser)
		}
		return nil
	}

	c.readTimer = time.AfterFunc(d, func() {
		if c.readCloser != nil {
			_ = common.Interrupt(c.readCloser)
		}
	})
	return nil
}

func (c *pipeConn) SetWriteDeadline(t time.Time) error { return nil }

func isQUICPacket(data []byte) bool {
	if len(data) < 20 {
		return false
	}
	// Fixed bit (bit 6 of byte 0) must be 1 in QUIC (RFC 9000 section 17)
	if (data[0] & 0x40) == 0 {
		return false
	}
	return true
}

func buildServerTLSConfig(config *InboundConfig) (*tls.Config, error) {
	var cert tls.Certificate
	var err error
	if config.CertFile != "" && config.KeyFile != "" {
		cert, err = tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load x509 keypair: %w", err)
		}
	} else {
		cert, err = generateSelfSignedCert(config.StrictSni)
		if err != nil {
			return nil, fmt.Errorf("generate self-signed cert: %w", err)
		}
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{http3.NextProtoH3},
	}
	if len(config.Psk) >= 32 {
		var key [32]byte
		copy(key[:], config.Psk[:32])
		tlsConfig.SetSessionTicketKeys([][32]byte{key})
	}
	if config.StrictSni != "" {
		tlsConfig.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			if !strings.EqualFold(chi.ServerName, config.StrictSni) {
				return nil, fmt.Errorf("strict SNI mismatch: got %q, want %q", chi.ServerName, config.StrictSni)
			}
			return nil, nil
		}
	}
	return tlsConfig, nil
}

func generateSelfSignedCert(serverName string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"Chitanda Edge Gateway"},
			CommonName:   serverName,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if serverName != "" {
		if ip := net.ParseIP(serverName); ip != nil {
			template.IPAddresses = []net.IP{ip}
		} else {
			template.DNSNames = []string{serverName, "localhost"}
		}
	} else {
		template.DNSNames = []string{"localhost"}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

type packetItem struct {
	data []byte
	addr net.Addr
}

type virtualPacketConn struct {
	recvCh      chan *packetItem
	closeCh     chan struct{}
	closed      atomic.Bool
	localAddr   net.Addr

	mu          sync.RWMutex
	writers     map[string]stat.Connection

	readTimer   *time.Timer
	timerMu     sync.Mutex
	readExpired atomic.Bool
}

func newVirtualPacketConn() *virtualPacketConn {
	return &virtualPacketConn{
		recvCh:    make(chan *packetItem, 2048),
		closeCh:   make(chan struct{}),
		localAddr: &net.UDPAddr{IP: net.IPv4zero, Port: 0},
		writers:   make(map[string]stat.Connection),
	}
}

func (c *virtualPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	if c.readExpired.Load() {
		return 0, nil, os.ErrDeadlineExceeded
	}
	select {
	case pkt, ok := <-c.recvCh:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(p, pkt.data)
		return n, pkt.addr, nil
	case <-c.closeCh:
		return 0, nil, net.ErrClosed
	}
}

func (c *virtualPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.mu.RLock()
	conn, ok := c.writers[addr.String()]
	c.mu.RUnlock()
	if !ok || conn == nil {
		return 0, fmt.Errorf("no active connection for %s", addr.String())
	}
	return conn.Write(p)
}

func (c *virtualPacketConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.closeCh)
		c.timerMu.Lock()
		if c.readTimer != nil {
			c.readTimer.Stop()
			c.readTimer = nil
		}
		c.timerMu.Unlock()
	}
	return nil
}

func (c *virtualPacketConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *virtualPacketConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *virtualPacketConn) SetReadDeadline(t time.Time) error {
	c.timerMu.Lock()
	defer c.timerMu.Unlock()

	if c.readTimer != nil {
		c.readTimer.Stop()
		c.readTimer = nil
	}
	c.readExpired.Store(false)

	if t.IsZero() {
		return nil
	}

	d := time.Until(t)
	if d <= 0 {
		c.readExpired.Store(true)
		return nil
	}

	c.readTimer = time.AfterFunc(d, func() {
		c.readExpired.Store(true)
	})
	return nil
}

func (c *virtualPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *virtualPacketConn) feed(data []byte, addr net.Addr) {
	if c.closed.Load() {
		return
	}
	buf := make([]byte, len(data))
	copy(buf, data)
	select {
	case c.recvCh <- &packetItem{data: buf, addr: addr}:
	default:
	}
}

func (c *virtualPacketConn) registerConn(key string, conn stat.Connection) {
	c.mu.Lock()
	c.writers[key] = conn
	c.mu.Unlock()
}

func (c *virtualPacketConn) unregisterConn(key string, conn stat.Connection) {
	c.mu.Lock()
	if c.writers[key] == conn {
		delete(c.writers, key)
	}
	c.mu.Unlock()
}

func init() {
	common.Must(common.RegisterConfig((*InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewInboundHandler(ctx, config.(*InboundConfig))
	}))
}
