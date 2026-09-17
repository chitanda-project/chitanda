package chitanda

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/violetaini/chitanda/pkg/auth"
	"github.com/violetaini/chitanda/pkg/connio"
	"github.com/violetaini/chitanda/pkg/server"

	"golang.org/x/net/http2"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
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
	udpReplays   udpReplayRegistry
	dispatcher   routing.Dispatcher
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex
	httpSlots    chan struct{}
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
			copyInbound := *inbound
			copyInbound.Tag = "chitanda-inbound"
			ctx = session.ContextWithInbound(ctx, &copyInbound)
		}

		link, err := dispatcher.Dispatch(requestContext(ctx), dest)
		if err != nil {
			return nil, err
		}

		if network == "udp" {
			return newPacketLinkConn(link.Reader, link.Writer, packetAddress(address)), nil
		}
		return newPipeConn(link.Reader, link.Writer), nil
	}

	srv := server.NewServer(config.Path, []byte(config.Psk), replays, fbHandler, 1024)
	srv.SetDialTargetForTest(func(ctx context.Context, address string) (net.Conn, error) {
		return dialTargetFn(ctx, "tcp", address)
	})
	srv.SetDialUDP(func(ctx context.Context, address string) (net.Conn, error) {
		return dialTargetFn(ctx, "udp", address)
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
		h3Server.ConnContext = func(ctx context.Context, conn *quic.Conn) context.Context {
			return vconn.connectionContext(ctx, conn.RemoteAddr())
		}
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
		httpSlots:    make(chan struct{}, 1024),
	}
	go h.udpReplays.run(inCtx)

	return h, nil
}

func (h *InboundHandler) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP, xnet.Network_UDP}
}

// Requested by the injected Xray UDP worker; other inbound protocols keep
// their upstream buffer size. This includes Plain-UDP encapsulation overhead.
func (h *InboundHandler) UDPPacketBufferSize() int32 { return 65535 }

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
	stopCaller := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCaller()
	stopHandler := context.AfterFunc(h.ctx, func() { _ = conn.Close() })
	defer stopHandler()

	if h.config.Transport == "stream" {
		h.streamServer.HandleConnContext(ctx, conn)
		return nil
	}
	// Bound non-RawStream carrier processing, including incomplete unauthenticated
	// HTTP requests. Authenticated carriers release this slot on connection close.
	if h.httpSlots != nil {
		select {
		case h.httpSlots <- struct{}{}:
			defer func() { <-h.httpSlots }()
		default:
			return fmt.Errorf("chitanda: HTTP carrier limit reached")
		}
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
		Handler:           h.server,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ReadHeaderTimeout: 2 * time.Second,
		MaxHeaderBytes:    16 << 10,
		IdleTimeout:       30 * time.Second,
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
	stopCaller := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCaller()
	if h.ctx != nil {
		stopHandler := context.AfterFunc(h.ctx, func() { _ = conn.Close() })
		defer stopHandler()
	}
	if h.plainCodec == nil && h.h3Server == nil {
		return fmt.Errorf("neither chitanda plain-udp nor h3 initialized")
	}

	key := conn.RemoteAddr().String()
	if h.vconn != nil {
		h.vconn.registerConn(key, conn, ctx)
		defer h.vconn.unregisterConn(key, conn)
	}

	routes := newUDPRoutes(ctx, dispatcher, h.plainCodec, conn)
	defer routes.Close()

	reader := newFullPacketReader(conn)
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
					if !h.udpReplays.accept(sessionID, seq, time.Now()) {
						payload.Release()
						continue // drop replayed packet across any connection/association!
					}

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
							copyInbound := *inbound
							copyInbound.Tag = "chitanda-inbound"
							packetCtx = session.ContextWithInbound(ctx, &copyInbound)
						} else {
							packetCtx = ctx
						}
					}

					payload.Release()
					_ = routes.Write(packetCtx, sessionID, dest, rawData)
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
	reader     *buf.BufferedReader
	readCloser interface{}
	reads      *connio.Reader
	writes     *pipeWriteQueue
}

func newPipeConn(reader buf.Reader, writer buf.Writer) *pipeConn {
	c := &pipeConn{
		readCloser: reader,
		writes:     newPipeWriteQueue(writer),
	}
	if reader != nil {
		c.reader = &buf.BufferedReader{Reader: reader}
		c.reads = connio.NewReader(func() ([]byte, net.Addr, error) {
			b := make([]byte, 32<<10)
			n, err := c.reader.Read(b)
			return b[:n], nil, err
		}, func() error { _ = common.Interrupt(reader); return common.Close(reader) })
	}
	return c
}

func (c *pipeConn) Read(b []byte) (n int, err error) {
	if c.reads == nil {
		return 0, io.EOF
	}
	return c.reads.Read(b)
}

func (c *pipeConn) Write(b []byte) (n int, err error) {
	return c.writes.Write(b)
}

func (c *pipeConn) Close() error {
	err1 := c.writes.Close()
	var err2 error
	if c.reads != nil {
		err2 = c.reads.Close()
	} else if c.readCloser != nil {
		_ = common.Interrupt(c.readCloser)
		err2 = common.Close(c.readCloser)
	}
	if err1 != nil {
		return err1
	}
	return err2
}

func (c *pipeConn) CloseWrite() error {
	return c.writes.CloseWrite()
}

func (c *pipeConn) CloseRead() error {
	if c.reads != nil {
		return c.reads.Close()
	}
	if c.readCloser != nil {
		_ = common.Interrupt(c.readCloser)
		return common.Close(c.readCloser)
	}
	return nil
}

func (c *pipeConn) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }
func (c *pipeConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }

func (c *pipeConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *pipeConn) SetReadDeadline(t time.Time) error {
	if c.reads != nil {
		return c.reads.SetDeadline(t)
	}
	return nil
}

func (c *pipeConn) SetWriteDeadline(t time.Time) error {
	return c.writes.SetDeadline(t)
}

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
	if config.CertFile == "" || config.KeyFile == "" {
		return nil, fmt.Errorf("H3 requires cert_file and key_file (or an inherited streamSettings.tlsSettings file pair)")
	}
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load x509 keypair: %w", err)
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{http3.NextProtoH3},
	}
	// Go TLS generates independent server-only ticket keys and rotates them.
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

type packetItem struct {
	data []byte
	addr net.Addr
}

type virtualPacketConn struct {
	recvCh    chan *packetItem
	closeCh   chan struct{}
	closed    atomic.Bool
	localAddr net.Addr

	mu      sync.RWMutex
	writers map[string]stat.Connection

	deadlineMu      sync.Mutex
	readDeadline    time.Time
	deadlineChanged chan struct{}
	contexts        map[string]context.Context
	writeQueue      *connio.Writer
}

func newVirtualPacketConn() *virtualPacketConn {
	c := &virtualPacketConn{
		recvCh:          make(chan *packetItem, 2048),
		closeCh:         make(chan struct{}),
		localAddr:       &net.UDPAddr{IP: net.IPv4zero, Port: 0},
		writers:         make(map[string]stat.Connection),
		contexts:        make(map[string]context.Context),
		deadlineChanged: make(chan struct{}),
	}
	c.writeQueue = connio.NewWriter(func(p []byte, addr net.Addr) (int, error) {
		c.mu.RLock()
		conn := c.writers[addr.String()]
		c.mu.RUnlock()
		// A datagram accepted into the bounded send queue can be lost if its
		// association disappears. Do not poison other QUIC peers on that loss.
		if conn != nil {
			_, _ = conn.Write(p)
		}
		return len(p), nil
	}, nil, func() error {
		c.mu.RLock()
		connections := make([]stat.Connection, 0, len(c.writers))
		for _, conn := range c.writers {
			connections = append(connections, conn)
		}
		c.mu.RUnlock()
		for _, conn := range connections {
			_ = conn.Close()
		}
		return nil
	})
	return c
}

func (c *virtualPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		if c.closed.Load() {
			return 0, nil, net.ErrClosed
		}
		c.deadlineMu.Lock()
		dl, changed := c.readDeadline, c.deadlineChanged
		c.deadlineMu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !dl.IsZero() {
			if !time.Now().Before(dl) {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(dl))
			timeout = timer.C
		}
		select {
		case pkt := <-c.recvCh:
			if timer != nil {
				timer.Stop()
			}
			return copy(p, pkt.data), pkt.addr, nil
		case <-c.closeCh:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		case <-timeout:
			// Re-check under the next iteration in case the deadline was extended.
		}
	}
}

func (c *virtualPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if addr == nil {
		return 0, net.InvalidAddrError("nil UDP peer")
	}
	c.mu.RLock()
	conn, ok := c.writers[addr.String()]
	c.mu.RUnlock()
	if !ok || conn == nil {
		return 0, fmt.Errorf("no active connection for %s", addr.String())
	}
	return c.writeQueue.WritePacket(p, addr)
}

func (c *virtualPacketConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.closeCh)
	}
	_ = c.writeQueue.Close()
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
	c.deadlineMu.Lock()
	c.readDeadline = t
	close(c.deadlineChanged)
	c.deadlineChanged = make(chan struct{})
	c.deadlineMu.Unlock()
	return nil
}

func (c *virtualPacketConn) SetWriteDeadline(t time.Time) error {
	return c.writeQueue.SetDeadline(t)
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

func (c *virtualPacketConn) registerConn(key string, conn stat.Connection, contexts ...context.Context) {
	c.mu.Lock()
	c.writers[key] = conn
	if len(contexts) > 0 {
		c.contexts[key] = context.WithoutCancel(contexts[0])
	}
	c.mu.Unlock()
}

func (c *virtualPacketConn) unregisterConn(key string, conn stat.Connection) {
	c.mu.Lock()
	if c.writers[key] == conn {
		delete(c.writers, key)
		delete(c.contexts, key)
	}
	c.mu.Unlock()
}

type inboundValueContext struct {
	context.Context
	values context.Context
}

func (c inboundValueContext) Value(key any) any {
	if v := c.Context.Value(key); v != nil {
		return v
	}
	return c.values.Value(key)
}

func (c *virtualPacketConn) connectionContext(ctx context.Context, addr net.Addr) context.Context {
	c.mu.RLock()
	values := c.contexts[addr.String()]
	c.mu.RUnlock()
	if values == nil {
		return ctx
	}
	// Keep QUIC's lifetime but preserve the original Xray inbound tag, user and
	// routing metadata even when a short-lived UDP association is replaced.
	return inboundValueContext{Context: ctx, values: values}
}

func init() {
	common.Must(common.RegisterConfig((*InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewInboundHandler(ctx, config.(*InboundConfig))
	}))
}
