package server

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/violetaini/chitanda/internal/rawstream"
	"github.com/violetaini/chitanda/internal/target"
	"github.com/violetaini/chitanda/pkg/auth"
)

// StreamServer handles Chitanda RawStream (TCP) and Native PlainUDP connections.
// It is hardened for IEPL/transit environments with zero Web footprint (probes receive instant RST/close).
type StreamServer struct {
	psk          []byte
	users        []UserKey
	pskList      [][]byte
	matcher      *rawstream.PreparedClientHelloMatcher
	serverID     string
	dialTarget   func(ctx context.Context, network, address string) (net.Conn, error)
	listenersMu  sync.Mutex
	listeners    []net.Listener
	udpServer    *PlainUDPServer
	dialICMP     func(ctx context.Context, address string) (net.PacketConn, error)
	replays      *auth.ReplayCache
	closed       atomic.Bool
	wg           sync.WaitGroup
	maxConns     atomic.Int64
	activeConns  atomic.Int64
	handshakeSem chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewStreamServer creates a new StreamServer with a single PSK.
func NewStreamServer(psk []byte, serverID string, replays *auth.ReplayCache, dialTarget func(ctx context.Context, network, address string) (net.Conn, error)) *StreamServer {
	psk = append([]byte(nil), psk...)
	if dialTarget == nil {
		dialTarget = func(ctx context.Context, network, address string) (net.Conn, error) {
			return target.DialContext(ctx, address)
		}
	}
	if replays == nil {
		replays = auth.NewReplayCache()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &StreamServer{
		psk:          psk,
		serverID:     serverID,
		dialTarget:   dialTarget,
		replays:      replays,
		handshakeSem: make(chan struct{}, 512),
		ctx:          ctx,
		cancel:       cancel,
	}
	s.maxConns.Store(10000)
	if len(psk) > 0 {
		s.pskList = [][]byte{psk}
		s.users = []UserKey{{PSK: psk}}
	}
	return s
}

// NewStreamServerWithUsers creates a new StreamServer supporting multiple users.
func NewStreamServerWithUsers(users []UserKey, serverID string, replays *auth.ReplayCache, dialTarget func(ctx context.Context, network, address string) (net.Conn, error)) (*StreamServer, error) {
	if err := ValidateUserKeys(users); err != nil {
		return nil, err
	}
	if dialTarget == nil {
		dialTarget = func(ctx context.Context, network, address string) (net.Conn, error) {
			return target.DialContext(ctx, address)
		}
	}
	if replays == nil {
		replays = auth.NewReplayCache()
	}
	validUsers, pskList := copyUserKeys(users)
	matcher, err := rawstream.NewPreparedClientHelloMatcher(pskList, serverID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &StreamServer{
		users:        validUsers,
		pskList:      pskList,
		matcher:      matcher,
		serverID:     serverID,
		dialTarget:   dialTarget,
		replays:      replays,
		handshakeSem: make(chan struct{}, 512),
		ctx:          ctx,
		cancel:       cancel,
	}
	s.maxConns.Store(10000)
	if len(validUsers) == 1 {
		s.psk = validUsers[0].PSK
	}
	return s, nil
}

// SetMaxConns sets the maximum number of concurrent connections (for testing or configuration).
func (s *StreamServer) SetMaxConns(n int) {
	s.maxConns.Store(int64(n))
}

// Reserve before entering a handshake. Load/check followed by Add can admit
// several callers past the same limit under concurrent HandleConn/Serve use.
// Count sockets still entering the handshake, and roll back on every reject.
func (s *StreamServer) reserveConnection() bool {
	for {
		if s.closed.Load() {
			return false
		}
		active, limit := s.activeConns.Load(), s.maxConns.Load()
		if limit > 0 && active >= limit {
			return false
		}
		if s.activeConns.CompareAndSwap(active, active+1) {
			if s.closed.Load() {
				s.activeConns.Add(-1)
				return false
			}
			return true
		}
	}
}

// Register accepted work under the same lock that seals admission in Close.
// A positive WaitGroup.Add must not race a Wait starting at zero.
func (s *StreamServer) admitConnection() bool {
	s.listenersMu.Lock()
	defer s.listenersMu.Unlock()
	if !s.reserveConnection() {
		return false
	}
	select {
	case s.handshakeSem <- struct{}{}:
	default:
		s.activeConns.Add(-1)
		return false
	}
	s.wg.Add(1)
	return true
}

// SetHandshakeLimit sets the maximum number of concurrent pending handshakes.
func (s *StreamServer) SetHandshakeLimit(n int) {
	s.handshakeSem = make(chan struct{}, n)
}

// SetReplayCache sets an explicit ReplayCache instance (e.g. for persistent storage or tests).
func (s *StreamServer) SetReplayCache(cache *auth.ReplayCache) {
	if cache != nil {
		s.replays = cache
	}
}

// SetDialICMP sets the custom dialer used to listen/dial ICMP packets on the attached UDP server.
func (s *StreamServer) SetDialICMP(fn func(ctx context.Context, address string) (net.PacketConn, error)) {
	s.listenersMu.Lock()
	defer s.listenersMu.Unlock()
	s.dialICMP = fn
	if s.udpServer != nil {
		s.udpServer.SetDialICMP(fn)
	}
}

// AttachUDP binds a Native PlainUDP listener to this server and starts the UDP serve loop.
func (s *StreamServer) AttachUDP(udpConn *net.UDPConn) error {
	s.listenersMu.Lock()
	defer s.listenersMu.Unlock()
	if s.closed.Load() || s.udpServer != nil {
		return errors.New("stream server closed or UDP already attached")
	}
	udpSrv, err := NewPlainUDPServerWithUsers(udpConn, s.users, PlainUDPOptions{ServerID: s.serverID, Replays: s.replays})
	if err != nil {
		return err
	}
	if s.dialICMP != nil {
		udpSrv.SetDialICMP(s.dialICMP)
	}
	s.udpServer = udpSrv
	go func() {
		_ = udpSrv.Serve(s.ctx)
	}()
	return nil
}

// UDPServer returns the underlying PlainUDPServer instance.
func (s *StreamServer) UDPServer() *PlainUDPServer {
	s.listenersMu.Lock()
	defer s.listenersMu.Unlock()
	return s.udpServer
}

// Serve starts accepting connections on one or more TCP listeners.
// When multiple listeners are provided (e.g. via SO_REUSEPORT on Linux),
// connections are accepted in parallel across all listeners.
func (s *StreamServer) Serve(listeners ...net.Listener) error {
	if len(listeners) == 0 {
		return errors.New("no listeners provided")
	}
	s.listenersMu.Lock()
	if s.closed.Load() {
		s.listenersMu.Unlock()
		for _, ln := range listeners {
			_ = ln.Close()
		}
		return net.ErrClosed
	}
	s.listeners = append(s.listeners, listeners...)
	s.listenersMu.Unlock()

	var lnWg sync.WaitGroup
	errCh := make(chan error, len(listeners))

	for _, l := range listeners {
		lnWg.Add(1)
		go func(ln net.Listener) {
			defer lnWg.Done()
			for {
				conn, err := ln.Accept()
				if err != nil {
					if s.closed.Load() {
						return
					}
					errCh <- err
					return
				}

				if !s.admitConnection() {
					_ = conn.Close()
					continue
				}
				go s.runConnection(s.ctx, conn)
			}
		}(l)
	}

	lnWg.Wait()
	close(errCh)
	if s.closed.Load() {
		return nil
	}
	for err := range errCh {
		if err != nil && !errors.Is(err, net.ErrClosed) {
			return err
		}
	}
	return nil
}

// HandleConn processes an incoming raw TCP connection using the server's root context.
func (s *StreamServer) HandleConn(conn net.Conn) {
	s.HandleConnContext(s.ctx, conn)
}

// HandleConnContext processes an incoming raw TCP connection with the provided context.
// It enforces connection limits and bounded concurrent handshakes before processing.
func (s *StreamServer) HandleConnContext(ctx context.Context, conn net.Conn) {
	if !s.admitConnection() {
		_ = conn.Close()
		return
	}
	s.runConnection(ctx, conn)
}

func (s *StreamServer) runConnection(ctx context.Context, conn net.Conn) {
	defer s.wg.Done()
	defer s.activeConns.Add(-1)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	stopConn := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopConn()
	s.handleConn(ctx, conn)
}

func (s *StreamServer) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	handshakeReleased := false
	releaseHandshake := func() {
		if !handshakeReleased {
			handshakeReleased = true
			select {
			case <-s.handshakeSem:
			default:
			}
		}
	}
	defer releaseHandshake()

	// 2-second deadline for the initial handshake flight
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// 1. Read and verify polymorphic ClientHello (49-113 bytes)
	var clientNonce [24]byte
	var ts uint64
	var matchedUser *UserKey

	if len(s.psk) > 0 && len(s.users) <= 1 {
		cNonce, tStamp, err := rawstream.ReadAndVerifyPolymorphicClientHello(conn, s.psk, s.serverID, time.Now())
		if err != nil {
			return
		}
		clientNonce = cNonce
		ts = tStamp
		if len(s.users) == 1 {
			matchedUser = &s.users[0]
		} else {
			matchedUser = &UserKey{PSK: s.psk}
		}
	} else {
		matchedIdx, cNonce, tStamp, err := s.matcher.ReadAndMatch(conn, time.Now())
		if err != nil || matchedIdx < 0 || matchedIdx >= len(s.users) {
			return
		}
		clientNonce = cNonce
		ts = tStamp
		matchedUser = &s.users[matchedIdx]
	}

	// 2. Early non-mutating check in replay cache
	nonceHex := hex.EncodeToString(clientNonce[:])
	if s.replays.Check(nonceHex, time.Now()) {
		// Replayed handshake detected: drop immediately with 0 bytes
		return
	}

	// 3. Read 2-byte wire length of the 0-RTT frame
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return
	}
	wireLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if wireLen <= 16 || wireLen > rawstream.MaxChunkWireLen {
		return
	}

	// 4. Read encrypted 0-RTT frame
	encFrame := make([]byte, wireLen)
	if _, err := io.ReadFull(conn, encFrame); err != nil {
		return
	}

	// 5. Derive 0-RTT key and decrypt open frame
	k0RTT, err := rawstream.Derive0RTTKey(matchedUser.PSK, s.serverID, ts, clientNonce)
	if err != nil {
		return
	}

	openFramePlaintext, err := rawstream.Decrypt0RTTChunk(k0RTT, encFrame)
	if err != nil {
		// Decryption failed: drop with 0 bytes, do NOT commit replay cache
		return
	}

	// 6. Decode target and optional initial payload (strips dynamic padding)
	targetAddr, initialPayload, err := rawstream.Decode0RTTOpenFrame(openFramePlaintext)
	if err != nil {
		// Invalid open frame / target: drop with 0 bytes, do NOT commit replay cache
		return
	}

	// 7. Both ClientHello and 0-RTT frame validated: commit Nonce to durable replay cache
	accepted, err := s.replays.Accept(nonceHex, time.Now())
	if err != nil || !accepted {
		// Concurrent replay race: drop
		return
	}

	// 8. Generate polymorphic ServerHello (41-105 bytes)
	serverHelloRecord, serverNonce, err := rawstream.CreatePolymorphicServerHello(matchedUser.PSK, s.serverID, ts, clientNonce)
	if err != nil {
		return
	}

	// 9. Write ServerHello to client
	if _, err := conn.Write(serverHelloRecord); err != nil {
		return
	}

	// 10. Derive bidirectional session keys
	c2sKey, s2cKey, err := rawstream.DeriveSessionKeys(matchedUser.PSK, s.serverID, ts, clientNonce, serverNonce)
	if err != nil {
		return
	}

	// Cryptographic handshake successfully completed:
	// Release the handshake semaphore immediately so concurrent handshakes are not queued
	releaseHandshake()

	// Clear the 2-second handshake deadline so dialing upstream target is not aborted prematurely
	_ = conn.SetDeadline(time.Time{})

	// 11. Dial upstream target using session-scoped context
	baseCtx := ctx
	if baseCtx == nil {
		baseCtx = s.ctx
	}
	connCtx, connCancel := context.WithCancel(ContextWithUser(baseCtx, matchedUser))
	defer connCancel()

	upstream, err := s.dialTarget(connCtx, "tcp", targetAddr)
	if err != nil {
		return
	}
	defer upstream.Close()

	// Upgrade TCP settings: enable NoDelay and aggressive KeepAlive to prevent intermediate NAT/IEPL timeouts
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(15 * time.Second)
	} else if kac, ok := conn.(interface {
		SetKeepAlive(bool) error
		SetKeepAlivePeriod(time.Duration) error
	}); ok {
		_ = kac.SetKeepAlive(true)
		_ = kac.SetKeepAlivePeriod(15 * time.Second)
	}
	if tc, ok := upstream.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(15 * time.Second)
	} else if kac, ok := upstream.(interface {
		SetKeepAlive(bool) error
		SetKeepAlivePeriod(time.Duration) error
	}); ok {
		_ = kac.SetKeepAlive(true)
		_ = kac.SetKeepAlivePeriod(15 * time.Second)
	}

	// 12. Send initial payload to upstream if present
	if len(initialPayload) > 0 {
		if _, err := upstream.Write(initialPayload); err != nil {
			return
		}
	}

	// 13. Wrap client connection in AEAD StreamConn
	rStream, err := rawstream.NewAEADStream(c2sKey)
	if err != nil {
		return
	}
	wStream, err := rawstream.NewAEADStream(s2cKey)
	if err != nil {
		return
	}
	streamConn := rawstream.NewStreamConn(conn, rStream, wStream)

	// 14. Bidirectional relay
	relayBidirectional(connCtx, streamConn, upstream)
}

func relayBidirectional(ctx context.Context, client, target net.Conn) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		<-ctx.Done()
		_ = client.Close()
		_ = target.Close()
	}()

	activityCh := make(chan struct{}, 64)
	signalActivity := func() {
		select {
		case activityCh <- struct{}{}:
		default:
		}
	}

	uploadDone := make(chan error, 1)
	downloadDone := make(chan error, 1)

	// client -> target (upload)
	go func() {
		bufPtr := copyBufferPool.Get().(*[]byte)
		defer copyBufferPool.Put(bufPtr)
		ar := &activityReader{r: client, onActivity: signalActivity}
		_, err := io.CopyBuffer(target, ar, *bufPtr)
		if err != nil {
			cancel()
		} else {
			closeWriteConn(target)
		}
		uploadDone <- err
	}()

	// target -> client (download)
	go func() {
		bufPtr := copyBufferPool.Get().(*[]byte)
		defer copyBufferPool.Put(bufPtr)
		ar := &activityReader{r: target, onActivity: signalActivity}
		_, err := io.CopyBuffer(client, ar, *bufPtr)
		if err != nil {
			cancel()
		} else {
			closeWriteConn(client)
		}
		downloadDone <- err
	}()

	waitRelay(ctx, activityCh, uploadDone, downloadDone, func() {
		_ = client.Close()
		_ = target.Close()
	})
}

// Close gracefully closes the listener, replay cache, and active PlainUDP server.
func (s *StreamServer) Close() error {
	s.listenersMu.Lock()
	s.closed.Store(true)
	listeners := s.listeners
	s.listeners = nil
	udpServer := s.udpServer
	s.listenersMu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	var firstErr error
	for _, ln := range listeners {
		if ln != nil {
			if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) && firstErr == nil {
				firstErr = err
			}
		}
	}
	if udpServer != nil {
		udpServer.Close()
	}
	s.wg.Wait()
	if s.replays != nil {
		_ = s.replays.Close()
	}
	return firstErr
}
