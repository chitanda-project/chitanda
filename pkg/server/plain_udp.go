package server

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/violetaini/chitanda/internal/frame"
	"github.com/violetaini/chitanda/internal/icmpmsg"
	"github.com/violetaini/chitanda/internal/plainudp"
	"github.com/violetaini/chitanda/internal/target"
	"github.com/violetaini/chitanda/pkg/auth"
)

const (
	DefaultUDPWorkerQueueSize = 1024
	DefaultUDPMemoryBudget    = 64 << 20 // 64 MB maximum in-flight datagram memory budget
	// Covers retained task/address metadata, including expanded IP strings.
	plainUDPTaskOverhead = 256
)

var udpTaskPool = sync.Pool{
	New: func() any {
		b := make([]byte, 64<<10)
		return &b
	},
}

type udpTask struct {
	userIndex  int
	sessionID  uint64
	clientAddr *net.UDPAddr
	targetAddr string
	payload    []byte
	memoryCost int64
	seq        uint64
	timestamp  uint64
}

// Round the wire bound up to a power of two rather than charging only payload
// length: the Go allocator may reserve a larger size class than make's cap.
// The receiver's single scratch buffer is separate from this queue budget.
func plainUDPTaskMemoryCost(wireLen int) int64 {
	backing := int64(256)
	for backing < int64(wireLen) {
		backing <<= 1
	}
	return backing + plainUDPTaskOverhead
}

type plainUDPSessionKey struct {
	userIndex int
	sessionID uint64
}

type PlainUDPServer struct {
	codec              *plainudp.Codec
	codecs             []*plainudp.Codec
	conn               *net.UDPConn
	sessions           sync.Map // plainUDPSessionKey -> *plainUDPSession
	sessionCount       atomic.Int64
	maxSessions        int64
	workers            []chan udpTask
	workerWg           sync.WaitGroup
	upstreamWg         sync.WaitGroup
	lifecycleMu        sync.Mutex
	started            bool
	done               chan struct{}
	ctx                context.Context
	cancel             context.CancelFunc
	resolveMu          sync.RWMutex
	resolveUDP         func(ctx context.Context, address string) (*net.UDPAddr, error)
	dialICMPMu         sync.RWMutex
	dialICMP           func(ctx context.Context, address string) (net.PacketConn, error)
	allowPrivateICMP   bool
	closed             atomic.Bool
	inFlightMem        atomic.Int64
	maxMemBudget       int64
	replays            *auth.ReplayCache
	namespaces         []string
	resourceIdentities []string
}

type plainUDPTarget struct {
	*net.UDPConn
	once    sync.Once
	release func()
}

func (t *plainUDPTarget) Close() error {
	var err error
	t.once.Do(func() { err = t.UDPConn.Close(); t.release() })
	return err
}

type plainICMPTarget struct {
	once       sync.Once
	release    func()
	address    string
	targetIP   net.IP
	packetConn net.PacketConn
	tracker    icmpmsg.EchoTracker
}

func (t *plainICMPTarget) Close() error {
	var err error
	t.once.Do(func() {
		if t.packetConn != nil {
			err = t.packetConn.Close()
		}
		if t.release != nil {
			t.release()
		}
	})
	return err
}

type plainUDPSession struct {
	sessionID        uint64
	codec            *plainudp.Codec
	clientAddr       atomic.Pointer[net.UDPAddr]
	targets          sync.Map // string(targetAddr) -> *net.UDPConn or *plainICMPTarget
	targetCount      atomic.Int64
	lastActive       atomic.Int64
	replayMu         sync.Mutex
	replay           frame.ReplayWindow
	guard            *UDPReplayWindow
	resourceIdentity string
	targetMu         sync.Mutex
	closed           bool
}

// PlainUDPOptions binds native UDP to the same identity and durable replay
// cache as TCP. A nil cache is explicitly memory-only SDK mode.
type PlainUDPOptions struct {
	ServerID string
	Replays  *auth.ReplayCache
}

// NewPlainUDPServer creates a new plain-udp listener with a bounded worker pool and memory budget.
func NewPlainUDPServer(conn *net.UDPConn, psk []byte, options ...PlainUDPOptions) (*PlainUDPServer, error) {
	return NewPlainUDPServerWithUsers(conn, []UserKey{{PSK: psk}}, options...)
}

// NewPlainUDPServerWithUsers keeps each user's authenticated UDP sessions and
// response cipher separate, even when clients choose the same session ID.
func NewPlainUDPServerWithUsers(conn *net.UDPConn, users []UserKey, options ...PlainUDPOptions) (*PlainUDPServer, error) {
	var option PlainUDPOptions
	if len(options) > 1 {
		return nil, errors.New("plainudp: multiple options")
	}
	if len(options) == 1 {
		option = options[0]
	}
	if conn == nil {
		return nil, errors.New("plainudp: listener is required")
	}
	if err := ValidateUserKeys(users); err != nil {
		return nil, err
	}
	codecs := make([]*plainudp.Codec, 0, len(users))
	identities := make([]string, 0, len(users))
	for _, user := range users {
		codec, err := plainudp.NewCodec(user.PSK, option.ServerID)
		if err != nil {
			return nil, err
		}
		codecs = append(codecs, codec)
		identities = append(identities, UDPResourceIdentity(user.PSK))
	}
	_ = conn.SetReadBuffer(8 << 20)
	_ = conn.SetWriteBuffer(8 << 20)

	numWorkers := runtime.NumCPU() * 2
	if numWorkers < 8 {
		numWorkers = 8
	}
	workers := make([]chan udpTask, numWorkers)
	for i := range workers {
		workers[i] = make(chan udpTask, DefaultUDPWorkerQueueSize)
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &PlainUDPServer{
		ctx: ctx, cancel: cancel, done: make(chan struct{}),
		codec:              codecs[0],
		codecs:             codecs,
		conn:               conn,
		workers:            workers,
		maxMemBudget:       DefaultUDPMemoryBudget,
		maxSessions:        10000,
		replays:            option.Replays,
		namespaces:         udpReplayNamespaces(users, option.ServerID),
		resourceIdentities: identities,
		resolveUDP:         target.ResolveUDPAddr,
	}, nil
}

// SetResolveUDP safely replaces the resolver used for new target connections.
// Existing target connections and in-progress resolutions are not changed.
// A nil function restores the default resolver, including its target restrictions.
func (s *PlainUDPServer) SetResolveUDP(fn func(ctx context.Context, address string) (*net.UDPAddr, error)) {
	if fn == nil {
		fn = target.ResolveUDPAddr
	}
	s.resolveMu.Lock()
	s.resolveUDP = fn
	s.resolveMu.Unlock()
}

// SetResolveUDPForTest is kept for compatibility with existing SDK callers.
func (s *PlainUDPServer) SetResolveUDPForTest(fn func(ctx context.Context, address string) (*net.UDPAddr, error)) {
	s.SetResolveUDP(fn)
}

// SetDialICMP sets the custom dialer used to listen/dial ICMP packets on the server.
func (s *PlainUDPServer) SetDialICMP(fn func(ctx context.Context, address string) (net.PacketConn, error)) {
	s.dialICMPMu.Lock()
	s.dialICMP = fn
	s.dialICMPMu.Unlock()
}

func (s *PlainUDPServer) SetAllowPrivateICMPTargets(allow bool) {
	s.dialICMPMu.Lock()
	s.allowPrivateICMP = allow
	s.dialICMPMu.Unlock()
}

func (s *PlainUDPServer) getDialICMP() func(ctx context.Context, address string) (net.PacketConn, error) {
	s.dialICMPMu.RLock()
	defer s.dialICMPMu.RUnlock()
	return s.dialICMP
}

// Serve starts the worker pool and the UDP packet read loop.
func (s *PlainUDPServer) Serve(ctx context.Context) error {
	s.lifecycleMu.Lock()
	if s.started || s.closed.Load() {
		s.lifecycleMu.Unlock()
		return errors.New("plainudp: already started or closed")
	}
	s.started = true
	s.lifecycleMu.Unlock()
	stopParent := context.AfterFunc(ctx, s.cancel)
	defer stopParent()
	ctx = s.ctx
	stopRead := context.AfterFunc(ctx, func() { _ = s.conn.Close() })
	defer stopRead()
	cleanerDone := make(chan struct{})
	go func() { defer close(cleanerDone); s.cleaner(ctx) }()
	defer func() {
		s.closed.Store(true)
		s.cancel()
		_ = s.conn.Close()
		// Only this read loop produces tasks. Closing after it has stopped
		// lets workers drain even a packet decoded concurrently with cancel.
		for _, tasks := range s.workers {
			close(tasks)
		}
		// Workers can create upstream readers; join them before closing targets.
		s.workerWg.Wait()
		s.closeSessions()
		s.upstreamWg.Wait()
		<-cleanerDone
		close(s.done)
	}()

	for i, ch := range s.workers {
		s.workerWg.Add(1)
		go s.workerLoop(ctx, i, ch)
	}
	// DecodePacket returns an owned payload, so the receive buffer never
	// belongs to a queued task. Retain only one 64 KiB scratch per serve loop.
	rawBufPtr := udpTaskPool.Get().(*[]byte)
	defer udpTaskPool.Put(rawBufPtr)

	for {
		if s.closed.Load() || ctx.Err() != nil {
			break
		}

		n, clientAddr, err := s.conn.ReadFromUDP(*rawBufPtr)
		if err != nil {
			if s.closed.Load() || ctx.Err() != nil {
				break
			}
			return err
		}

		// Reserve before authentication/copying, including conservative backing
		// allocation and metadata costs rather than a retained 64 KiB scratch.
		cost := plainUDPTaskMemoryCost(n)
		if s.inFlightMem.Add(cost) > s.maxMemBudget {
			s.inFlightMem.Add(-cost)
			continue // Drop under physical memory pressure
		}

		now := time.Now()
		var userIndex int
		var sessionID, seq, timestamp uint64
		var targetAddr string
		var payload []byte
		if len(s.codecs) == 1 {
			sessionID, targetAddr, payload, timestamp, seq, err = s.codecs[0].DecodePacket((*rawBufPtr)[:n], plainudp.DirClientToServer, now)
		} else {
			userIndex, sessionID, targetAddr, payload, timestamp, seq, err = plainudp.DecodePacketMulti(s.codecs, (*rawBufPtr)[:n], plainudp.DirClientToServer, now)
		}
		if err != nil {
			s.inFlightMem.Add(-cost)
			continue // Drop invalid / tampered / expired / wrong direction packets
		}

		workerIdx := (sessionID ^ uint64(userIndex)) % uint64(len(s.workers))
		task := udpTask{
			userIndex:  userIndex,
			sessionID:  sessionID,
			clientAddr: clientAddr,
			targetAddr: targetAddr,
			payload:    payload,
			memoryCost: cost,
			seq:        seq,
			timestamp:  timestamp,
		}

		select {
		case s.workers[workerIdx] <- task:
		default:
			// Drop under burst pressure without retaining the decoded payload.
			s.inFlightMem.Add(-cost)
		}
	}

	return nil
}

func (s *PlainUDPServer) workerLoop(ctx context.Context, workerID int, tasks <-chan udpTask) {
	defer s.workerWg.Done()
	for task := range tasks {
		if ctx.Err() == nil {
			s.processTask(ctx, task)
		}
		s.inFlightMem.Add(-task.memoryCost)
	}
}

func (s *PlainUDPServer) processTask(ctx context.Context, task udpTask) {
	if task.userIndex < 0 || task.userIndex >= len(s.codecs) {
		return
	}
	key := plainUDPSessionKey{userIndex: task.userIndex, sessionID: task.sessionID}
	val, loaded := s.sessions.Load(key)
	if !loaded {
		if s.maxSessions > 0 && s.sessionCount.Load() >= s.maxSessions {
			return // Session limit reached, drop task
		}
		newSession := &plainUDPSession{sessionID: task.sessionID, codec: s.codecs[task.userIndex], guard: NewPersistentUDPReplayWindow(s.replays, s.namespaces[task.userIndex], task.sessionID)}
		if task.userIndex < len(s.resourceIdentities) {
			newSession.resourceIdentity = s.resourceIdentities[task.userIndex]
		}
		actual, loadedActual := s.sessions.LoadOrStore(key, newSession)
		if !loadedActual {
			s.sessionCount.Add(1)
		}
		val = actual
	}
	session := val.(*plainUDPSession)
	session.targetMu.Lock()
	defer session.targetMu.Unlock()
	if session.closed || ctx.Err() != nil {
		return
	}

	// Anti-Replay verification MUST succeed BEFORE updating clientAddr
	accepted := session.guard.AcceptAuthenticated(task.seq, task.timestamp, time.Now())
	if !accepted {
		return
	}

	session.clientAddr.Store(task.clientAddr)
	session.lastActive.Store(time.Now().Unix())

	if strings.HasPrefix(task.targetAddr, "icmp:") {
		s.processICMPTask(ctx, session, task)
		return
	}

	targetConnVal, ok := session.targets.Load(task.targetAddr)
	var upstreamConn *plainUDPTarget
	if !ok {
		if session.targetCount.Load() >= 32 {
			return // Max targets reached for this session
		}
		release, ok := ReserveUDPTarget(session.resourceIdentity)
		if !ok {
			return
		}
		// Snapshot the callback under lock, but never hold it during DNS or
		// caller code. Cached targets do not enter this path.
		s.resolveMu.RLock()
		resolve := s.resolveUDP
		s.resolveMu.RUnlock()
		resolved, err := resolve(ctx, task.targetAddr)
		if err != nil || ctx.Err() != nil {
			release()
			return
		}

		upConn, err := net.DialUDP("udp", nil, resolved)
		if err != nil {
			release()
			return
		}
		_ = upConn.SetReadBuffer(8 << 20)
		_ = upConn.SetWriteBuffer(8 << 20)

		leased := &plainUDPTarget{UDPConn: upConn, release: release}
		actual, loaded := session.targets.LoadOrStore(task.targetAddr, leased)
		if loaded {
			_ = leased.Close()
			upstreamConn = actual.(*plainUDPTarget)
		} else {
			session.targetCount.Add(1)
			upstreamConn = leased
			s.upstreamWg.Add(1)
			go s.listenUpstream(ctx, session, task.targetAddr, upstreamConn)
		}
	} else {
		upstreamConn = targetConnVal.(*plainUDPTarget)
	}

	_, _ = upstreamConn.Write(task.payload)
}

func (s *PlainUDPServer) processICMPTask(ctx context.Context, session *plainUDPSession, task udpTask) {
	targetIPStr := strings.TrimPrefix(task.targetAddr, "icmp:")
	s.dialICMPMu.RLock()
	allowPrivate := s.allowPrivateICMP
	s.dialICMPMu.RUnlock()
	targetIP, err := target.ResolveICMPIP(ctx, targetIPStr, allowPrivate)
	if err != nil {
		return
	}

	targetConnVal, ok := session.targets.Load(task.targetAddr)
	var icmpTarget *plainICMPTarget
	if !ok {
		if session.targetCount.Load() >= 32 {
			return // Max targets reached for this session
		}
		release, ok := ReserveUDPTarget(session.resourceIdentity)
		if !ok {
			return
		}
		dialICMP := s.getDialICMP()
		var pconn net.PacketConn
		if dialICMP != nil {
			pconn, err = dialICMP(ctx, targetIP.String())
		} else {
			network := "ip4:icmp"
			listenAddr := "0.0.0.0"
			if targetIP.To4() == nil {
				network = "ip6:ipv6-icmp"
				listenAddr = "::"
			}
			pconn, err = net.ListenPacket(network, listenAddr)
		}
		if err != nil || ctx.Err() != nil {
			release()
			if pconn != nil {
				_ = pconn.Close()
			}
			return
		}

		target := &plainICMPTarget{
			release:    release,
			address:    task.targetAddr,
			targetIP:   targetIP,
			packetConn: pconn,
		}
		actual, loaded := session.targets.LoadOrStore(task.targetAddr, target)
		if loaded {
			_ = target.Close()
			icmpTarget = actual.(*plainICMPTarget)
		} else {
			session.targetCount.Add(1)
			icmpTarget = target
			s.upstreamWg.Add(1)
			go s.listenICMPUpstream(ctx, session, task.targetAddr, icmpTarget)
		}
	} else {
		var okCast bool
		icmpTarget, okCast = targetConnVal.(*plainICMPTarget)
		if !okCast {
			return
		}
	}

	wire, err := icmpTarget.tracker.PrepareRequest(task.payload, targetIP.To4() == nil)
	if err != nil {
		return
	}
	_, _ = icmpTarget.packetConn.WriteTo(wire, &net.IPAddr{IP: targetIP})
}

func (s *PlainUDPServer) listenICMPUpstream(ctx context.Context, session *plainUDPSession, targetAddr string, target *plainICMPTarget) {
	defer s.upstreamWg.Done()
	defer target.Close()
	buf := make([]byte, 64<<10)
	for {
		if s.closed.Load() || ctx.Err() != nil {
			return
		}
		_ = target.packetConn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, from, err := target.packetConn.ReadFrom(buf)
		if err != nil {
			if _, deleted := session.targets.LoadAndDelete(targetAddr); deleted {
				session.targetCount.Add(-1)
			}
			_ = target.Close()
			return
		}

		fromAddr, ok := from.(*net.IPAddr)
		if !ok || !fromAddr.IP.Equal(target.targetIP) {
			continue
		}
		payload, ok := target.tracker.RestoreReply(buf[:n], target.targetIP.To4() == nil)
		if !ok {
			continue
		}

		session.lastActive.Store(time.Now().Unix())
		encrypted, err := session.codec.EncodePacket(nil, plainudp.DirServerToClient, session.sessionID, targetAddr, payload, time.Now())
		if err != nil {
			continue
		}

		clientAddr := session.clientAddr.Load()
		if clientAddr != nil {
			_, _ = s.conn.WriteToUDP(encrypted, clientAddr)
		}
	}
}

func (s *PlainUDPServer) listenUpstream(ctx context.Context, session *plainUDPSession, targetAddr string, upstreamConn *plainUDPTarget) {
	defer s.upstreamWg.Done()
	defer upstreamConn.Close()
	buf := make([]byte, 64<<10)
	for {
		if s.closed.Load() || ctx.Err() != nil {
			return
		}
		_ = upstreamConn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := upstreamConn.Read(buf)
		if err != nil {
			if _, deleted := session.targets.LoadAndDelete(targetAddr); deleted {
				session.targetCount.Add(-1)
			}
			_ = upstreamConn.Close()
			return
		}

		session.lastActive.Store(time.Now().Unix())
		encrypted, err := session.codec.EncodePacket(nil, plainudp.DirServerToClient, session.sessionID, targetAddr, buf[:n], time.Now())
		if err != nil {
			continue
		}

		clientAddr := session.clientAddr.Load()
		if clientAddr != nil {
			_, _ = s.conn.WriteToUDP(encrypted, clientAddr)
		}
	}
}

func (s *PlainUDPServer) cleaner(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().Unix()
			s.sessions.Range(func(key, value any) bool {
				session := value.(*plainUDPSession)
				if now-session.lastActive.Load() > 60 {
					if !session.targetMu.TryLock() {
						return true
					}
					if now-session.lastActive.Load() <= 60 {
						session.targetMu.Unlock()
						return true
					}
					session.closed = true
					session.targets.Range(func(tKey, tVal any) bool {
						if closer, ok := tVal.(io.Closer); ok {
							_ = closer.Close()
						}
						session.targets.Delete(tKey)
						return true
					})
					s.sessions.Delete(key)
					s.sessionCount.Add(-1)
					session.targetMu.Unlock()
				}
				return true
			})
		}
	}
}

func (s *PlainUDPServer) Close() error {
	s.lifecycleMu.Lock()
	s.closed.Store(true)
	started := s.started
	s.lifecycleMu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
	if started {
		<-s.done
	} else {
		s.closeSessions()
	}
	return nil
}

func (s *PlainUDPServer) closeSessions() {
	s.sessions.Range(func(key, value any) bool {
		session := value.(*plainUDPSession)
		session.targets.Range(func(tKey, tVal any) bool {
			if closer, ok := tVal.(io.Closer); ok {
				_ = closer.Close()
			}
			return true
		})
		s.sessions.Delete(key)
		return true
	})
}

// PlainUDPCodec wraps plainudp.Codec for external integrators (e.g. Xray).
type PlainUDPCodec struct {
	codec            *plainudp.Codec
	namespace        string
	resourceIdentity string
}

func NewPlainUDPCodec(psk []byte, serverIDs ...string) (*PlainUDPCodec, error) {
	c, err := plainudp.NewCodec(psk, serverIDs...)
	if err != nil {
		return nil, err
	}
	serverID := ""
	if len(serverIDs) > 0 {
		serverID = serverIDs[0]
	}
	return &PlainUDPCodec{codec: c, namespace: UDPReplayNamespace(psk, serverID), resourceIdentity: UDPResourceIdentity(psk)}, nil
}

func (c *PlainUDPCodec) ReplayNamespace() string  { return c.namespace }
func (c *PlainUDPCodec) ResourceIdentity() string { return c.resourceIdentity }

func (c *PlainUDPCodec) DecodeClientPacket(packet []byte, now time.Time) (sessionID uint64, targetAddr string, payload []byte, timestamp uint64, seq uint64, err error) {
	return c.codec.DecodePacket(packet, plainudp.DirClientToServer, now)
}

func (c *PlainUDPCodec) DecodeServerPacket(packet []byte, now time.Time) (sessionID uint64, targetAddr string, payload []byte, timestamp uint64, seq uint64, err error) {
	return c.codec.DecodePacket(packet, plainudp.DirServerToClient, now)
}

func (c *PlainUDPCodec) EncodeServerPacket(sessionID uint64, targetAddr string, payload []byte, now time.Time) ([]byte, error) {
	return c.codec.EncodePacket(nil, plainudp.DirServerToClient, sessionID, targetAddr, payload, now)
}

func (c *PlainUDPCodec) EncodeClientPacket(sessionID uint64, targetAddr string, payload []byte, now time.Time) ([]byte, error) {
	return c.codec.EncodePacket(nil, plainudp.DirClientToServer, sessionID, targetAddr, payload, now)
}

// DecodeClientPacketMulti decodes a client packet across multiple user codecs.
func DecodeClientPacketMulti(codecs []*PlainUDPCodec, packet []byte, now time.Time) (matchedIndex int, sessionID uint64, targetAddr string, payload []byte, timestamp uint64, seq uint64, err error) {
	for i, c := range codecs {
		if c == nil || c.codec == nil {
			continue
		}
		sID, tAddr, pLoad, ts, sNum, err := c.DecodeClientPacket(packet, now)
		if err == nil {
			return i, sID, tAddr, pLoad, ts, sNum, nil
		}
	}
	return -1, 0, "", nil, 0, 0, plainudp.ErrDecryptionFailed
}

// UDPReplayWindow provides anti-replay window tracking for datagrams.
type UDPReplayWindow struct {
	mu        sync.Mutex
	window    frame.ReplayWindow
	cache     *auth.ReplayCache
	namespace string
	sessionID uint64
	buckets   map[uint64]time.Time
}

func NewUDPReplayWindow() *UDPReplayWindow {
	return &UDPReplayWindow{}
}

func (w *UDPReplayWindow) Accept(seq uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.window.Accept(seq)
}
