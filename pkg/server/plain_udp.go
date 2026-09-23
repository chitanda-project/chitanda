package server

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/violetaini/chitanda/internal/frame"
	"github.com/violetaini/chitanda/internal/plainudp"
	"github.com/violetaini/chitanda/internal/target"
)

const (
	DefaultUDPWorkerQueueSize = 256
	DefaultUDPMemoryBudget    = 64 << 20 // 64 MB maximum in-flight datagram memory budget
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
	rawBuf     *[]byte
	rawLen     int
	seq        uint64
}

type plainUDPSessionKey struct {
	userIndex int
	sessionID uint64
}

type PlainUDPServer struct {
	codec        *plainudp.Codec
	codecs       []*plainudp.Codec
	conn         *net.UDPConn
	sessions     sync.Map // plainUDPSessionKey -> *plainUDPSession
	sessionCount atomic.Int64
	maxSessions  int64
	workers      []chan udpTask
	workerWg     sync.WaitGroup
	upstreamWg   sync.WaitGroup
	lifecycleMu  sync.Mutex
	started      bool
	done         chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
	resolveMu    sync.RWMutex
	resolveUDP   func(ctx context.Context, address string) (*net.UDPAddr, error)
	closed       atomic.Bool
	inFlightMem  atomic.Int64
	maxMemBudget int64
}

type plainUDPSession struct {
	sessionID   uint64
	codec       *plainudp.Codec
	clientAddr  atomic.Pointer[net.UDPAddr]
	targets     sync.Map // string(targetAddr) -> *net.UDPConn
	targetCount atomic.Int64
	lastActive  atomic.Int64
	replayMu    sync.Mutex
	replay      frame.ReplayWindow
}

// NewPlainUDPServer creates a new plain-udp listener with a bounded worker pool and memory budget.
func NewPlainUDPServer(conn *net.UDPConn, psk []byte) (*PlainUDPServer, error) {
	return NewPlainUDPServerWithUsers(conn, []UserKey{{PSK: psk}})
}

// NewPlainUDPServerWithUsers keeps each user's authenticated UDP sessions and
// response cipher separate, even when clients choose the same session ID.
func NewPlainUDPServerWithUsers(conn *net.UDPConn, users []UserKey) (*PlainUDPServer, error) {
	if conn == nil {
		return nil, errors.New("plainudp: listener is required")
	}
	if err := ValidateUserKeys(users); err != nil {
		return nil, err
	}
	codecs := make([]*plainudp.Codec, 0, len(users))
	for _, user := range users {
		codec, err := plainudp.NewCodec(user.PSK)
		if err != nil {
			return nil, err
		}
		codecs = append(codecs, codec)
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
		codec:        codecs[0],
		codecs:       codecs,
		conn:         conn,
		workers:      workers,
		maxMemBudget: DefaultUDPMemoryBudget,
		maxSessions:  10000,
		resolveUDP:   target.ResolveUDPAddr,
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

	for {
		if s.closed.Load() || ctx.Err() != nil {
			break
		}

		rawBufPtr := udpTaskPool.Get().(*[]byte)
		n, clientAddr, err := s.conn.ReadFromUDP(*rawBufPtr)
		if err != nil {
			udpTaskPool.Put(rawBufPtr)
			if s.closed.Load() || ctx.Err() != nil {
				break
			}
			return err
		}

		// Enforce strict physical buffer capacity budget (64MB max = 1024 concurrent 64KB buffers)
		bufCap := int64(cap(*rawBufPtr))
		if s.inFlightMem.Add(bufCap) > s.maxMemBudget {
			s.inFlightMem.Add(-bufCap)
			udpTaskPool.Put(rawBufPtr)
			continue // Drop under physical memory pressure
		}

		now := time.Now()
		var userIndex int
		var sessionID, seq uint64
		var targetAddr string
		var payload []byte
		if len(s.codecs) == 1 {
			sessionID, targetAddr, payload, _, seq, err = s.codecs[0].DecodePacket((*rawBufPtr)[:n], plainudp.DirClientToServer, now)
		} else {
			userIndex, sessionID, targetAddr, payload, _, seq, err = plainudp.DecodePacketMulti(s.codecs, (*rawBufPtr)[:n], plainudp.DirClientToServer, now)
		}
		if err != nil {
			s.inFlightMem.Add(-bufCap)
			udpTaskPool.Put(rawBufPtr)
			continue // Drop invalid / tampered / expired / wrong direction packets
		}

		workerIdx := (sessionID ^ uint64(userIndex)) % uint64(len(s.workers))
		task := udpTask{
			userIndex:  userIndex,
			sessionID:  sessionID,
			clientAddr: clientAddr,
			targetAddr: targetAddr,
			payload:    payload,
			rawBuf:     rawBufPtr,
			rawLen:     n,
			seq:        seq,
		}

		select {
		case s.workers[workerIdx] <- task:
		default:
			// Under extreme burst load, drop packet, decrement physical memory budget, and recycle buffer
			s.inFlightMem.Add(-bufCap)
			udpTaskPool.Put(rawBufPtr)
		}
	}

	return nil
}

func (s *PlainUDPServer) workerLoop(ctx context.Context, workerID int, tasks <-chan udpTask) {
	defer s.workerWg.Done()
	for {
		select {
		case <-ctx.Done():
			// Drain remaining tasks on shutdown
			for {
				select {
				case task := <-tasks:
					s.inFlightMem.Add(-int64(cap(*task.rawBuf)))
					udpTaskPool.Put(task.rawBuf)
				default:
					return
				}
			}
		case task := <-tasks:
			s.processTask(ctx, task)
			s.inFlightMem.Add(-int64(cap(*task.rawBuf)))
			udpTaskPool.Put(task.rawBuf)
		}
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
		newSession := &plainUDPSession{sessionID: task.sessionID, codec: s.codecs[task.userIndex]}
		actual, loadedActual := s.sessions.LoadOrStore(key, newSession)
		if !loadedActual {
			s.sessionCount.Add(1)
		}
		val = actual
	}
	session := val.(*plainUDPSession)

	// Anti-Replay verification MUST succeed BEFORE updating clientAddr
	session.replayMu.Lock()
	accepted := session.replay.Accept(task.seq)
	session.replayMu.Unlock()
	if !accepted {
		return
	}

	session.clientAddr.Store(task.clientAddr)
	session.lastActive.Store(time.Now().Unix())

	targetConnVal, ok := session.targets.Load(task.targetAddr)
	var upstreamConn *net.UDPConn
	if !ok {
		if session.targetCount.Load() >= 32 {
			return // Max targets reached for this session
		}
		// Snapshot the callback under lock, but never hold it during DNS or
		// caller code. Cached targets do not enter this path.
		s.resolveMu.RLock()
		resolve := s.resolveUDP
		s.resolveMu.RUnlock()
		resolved, err := resolve(ctx, task.targetAddr)
		if err != nil || ctx.Err() != nil {
			return
		}

		upConn, err := net.DialUDP("udp", nil, resolved)
		if err != nil {
			return
		}
		_ = upConn.SetReadBuffer(8 << 20)
		_ = upConn.SetWriteBuffer(8 << 20)

		actual, loaded := session.targets.LoadOrStore(task.targetAddr, upConn)
		if loaded {
			_ = upConn.Close()
			upstreamConn = actual.(*net.UDPConn)
		} else {
			session.targetCount.Add(1)
			upstreamConn = upConn
			s.upstreamWg.Add(1)
			go s.listenUpstream(ctx, session, task.targetAddr, upstreamConn)
		}
	} else {
		upstreamConn = targetConnVal.(*net.UDPConn)
	}

	_, _ = upstreamConn.Write(task.payload)
}

func (s *PlainUDPServer) listenUpstream(ctx context.Context, session *plainUDPSession, targetAddr string, upstreamConn *net.UDPConn) {
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
					session.targets.Range(func(tKey, tVal any) bool {
						_ = tVal.(*net.UDPConn).Close()
						session.targets.Delete(tKey)
						return true
					})
					s.sessions.Delete(key)
					s.sessionCount.Add(-1)
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
			_ = tVal.(*net.UDPConn).Close()
			return true
		})
		s.sessions.Delete(key)
		return true
	})
}

// PlainUDPCodec wraps plainudp.Codec for external integrators (e.g. Xray).
type PlainUDPCodec struct {
	codec *plainudp.Codec
}

func NewPlainUDPCodec(psk []byte) (*PlainUDPCodec, error) {
	c, err := plainudp.NewCodec(psk)
	if err != nil {
		return nil, err
	}
	return &PlainUDPCodec{codec: c}, nil
}

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
	mu     sync.Mutex
	window frame.ReplayWindow
}

func NewUDPReplayWindow() *UDPReplayWindow {
	return &UDPReplayWindow{}
}

func (w *UDPReplayWindow) Accept(seq uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.window.Accept(seq)
}
