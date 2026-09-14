package server

import (
	"context"
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
	sessionID  uint64
	clientAddr *net.UDPAddr
	targetAddr string
	payload    []byte
	rawBuf     *[]byte
	rawLen     int
	seq        uint64
}

type PlainUDPServer struct {
	codec        *plainudp.Codec
	conn         *net.UDPConn
	sessions     sync.Map // uint64(sessionID) -> *plainUDPSession
	sessionCount atomic.Int64
	maxSessions  int64
	workers      []chan udpTask
	workerWg     sync.WaitGroup
	resolveUDP   func(ctx context.Context, address string) (*net.UDPAddr, error)
	closed       atomic.Bool
	inFlightMem  atomic.Int64
	maxMemBudget int64
}

type plainUDPSession struct {
	sessionID   uint64
	clientAddr  atomic.Pointer[net.UDPAddr]
	targets     sync.Map // string(targetAddr) -> *net.UDPConn
	targetCount atomic.Int64
	lastActive  atomic.Int64
	replayMu    sync.Mutex
	replay      frame.ReplayWindow
}

// NewPlainUDPServer creates a new plain-udp listener with a bounded worker pool and memory budget.
func NewPlainUDPServer(conn *net.UDPConn, psk []byte) (*PlainUDPServer, error) {
	_ = conn.SetReadBuffer(8 << 20)
	_ = conn.SetWriteBuffer(8 << 20)

	codec, err := plainudp.NewCodec(psk)
	if err != nil {
		return nil, err
	}

	numWorkers := runtime.NumCPU() * 2
	if numWorkers < 8 {
		numWorkers = 8
	}
	workers := make([]chan udpTask, numWorkers)
	for i := range workers {
		workers[i] = make(chan udpTask, DefaultUDPWorkerQueueSize)
	}

	return &PlainUDPServer{
		codec:        codec,
		conn:         conn,
		workers:      workers,
		maxMemBudget: DefaultUDPMemoryBudget,
		maxSessions:  10000,
		resolveUDP:   target.ResolveUDPAddr,
	}, nil
}

// SetResolveUDPForTest overrides target resolution in unit tests.
func (s *PlainUDPServer) SetResolveUDPForTest(fn func(ctx context.Context, address string) (*net.UDPAddr, error)) {
	s.resolveUDP = fn
}

// Serve starts the worker pool and the UDP packet read loop.
func (s *PlainUDPServer) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go s.cleaner(ctx)

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
		sessionID, targetAddr, payload, _, seq, err := s.codec.DecodePacket((*rawBufPtr)[:n], plainudp.DirClientToServer, now)
		if err != nil {
			s.inFlightMem.Add(-bufCap)
			udpTaskPool.Put(rawBufPtr)
			continue // Drop invalid / tampered / expired / wrong direction packets
		}

		workerIdx := sessionID % uint64(len(s.workers))
		task := udpTask{
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

	s.workerWg.Wait()
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
	val, loaded := s.sessions.Load(task.sessionID)
	if !loaded {
		if s.maxSessions > 0 && s.sessionCount.Load() >= s.maxSessions {
			return // Session limit reached, drop task
		}
		newSession := &plainUDPSession{sessionID: task.sessionID}
		actual, loadedActual := s.sessions.LoadOrStore(task.sessionID, newSession)
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
		resolved, err := s.resolveUDP(ctx, task.targetAddr)
		if err != nil {
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
			go s.listenUpstream(ctx, session, task.targetAddr, upstreamConn)
		}
	} else {
		upstreamConn = targetConnVal.(*net.UDPConn)
	}

	_, _ = upstreamConn.Write(task.payload)
}

func (s *PlainUDPServer) listenUpstream(ctx context.Context, session *plainUDPSession, targetAddr string, upstreamConn *net.UDPConn) {
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
		encrypted, err := s.codec.EncodePacket(nil, plainudp.DirServerToClient, session.sessionID, targetAddr, buf[:n], time.Now())
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
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.sessions.Range(func(key, value any) bool {
		session := value.(*plainUDPSession)
		session.targets.Range(func(tKey, tVal any) bool {
			_ = tVal.(*net.UDPConn).Close()
			return true
		})
		s.sessions.Delete(key)
		return true
	})
	return nil
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

func (c *PlainUDPCodec) EncodeServerPacket(sessionID uint64, targetAddr string, payload []byte, now time.Time) ([]byte, error) {
	return c.codec.EncodePacket(nil, plainudp.DirServerToClient, sessionID, targetAddr, payload, now)
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
