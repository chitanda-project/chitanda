package tunnel

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// The packet-count limit protects one association; byte limits also protect a
// router when many associations are waiting for an outbound handshake.
const chitandaSenderInitialCapacity = 32
const chitandaSenderMaxCapacity = 8192
const chitandaSenderMaxAge = 3 * time.Second
const chitandaSenderMaxFlowBytes int64 = 4 << 20
const chitandaSenderGlobalBytes int64 = 64 << 20
const chitandaSenderPacketOverhead int64 = 128

type chitandaQueueBudget struct {
	used  atomic.Int64
	limit int64
}

var chitandaGlobalQueueBudget = &chitandaQueueBudget{limit: chitandaSenderGlobalBytes}

func (b *chitandaQueueBudget) reserve(size int64) bool {
	for {
		used := b.used.Load()
		if size > b.limit-used {
			return false
		}
		if b.used.CompareAndSwap(used, used+size) {
			return true
		}
	}
}

func (b *chitandaQueueBudget) release(size int64) {
	b.used.Add(-size)
}

func chitandaPacketSize(packet C.PacketAdapter) int64 {
	data := packet.Data()
	size := len(data)
	if cap(data) > size {
		size = cap(data)
	}
	return int64(size) + chitandaSenderPacketOverhead
}

type chitandaQueuedPacket struct {
	packet C.PacketAdapter
	added  time.Time
	size   int64
}

type chitandaPacketQueue struct {
	mu           sync.Mutex
	items        []chitandaQueuedPacket
	head         int
	length       int
	bytes        int64
	closed       bool
	ready        chan struct{}
	lastDeadline time.Time
	budget       *chitandaQueueBudget
}

func newChitandaPacketQueue() *chitandaPacketQueue {
	return &chitandaPacketQueue{
		items:  make([]chitandaQueuedPacket, chitandaSenderInitialCapacity),
		ready:  make(chan struct{}, 1),
		budget: chitandaGlobalQueueBudget,
	}
}

func (q *chitandaPacketQueue) signal() {
	select {
	case q.ready <- struct{}{}:
	default:
	}
}

func (q *chitandaPacketQueue) push(packet C.PacketAdapter) {
	now := time.Now()
	size := chitandaPacketSize(packet)
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		packet.Drop()
		return
	}
	var expired C.PacketAdapter
	if q.length == chitandaSenderMaxCapacity {
		oldest := q.items[q.head]
		if now.Sub(oldest.added) <= chitandaSenderMaxAge {
			q.mu.Unlock()
			packet.Drop()
			return
		}
		expired = oldest.packet
		q.bytes -= oldest.size
		q.budget.release(oldest.size)
		q.items[q.head] = chitandaQueuedPacket{}
		q.head = (q.head + 1) % len(q.items)
		q.length--
	}
	if size > chitandaSenderMaxFlowBytes-q.bytes || !q.budget.reserve(size) {
		q.mu.Unlock()
		packet.Drop()
		if expired != nil {
			expired.Drop()
		}
		return
	}
	if q.length == len(q.items) {
		capacity := len(q.items) * 2
		if capacity > chitandaSenderMaxCapacity {
			capacity = chitandaSenderMaxCapacity
		}
		grown := make([]chitandaQueuedPacket, capacity)
		for i := 0; i < q.length; i++ {
			grown[i] = q.items[(q.head+i)%len(q.items)]
		}
		q.items, q.head = grown, 0
	}
	q.items[(q.head+q.length)%len(q.items)] = chitandaQueuedPacket{packet: packet, added: now, size: size}
	q.length++
	q.bytes += size
	q.signal()
	q.mu.Unlock()
	if expired != nil {
		expired.Drop()
	}
}

func (q *chitandaPacketQueue) pop() C.PacketAdapter {
	for {
		q.mu.Lock()
		if q.length == 0 {
			q.mu.Unlock()
			return nil
		}
		item := q.items[q.head]
		q.items[q.head] = chitandaQueuedPacket{}
		q.head = (q.head + 1) % len(q.items)
		q.length--
		q.bytes -= item.size
		q.budget.release(item.size)
		if q.length > 0 {
			q.signal()
		} else if len(q.items) > chitandaSenderInitialCapacity {
			q.items = make([]chitandaQueuedPacket, chitandaSenderInitialCapacity)
			q.head = 0
		}
		q.mu.Unlock()
		if time.Since(item.added) <= chitandaSenderMaxAge {
			return item.packet
		}
		item.packet.Drop()
	}
}

func (q *chitandaPacketQueue) popBatch(max int) []C.PacketAdapter {
	if max <= 0 {
		max = 32
	}
	now := time.Now()
	for {
		q.mu.Lock()
		if q.length == 0 {
			q.mu.Unlock()
			return nil
		}
		n := q.length
		if n > max {
			n = max
		}
		batch := make([]C.PacketAdapter, 0, n)
		var expired []C.PacketAdapter
		for i := 0; i < n; i++ {
			item := q.items[q.head]
			q.items[q.head] = chitandaQueuedPacket{}
			q.head = (q.head + 1) % len(q.items)
			q.length--
			q.bytes -= item.size
			q.budget.release(item.size)
			if now.Sub(item.added) <= chitandaSenderMaxAge {
				batch = append(batch, item.packet)
			} else {
				expired = append(expired, item.packet)
			}
		}
		if q.length > 0 {
			q.signal()
		} else if len(q.items) > chitandaSenderInitialCapacity {
			q.items = make([]chitandaQueuedPacket, chitandaSenderInitialCapacity)
			q.head = 0
		}
		q.mu.Unlock()
		for _, p := range expired {
			p.Drop()
		}
		if len(batch) > 0 {
			return batch
		}
	}
}

func (q *chitandaPacketQueue) close() {
	q.mu.Lock()
	q.closed = true
	items := make([]C.PacketAdapter, 0, q.length)
	for q.length > 0 {
		item := q.items[q.head]
		items = append(items, item.packet)
		q.bytes -= item.size
		q.budget.release(item.size)
		q.items[q.head] = chitandaQueuedPacket{}
		q.head = (q.head + 1) % len(q.items)
		q.length--
	}
	q.items = nil
	q.mu.Unlock()
	for _, packet := range items {
		packet.Drop()
	}
}

type batchPacketWriter interface {
	ChitandaBatchWrite(payloads [][]byte, addrs []net.Addr) (int, error)
}

func unwrapBatchWriter(pc any) batchPacketWriter {
	if bw, ok := pc.(batchPacketWriter); ok {
		return bw
	}
	// Only bypass the tracker we explicitly account for. Walking arbitrary
	// wrapper chains could skip a policy or a second accounting layer.
	if _, ok := pc.(interface{ RecordChitandaBatchUpload(int) }); !ok {
		return nil
	}
	if u, ok := pc.(interface{ Upstream() any }); ok {
		bw, _ := u.Upstream().(batchPacketWriter)
		return bw
	}
	return nil
}

func (s *packetSender) resolveTargetAddr(pc C.PacketConn, packet C.PacketAdapter) *net.UDPAddr {
	metadata := packet.Metadata()
	s.mappingMutex.RLock()
	targetAddr := s.originToTarget[metadata.String()]
	s.mappingMutex.RUnlock()

	if targetAddr.IsValid() {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(targetAddr, metadata.DstPort))
	}

	originMetadata := metadata
	metadata = metadata.Clone()
	_ = preHandleMetadata(metadata)
	metadata = metadata.Pure()
	if metadata.Host != "" {
		if err := pc.ResolveUDP(s.ctx, metadata); err != nil {
			log.Warnln("[UDP] Resolve Ip error: %s", err)
			return nil
		}
	}
	if !metadata.DstIP.IsValid() {
		log.Warnln("[UDP] Destination ip not valid: %#v", metadata)
		return nil
	}
	s.AddMapping(originMetadata, metadata)
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(metadata.DstIP, metadata.DstPort))
}

func (s *packetSender) drainBatch(pc C.PacketConn, proxy C.WriteBackProxy) {
	packets := s.ch.popBatch(32)
	if len(packets) == 0 {
		return
	}
	defer func() {
		for _, p := range packets {
			p.Drop()
		}
	}()

	bw := unwrapBatchWriter(pc)
	if bw != nil && len(packets) > 1 {
		payloads := make([][]byte, 0, len(packets))
		addrs := make([]net.Addr, 0, len(packets))
		for _, packet := range packets {
			if proxy != nil {
				proxy.UpdateWriteBack(packet)
			}
			addr := s.resolveTargetAddr(pc, packet)
			if addr != nil {
				payloads = append(payloads, packet.Data())
				addrs = append(addrs, addr)
			}
		}
		if len(payloads) > 0 {
			written, _ := bw.ChitandaBatchWrite(payloads, addrs)
			if recorder, ok := pc.(interface{ RecordChitandaBatchUpload(int) }); ok && written > 0 {
				recorder.RecordChitandaBatchUpload(written)
			}
		}
	} else {
		for _, packet := range packets {
			if proxy != nil {
				proxy.UpdateWriteBack(packet)
			}
			addr := s.resolveTargetAddr(pc, packet)
			if addr != nil {
				_, _ = pc.WriteTo(packet.Data(), addr)
			}
		}
	}

	if time.Since(s.ch.lastDeadline) >= time.Second {
		s.ch.lastDeadline = time.Now()
		_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))
	}
}
