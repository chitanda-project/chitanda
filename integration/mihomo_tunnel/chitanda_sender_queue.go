package tunnel

import (
	"net"
	"net/netip"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// chitandaPacketQueue keeps the original small per-flow allocation and grows
// only when a cold outbound association actually accumulates a burst.
// Sized to 8192 to match quic-go's datagram send queue and absorb high-throughput cold starts.
const chitandaSenderMaxCapacity = 8192
const chitandaSenderMaxAge = 3 * time.Second

type chitandaQueuedPacket struct {
	packet C.PacketAdapter
	added  time.Time
}

type chitandaPacketQueue struct {
	mu           sync.Mutex
	items        []chitandaQueuedPacket
	head         int
	length       int
	closed       bool
	ready        chan struct{}
	lastDeadline time.Time
}

func newChitandaPacketQueue() *chitandaPacketQueue {
	return &chitandaPacketQueue{
		items: make([]chitandaQueuedPacket, senderCapacity),
		ready: make(chan struct{}, 1),
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
		q.items[q.head] = chitandaQueuedPacket{}
		q.head = (q.head + 1) % len(q.items)
		q.length--
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
	q.items[(q.head+q.length)%len(q.items)] = chitandaQueuedPacket{packet: packet, added: now}
	q.length++
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
		if q.length > 0 {
			q.signal()
		} else if len(q.items) > senderCapacity {
			q.items = make([]chitandaQueuedPacket, senderCapacity)
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
			if now.Sub(item.added) <= chitandaSenderMaxAge {
				batch = append(batch, item.packet)
			} else {
				expired = append(expired, item.packet)
			}
		}
		if q.length > 0 {
			q.signal()
		} else if len(q.items) > senderCapacity {
			q.items = make([]chitandaQueuedPacket, senderCapacity)
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
		items = append(items, q.items[q.head].packet)
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
	WriteBatch(payloads [][]byte, addrs []net.Addr) error
}

func unwrapBatchWriter(pc any) batchPacketWriter {
	for {
		if bw, ok := pc.(batchPacketWriter); ok {
			return bw
		}
		if u, ok := pc.(interface{ Upstream() any }); ok {
			pc = u.Upstream()
			continue
		}
		if u, ok := pc.(interface{ Unwrap() any }); ok {
			pc = u.Unwrap()
			continue
		}
		return nil
	}
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
			_ = bw.WriteBatch(payloads, addrs)
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
