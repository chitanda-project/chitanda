package tunnel

import (
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// chitandaPacketQueue keeps the original small per-flow allocation and grows
// only when a cold outbound association actually accumulates a burst.
const chitandaSenderMaxCapacity = 4096
const chitandaSenderMaxAge = 3 * time.Second

type chitandaQueuedPacket struct {
	packet C.PacketAdapter
	added  time.Time
}

type chitandaPacketQueue struct {
	mu     sync.Mutex
	items  []chitandaQueuedPacket
	head   int
	length int
	closed bool
	ready  chan struct{}
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
