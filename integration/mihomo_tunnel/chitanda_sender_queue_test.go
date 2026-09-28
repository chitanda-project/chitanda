package tunnel

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

type chitandaQueueTestPacket struct {
	C.PacketAdapter
	id      int
	dropped atomic.Int32
}

func (p *chitandaQueueTestPacket) Drop() { p.dropped.Add(1) }

func TestChitandaQueueGrowsOnlyOnBurstAndPreservesFIFO(t *testing.T) {
	q := newChitandaPacketQueue()
	if got := len(q.items); got != senderCapacity {
		t.Fatalf("initial capacity = %d, want %d", got, senderCapacity)
	}
	packets := make([]*chitandaQueueTestPacket, 500)
	for i := range packets {
		packets[i] = &chitandaQueueTestPacket{id: i}
		q.push(packets[i])
	}
	if got := len(q.items); got != 512 {
		t.Fatalf("grown capacity = %d, want 512", got)
	}
	for i := range packets {
		if got := q.pop(); got != packets[i] {
			t.Fatalf("packet %d out of order: %v", i, got)
		}
	}
	if q.pop() != nil {
		t.Fatal("queue should be empty")
	}
	if got := len(q.items); got != senderCapacity {
		t.Fatalf("drained queue retained burst allocation: %d", got)
	}
	q.close()
}

func TestChitandaQueueBoundsAndDropsStalePackets(t *testing.T) {
	q := newChitandaPacketQueue()
	for i := 0; i < chitandaSenderMaxCapacity; i++ {
		q.push(&chitandaQueueTestPacket{id: i})
	}
	if got := len(q.items); got != chitandaSenderMaxCapacity {
		t.Fatalf("maximum capacity = %d", got)
	}
	overflow := &chitandaQueueTestPacket{}
	q.push(overflow)
	if overflow.dropped.Load() != 1 {
		t.Fatal("overflow packet was not dropped")
	}
	oldest := q.items[q.head].packet.(*chitandaQueueTestPacket)
	q.items[q.head].added = time.Now().Add(-chitandaSenderMaxAge - time.Second)
	newest := &chitandaQueueTestPacket{id: chitandaSenderMaxCapacity}
	q.push(newest)
	if oldest.dropped.Load() != 1 {
		t.Fatal("stale head was not replaced when queue was full")
	}
	if got := q.pop().(*chitandaQueueTestPacket).id; got != 1 {
		t.Fatalf("unexpected head after replacement: got %d", got)
	}
	q.close()
	if q.length != 0 {
		t.Fatal("close retained queued packets")
	}
}

func TestChitandaQueueConcurrentClose(t *testing.T) {
	q := newChitandaPacketQueue()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				q.push(&chitandaQueueTestPacket{})
			}
		}()
	}
	q.close()
	wg.Wait()
	if q.length != 0 || q.pop() != nil {
		t.Fatal("closed queue retained packets")
	}
}

func BenchmarkChitandaPacketQueue(b *testing.B) {
	q := newChitandaPacketQueue()
	packet := &chitandaQueueTestPacket{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q.push(packet)
		_ = q.pop()
	}
}

func BenchmarkOriginalPacketChannel(b *testing.B) {
	ch := make(chan C.PacketAdapter, senderCapacity)
	packet := &chitandaQueueTestPacket{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ch <- packet
		_ = <-ch
	}
}
