package tunnel

import (
	"net"
	"net/netip"
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

func TestChitandaQueuePopBatch(t *testing.T) {
	q := newChitandaPacketQueue()
	for i := 0; i < 50; i++ {
		q.push(&chitandaQueueTestPacket{id: i})
	}
	batch1 := q.popBatch(32)
	if len(batch1) != 32 {
		t.Fatalf("expected batch of 32, got %d", len(batch1))
	}
	for i := 0; i < 32; i++ {
		if got := batch1[i].(*chitandaQueueTestPacket).id; got != i {
			t.Fatalf("batch packet %d out of order: %d", i, got)
		}
	}
	batch2 := q.popBatch(32)
	if len(batch2) != 18 {
		t.Fatalf("expected remaining batch of 18, got %d", len(batch2))
	}
	for i := 0; i < 18; i++ {
		if got := batch2[i].(*chitandaQueueTestPacket).id; got != 32+i {
			t.Fatalf("batch packet %d out of order: %d", i, got)
		}
	}
	if q.popBatch(32) != nil {
		t.Fatal("expected nil batch on empty queue")
	}
	q.close()
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

type mockBatchPacketConn struct {
	C.PacketConn
	batches [][][]byte
	addrs   [][]net.Addr
}

func (m *mockBatchPacketConn) WriteBatch(payloads [][]byte, addrs []net.Addr) error {
	m.batches = append(m.batches, payloads)
	m.addrs = append(m.addrs, addrs)
	return nil
}

func (m *mockBatchPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

type mockDrainPacket struct {
	C.PacketAdapter
	data     []byte
	metadata *C.Metadata
	dropped  atomic.Int32
}

func (p *mockDrainPacket) Data() []byte { return p.data }
func (p *mockDrainPacket) Metadata() *C.Metadata { return p.metadata }
func (p *mockDrainPacket) Drop() { p.dropped.Add(1) }

func TestChitandaSenderDrainBatch(t *testing.T) {
	sender := newPacketSender().(*packetSender)
	mockPC := &mockBatchPacketConn{}
	targetIP, _ := netip.ParseAddr("1.2.3.4")
	meta := &C.Metadata{
		NetWork: C.UDP,
		DstIP:   targetIP,
		DstPort: 1234,
	}

	packets := make([]*mockDrainPacket, 10)
	for i := 0; i < 10; i++ {
		packets[i] = &mockDrainPacket{
			data:     []byte{byte(i)},
			metadata: meta,
		}
		sender.ch.push(packets[i])
	}

	sender.drainBatch(mockPC, nil)

	if len(mockPC.batches) != 1 {
		t.Fatalf("expected 1 batch write, got %d", len(mockPC.batches))
	}
	t.Logf("batch len: %d, addrs: %v", len(mockPC.batches[0]), mockPC.addrs[0])
	if len(mockPC.batches[0]) != 10 {
		t.Fatalf("expected batch size 10, got %d", len(mockPC.batches[0]))
	}
	for i, p := range packets {
		if p.dropped.Load() != 1 {
			t.Fatalf("packet %d was not dropped after batch send", i)
		}
	}
	if sender.ch.length != 0 {
		t.Fatalf("expected empty queue after drain, got %d", sender.ch.length)
	}
}
