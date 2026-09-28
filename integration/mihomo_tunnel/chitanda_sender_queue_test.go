package tunnel

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

type chitandaQueueTestPacket struct {
	C.PacketAdapter
	id      int
	dropped atomic.Int32
}

func (p *chitandaQueueTestPacket) Drop()        { p.dropped.Add(1) }
func (p *chitandaQueueTestPacket) Data() []byte { return nil }

func TestChitandaQueueGrowsOnlyOnBurstAndPreservesFIFO(t *testing.T) {
	q := newChitandaPacketQueue()
	if got := len(q.items); got != chitandaSenderInitialCapacity {
		t.Fatalf("initial capacity = %d, want %d", got, chitandaSenderInitialCapacity)
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
	if got := len(q.items); got != chitandaSenderInitialCapacity {
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

func (m *mockBatchPacketConn) ChitandaBatchWrite(payloads [][]byte, addrs []net.Addr) (int, error) {
	m.batches = append(m.batches, payloads)
	m.addrs = append(m.addrs, addrs)
	var written int
	for _, payload := range payloads {
		written += len(payload)
	}
	return written, nil
}

func (*mockBatchPacketConn) RemoteDestination() string { return "example.org" }
func (*mockBatchPacketConn) Chains() C.Chain           { return nil }
func (*mockBatchPacketConn) ProviderChains() C.Chain   { return nil }
func (*mockBatchPacketConn) Close() error              { return nil }

func (m *mockBatchPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

type mockUnaccountedUpstream struct{ C.PacketConn }

func (w *mockUnaccountedUpstream) Upstream() any { return w.PacketConn }

func TestChitandaSenderDoesNotBypassUnknownWrapper(t *testing.T) {
	wrapped := &mockUnaccountedUpstream{PacketConn: &mockBatchPacketConn{}}
	if got := unwrapBatchWriter(wrapped); got != nil {
		t.Fatal("batch writer bypassed an unaccounted wrapper")
	}
}

type mockDrainPacket struct {
	C.PacketAdapter
	data     []byte
	metadata *C.Metadata
	dropped  atomic.Int32
}

func (p *mockDrainPacket) Data() []byte          { return p.data }
func (p *mockDrainPacket) Metadata() *C.Metadata { return p.metadata }
func (p *mockDrainPacket) Drop()                 { p.dropped.Add(1) }

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

func TestChitandaSenderBatchPreservesTrackerAccounting(t *testing.T) {
	sender := newPacketSender().(*packetSender)
	mockPC := &mockBatchPacketConn{}
	meta := &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("1.2.3.4"), DstPort: 1234}
	tracked := statistic.NewUDPTracker(mockPC, statistic.DefaultManager, meta, nil, 0, 0, true)
	for i := 0; i < 2; i++ {
		sender.ch.push(&mockDrainPacket{data: []byte{1, 2, 3}, metadata: meta})
	}
	sender.drainBatch(tracked, nil)
	if len(mockPC.batches) != 1 || len(mockPC.batches[0]) != 2 {
		t.Fatalf("batch not sent: %v", mockPC.batches)
	}
	if got := tracked.Info().UploadTotal.Load(); got != 6 {
		t.Fatalf("tracked upload = %d, want 6", got)
	}
	_ = tracked.Close()
}

func TestChitandaQueueGlobalByteBudgetReleasesOnPopAndClose(t *testing.T) {
	q := newChitandaPacketQueue()
	q.budget = &chitandaQueueBudget{limit: 2048}
	first := &mockDrainPacket{data: make([]byte, 900)}
	second := &mockDrainPacket{data: make([]byte, 900)}
	q.push(first)
	q.push(second)
	if second.dropped.Load() != 1 || q.length != 1 {
		t.Fatalf("global byte limit not enforced: length=%d dropped=%d", q.length, second.dropped.Load())
	}
	if q.pop() != first || q.budget.used.Load() != 0 {
		t.Fatal("pop did not release queued bytes")
	}
	q.push(second)
	if q.length != 1 {
		t.Fatal("budget was not reusable after pop")
	}
	q.close()
	if q.budget.used.Load() != 0 {
		t.Fatal("close did not release queued bytes")
	}
}

func TestChitandaQueueGlobalByteBudgetSharedAcrossFlows(t *testing.T) {
	budget := &chitandaQueueBudget{limit: 2048}
	first := newChitandaPacketQueue()
	second := newChitandaPacketQueue()
	first.budget, second.budget = budget, budget
	first.push(&mockDrainPacket{data: make([]byte, 900)})
	blocked := &mockDrainPacket{data: make([]byte, 900)}
	second.push(blocked)
	if blocked.dropped.Load() != 1 || second.length != 0 {
		t.Fatal("separate flows exceeded the shared budget")
	}
	first.close()
	second.push(&mockDrainPacket{data: make([]byte, 900)})
	if second.length != 1 {
		t.Fatal("closing one flow did not release shared budget")
	}
	second.close()
	if budget.used.Load() != 0 {
		t.Fatal("shared budget leaked after closing both flows")
	}
}

func TestChitandaQueuePerFlowByteLimit(t *testing.T) {
	q := newChitandaPacketQueue()
	q.budget = &chitandaQueueBudget{limit: chitandaSenderGlobalBytes}
	first := &mockDrainPacket{data: make([]byte, 2<<20)}
	second := &mockDrainPacket{data: make([]byte, 2<<20)}
	q.push(first)
	q.push(second)
	if second.dropped.Load() != 1 || q.length != 1 {
		t.Fatalf("per-flow byte limit not enforced: length=%d dropped=%d", q.length, second.dropped.Load())
	}
	q.close()
	if q.budget.used.Load() != 0 {
		t.Fatal("per-flow close leaked global budget")
	}
}
