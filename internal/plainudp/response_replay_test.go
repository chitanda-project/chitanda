package plainudp

import "testing"

func TestResponseReplaySparseReorderDuplicatesAndFloor(t *testing.T) {
	var w ResponseReplayWindow
	if !w.Accept(5000000, 10) || !w.Accept(1, 10) || w.Accept(1, 10) {
		t.Fatal("sparse/reorder/duplicate")
	}
	for i := uint64(2); i < 4*responseWindowSize; i++ {
		w.Accept(i*10000000, 10)
	}
	if len(w.heap) != responseWindowSize || len(w.seen) != responseWindowSize {
		t.Fatal("unbounded replay state")
	}
	if w.Accept(1, 10) || w.Accept(5000000, 10) || w.Accept(0, 11) {
		t.Fatal("evicted/zero replay accepted")
	}
	// A restarted sender's authenticated newer timestamp is a distinct packet;
	// revisiting an older timestamp cannot resurrect an evicted response.
	if !w.Accept(1, 11) || w.Accept(1, 11) || w.Accept(1, 10) {
		t.Fatal("timestamp identity/replay")
	}
}

func TestResponseReplayEveryAcceptedPacketRemainsRejected(t *testing.T) {
	var w ResponseReplayWindow
	ids := make([]responseID, 0, 8000)
	for i := uint64(1); i <= 8000; i++ {
		id := responseID{100 + i/3000, i * 7919}
		if !w.Accept(id.sequence, id.timestamp) {
			t.Fatal("fresh response rejected")
		}
		ids = append(ids, id)
	}
	for _, id := range ids {
		if w.Accept(id.sequence, id.timestamp) {
			t.Fatalf("accepted replay: %+v", id)
		}
	}
}

func BenchmarkResponseReplayWindow(b *testing.B) {
	var w ResponseReplayWindow
	for i := uint64(1); i <= responseWindowSize; i++ {
		w.Accept(i*4000, 100)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Accept(uint64(i+responseWindowSize+1)*4000, 100)
	}
}
