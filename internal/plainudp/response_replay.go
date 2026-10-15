package plainudp

import "time"

// ResponseReplayWindow keeps a sparse window of received identities, not a
// dense range of the sequence shared by all server associations. Floors are
// per authenticated timestamp: a sender clock rollback must not make a fresh
// higher-sequence response look older than an unrelated timestamp's floor.
// Call only after authenticated time/session/origin checks; serialize calls.
type ResponseReplayWindow struct {
	seen           map[responseID]struct{}
	ring           []responseID
	next           int
	floors         map[uint64]uint64
	maxTimestamp   uint64
	retiredThrough uint64
	hasRetired     bool
}

type responseID struct{ timestamp, sequence uint64 }

const responseWindowSize = 2048

func (w *ResponseReplayWindow) Accept(sequence, timestamp uint64) bool {
	if sequence == 0 || (w.hasRetired && timestamp <= w.retiredThrough) {
		return false
	}
	// Valid timestamps are within +/- skew of the receiver's clock. Twice
	// skew retains every simultaneously valid timestamp. Retirement never
	// goes backwards: discarded replay state cannot later be resurrected.
	if timestamp > w.maxTimestamp {
		w.maxTimestamp = timestamp
		span := uint64(2 * MaxTimestampSkew / time.Second)
		if timestamp > span {
			w.retiredThrough, w.hasRetired = timestamp-span-1, true
			for ts := range w.floors {
				if ts <= w.retiredThrough {
					delete(w.floors, ts)
				}
			}
		}
	}
	id := responseID{timestamp, sequence}
	if _, ok := w.seen[id]; ok {
		return false
	}
	if floor, ok := w.floors[timestamp]; ok && sequence <= floor {
		return false
	}
	if w.seen == nil {
		w.seen = make(map[responseID]struct{})
		w.floors = make(map[uint64]uint64)
		w.ring = make([]responseID, 0, responseWindowSize)
	}
	if len(w.ring) < responseWindowSize {
		w.ring = append(w.ring, id)
	} else {
		old := w.ring[w.next]
		delete(w.seen, old)
		if !w.hasRetired || old.timestamp > w.retiredThrough {
			w.floors[old.timestamp] = max(w.floors[old.timestamp], old.sequence)
		}
		w.ring[w.next] = id
		w.next = (w.next + 1) % responseWindowSize
	}
	w.seen[id] = struct{}{}
	return true
}
