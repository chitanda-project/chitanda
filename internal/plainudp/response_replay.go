package plainudp

// ResponseReplayWindow retains the newest received authenticated responses,
// not a dense range of shared server sequence numbers. The timestamp is part
// of the authenticated identity, allowing a restarted sender to use new
// sequence numbers without accepting a replay of an earlier response.
// Call only after DecodePacket and session/origin checks; callers serialize it.
type ResponseReplayWindow struct {
	seen     map[responseID]struct{}
	heap     []responseID
	floor    responseID
	hasFloor bool
}

type responseID struct{ timestamp, sequence uint64 }

func (a responseID) less(b responseID) bool {
	return a.timestamp < b.timestamp || (a.timestamp == b.timestamp && a.sequence < b.sequence)
}

const responseWindowSize = 2048

func (w *ResponseReplayWindow) Accept(sequence, timestamp uint64) bool {
	id := responseID{timestamp, sequence}
	if sequence == 0 || (w.hasFloor && !w.floor.less(id)) {
		return false
	}
	if _, ok := w.seen[id]; ok {
		return false
	}
	if w.seen == nil {
		w.seen = make(map[responseID]struct{})
		w.heap = make([]responseID, 0, responseWindowSize)
	}
	if len(w.heap) == responseWindowSize {
		old := w.heap[0]
		if !old.less(id) {
			return false
		}
		delete(w.seen, old)
		w.floor, w.hasFloor = old, true
		w.heap[0] = id
		for i := 0; ; {
			j := 2*i + 1
			if j >= len(w.heap) {
				break
			}
			if j+1 < len(w.heap) && w.heap[j+1].less(w.heap[j]) {
				j++
			}
			if !w.heap[j].less(w.heap[i]) {
				break
			}
			w.heap[i], w.heap[j] = w.heap[j], w.heap[i]
			i = j
		}
	} else {
		w.heap = append(w.heap, id)
		for i := len(w.heap) - 1; i > 0; {
			p := (i - 1) / 2
			if !w.heap[i].less(w.heap[p]) {
				break
			}
			w.heap[i], w.heap[p] = w.heap[p], w.heap[i]
			i = p
		}
	}
	w.seen[id] = struct{}{}
	return true
}
