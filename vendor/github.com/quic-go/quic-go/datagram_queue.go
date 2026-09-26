package quic

import (
	"context"
	"errors"
	"sync"

	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/utils/ringbuffer"
	"github.com/quic-go/quic-go/internal/wire"
)

const (
	maxDatagramSendQueueLen = 8192
	maxDatagramRcvQueueLen  = 2048
)

type datagramQueue struct {
	sendMx    sync.Mutex
	sendQueue ringbuffer.RingBuffer[*wire.DatagramFrame]
	sent      chan struct{} // used to notify Add that a datagram was dequeued

	rcvMx    sync.Mutex
	rcvQueue [][]byte
	rcvHead  int
	rcvLen   int
	rcvd     chan struct{} // used to notify Receive that a new datagram was received

	closeErr   error
	closed     chan struct{}
	closeOnce  sync.Once
	sendClosed bool

	hasData func()

	logger utils.Logger
}

func newDatagramQueue(hasData func(), logger utils.Logger) *datagramQueue {
	return &datagramQueue{
		hasData: hasData,
		rcvd:    make(chan struct{}, 1),
		sent:    make(chan struct{}, 1),
		closed:  make(chan struct{}),
		logger:  logger,
	}
}

// Add queues a new DATAGRAM frame for sending.
// Up to 32 DATAGRAM frames will be queued.
// Once that limit is reached, Add blocks until the queue size has reduced.
func (h *datagramQueue) Add(f *wire.DatagramFrame) error {
	return h.AddContext(context.Background(), f)
}

// AddContext only cancels while waiting for queue capacity. Once accepted,
// the datagram belongs to the connection and cannot be withdrawn.
func (h *datagramQueue) AddContext(ctx context.Context, f *wire.DatagramFrame) error {
	h.sendMx.Lock()

	for {
		if h.sendClosed {
			err := h.closeErr
			h.sendMx.Unlock()
			return err
		}
		if err := ctx.Err(); err != nil {
			h.sendMx.Unlock()
			return err
		}
		if h.sendQueue.Len() < maxDatagramSendQueueLen {
			h.sendQueue.PushBack(f)
			h.sendMx.Unlock()
			h.hasData()
			return nil
		}
		select {
		case <-h.sent: // drain the queue so we don't loop immediately
		default:
		}
		h.sendMx.Unlock()
		select {
		case <-h.closed:
			return h.closeErr
		case <-ctx.Done():
			return ctx.Err()
		case <-h.sent:
		}
		h.sendMx.Lock()
	}
}

// AddBatch atomically queues a batch of DATAGRAM frames and wakes the sender
// once, allowing the packet packer to build a UDP GSO batch.
func (h *datagramQueue) AddBatch(frames []*wire.DatagramFrame) error {
	return h.AddBatchContext(context.Background(), frames)
}

// AddBatchContext atomically accepts or cancels the whole batch.
func (h *datagramQueue) AddBatchContext(ctx context.Context, frames []*wire.DatagramFrame) error {
	if len(frames) == 0 {
		return ctx.Err()
	}
	if len(frames) > maxDatagramSendQueueLen {
		return errors.New("too many datagrams in batch")
	}
	h.sendMx.Lock()
	for {
		if h.sendClosed {
			err := h.closeErr
			h.sendMx.Unlock()
			return err
		}
		if err := ctx.Err(); err != nil {
			h.sendMx.Unlock()
			return err
		}
		if h.sendQueue.Len()+len(frames) <= maxDatagramSendQueueLen {
			for _, frame := range frames {
				h.sendQueue.PushBack(frame)
			}
			h.sendMx.Unlock()
			h.hasData()
			return nil
		}
		select {
		case <-h.sent:
		default:
		}
		h.sendMx.Unlock()
		select {
		case <-h.closed:
			return h.closeErr
		case <-ctx.Done():
			return ctx.Err()
		case <-h.sent:
		}
		h.sendMx.Lock()
	}
}

// Peek gets the next DATAGRAM frame for sending.
// If actually sent out, Pop needs to be called before the next call to Peek.
func (h *datagramQueue) Peek() *wire.DatagramFrame {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	if h.sendQueue.Empty() {
		return nil
	}
	return h.sendQueue.PeekFront()
}

func (h *datagramQueue) Pop() {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	_ = h.sendQueue.PopFront()
	select {
	case h.sent <- struct{}{}:
	default:
	}
}

// HandleDatagramFrame handles a received DATAGRAM frame.
func (h *datagramQueue) HandleDatagramFrame(f *wire.DatagramFrame) {
	h.rcvMx.Lock()
	if h.rcvLen >= maxDatagramRcvQueueLen {
		h.rcvMx.Unlock()
		if h.logger.Debug() {
			h.logger.Debugf("Discarding received DATAGRAM frame (%d bytes payload)", len(f.Data))
		}
		return
	}
	if len(h.rcvQueue) == 0 {
		h.rcvQueue = make([][]byte, 1)
	} else if h.rcvLen == len(h.rcvQueue) {
		newCapacity := min(len(h.rcvQueue)*2, maxDatagramRcvQueueLen)
		grown := make([][]byte, newCapacity)
		for i := range h.rcvLen {
			grown[i] = h.rcvQueue[(h.rcvHead+i)%len(h.rcvQueue)]
		}
		h.rcvQueue = grown
		h.rcvHead = 0
	}
	data := make([]byte, len(f.Data))
	copy(data, f.Data)
	index := (h.rcvHead + h.rcvLen) % len(h.rcvQueue)
	h.rcvQueue[index] = data
	h.rcvLen++
	select {
	case h.rcvd <- struct{}{}:
	default:
	}
	h.rcvMx.Unlock()
}

// Receive gets a received DATAGRAM frame.
func (h *datagramQueue) Receive(ctx context.Context) ([]byte, error) {
	var datagrams [1][]byte
	count, err := h.ReceiveBatch(ctx, datagrams[:])
	if err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, errors.New("invalid datagram batch result")
	}
	return datagrams[0], nil
}

// ReceiveBatch receives one or more queued datagrams without blocking after
// the first payload is available.
func (h *datagramQueue) ReceiveBatch(ctx context.Context, datagrams [][]byte) (int, error) {
	if len(datagrams) == 0 {
		return 0, errors.New("empty datagram batch buffer")
	}
	for {
		h.rcvMx.Lock()
		if h.rcvLen > 0 {
			count := min(len(datagrams), h.rcvLen)
			for i := range count {
				index := (h.rcvHead + i) % len(h.rcvQueue)
				datagrams[i] = h.rcvQueue[index]
				h.rcvQueue[index] = nil
			}
			h.rcvHead = (h.rcvHead + count) % len(h.rcvQueue)
			h.rcvLen -= count
			if h.rcvLen == 0 {
				h.rcvHead = 0
			}
			h.rcvMx.Unlock()
			return count, nil
		}
		h.rcvMx.Unlock()
		select {
		case <-h.rcvd:
			// Recheck the queue after the producer notification.
		case <-h.closed:
			return 0, h.closeErr
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}

func (h *datagramQueue) CloseWithError(e error) {
	h.closeOnce.Do(func() {
		h.sendMx.Lock()
		h.closeErr = e
		h.sendClosed = true
		close(h.closed)
		h.sendMx.Unlock()
	})
}
