package http3

import (
	"context"
	"errors"
	"os"
	"sync"

	"github.com/quic-go/quic-go"
)

const streamDatagramQueueLen = 256

// Account for the queue slot and slice metadata as well as payload bytes in
// the connection-wide budget. This also bounds streams full of empty frames.
const queuedDatagramAccountingOverhead = 32

// stateTrackingStream is an implementation of quic.Stream that delegates
// to an underlying stream
// it takes care of proxying send and receive errors onto an implementation of
// the errorSetter interface (intended to be occupied by a datagrammer)
// it is also responsible for clearing the stream based on its ID from its
// parent connection, this is done through the streamClearer interface when
// both the send and receive sides are closed
type stateTrackingStream struct {
	*quic.Stream

	sendDatagramContext  func(context.Context, []byte) error
	sendDatagramsContext func(context.Context, [][]byte) error
	hasData              chan struct{}
	recvClosed           chan struct{}
	queue                [][]byte
	queueHead            int
	queueLen             int

	mx      sync.Mutex
	sendErr error
	recvErr error

	clearer streamClearer
}

var _ datagramStream = &stateTrackingStream{}

type streamClearer interface {
	clearStream(quic.StreamID)
	reserveDatagram(int) bool
	releaseDatagram(int)
}

func newStateTrackingStream(
	s *quic.Stream,
	clearer streamClearer,
	sendDatagramContext func(context.Context, []byte) error,
	sendDatagramsContext func(context.Context, [][]byte) error,
) *stateTrackingStream {
	t := &stateTrackingStream{
		Stream:               s,
		clearer:              clearer,
		sendDatagramContext:  sendDatagramContext,
		sendDatagramsContext: sendDatagramsContext,
		hasData:              make(chan struct{}, 1),
		recvClosed:           make(chan struct{}),
	}

	context.AfterFunc(s.Context(), func() {
		t.closeSend(context.Cause(s.Context()))
	})

	return t
}

func (s *stateTrackingStream) closeSend(e error) {
	s.mx.Lock()
	defer s.mx.Unlock()

	// clear the stream the first time both the send
	// and receive are finished
	if s.sendErr == nil {
		if s.recvErr != nil {
			s.clearer.clearStream(s.StreamID())
		}
		s.sendErr = e
	}
}

func (s *stateTrackingStream) closeReceive(e error) {
	s.mx.Lock()
	defer s.mx.Unlock()

	// clear the stream the first time both the send
	// and receive are finished
	if s.recvErr == nil {
		if s.sendErr != nil {
			s.clearer.clearStream(s.StreamID())
		}
		s.recvErr = e
		queuedBytes := 0
		for i := range s.queueLen {
			index := (s.queueHead + i) % len(s.queue)
			queuedBytes += len(s.queue[index]) + queuedDatagramAccountingOverhead
			s.queue[index] = nil
		}
		s.queueHead = 0
		s.queueLen = 0
		s.clearer.releaseDatagram(queuedBytes)
		close(s.recvClosed)
	}
}

func (s *stateTrackingStream) Close() error {
	s.closeSend(errors.New("write on closed stream"))
	return s.Stream.Close()
}

func (s *stateTrackingStream) CancelWrite(e quic.StreamErrorCode) {
	s.closeSend(&quic.StreamError{StreamID: s.StreamID(), ErrorCode: e})
	s.Stream.CancelWrite(e)
}

func (s *stateTrackingStream) Write(b []byte) (int, error) {
	n, err := s.Stream.Write(b)
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		s.closeSend(err)
	}
	return n, err
}

func (s *stateTrackingStream) CancelRead(e quic.StreamErrorCode) {
	s.closeReceive(&quic.StreamError{StreamID: s.StreamID(), ErrorCode: e})
	s.Stream.CancelRead(e)
}

func (s *stateTrackingStream) Read(b []byte) (int, error) {
	n, err := s.Stream.Read(b)
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		s.closeReceive(err)
	}
	return n, err
}

func (s *stateTrackingStream) SendDatagram(b []byte) error {
	return s.SendDatagramContext(context.Background(), b)
}

func (s *stateTrackingStream) SendDatagramContext(ctx context.Context, b []byte) error {
	s.mx.Lock()
	sendErr := s.sendErr
	s.mx.Unlock()
	if sendErr != nil {
		return sendErr
	}

	return s.sendDatagramContext(ctx, b)
}

func (s *stateTrackingStream) SendDatagrams(datagrams [][]byte) error {
	return s.SendDatagramsContext(context.Background(), datagrams)
}

func (s *stateTrackingStream) SendDatagramsContext(ctx context.Context, datagrams [][]byte) error {
	s.mx.Lock()
	sendErr := s.sendErr
	s.mx.Unlock()
	if sendErr != nil {
		return sendErr
	}
	return s.sendDatagramsContext(ctx, datagrams)
}

func (s *stateTrackingStream) signalHasDatagram() {
	select {
	case s.hasData <- struct{}{}:
	default:
	}
}

func (s *stateTrackingStream) enqueueDatagram(data []byte) {
	s.enqueueDatagrams([][]byte{data})
}

func (s *stateTrackingStream) enqueueDatagrams(datagrams [][]byte) {
	s.mx.Lock()
	defer s.mx.Unlock()

	added := false
	for _, data := range datagrams {
		accountedSize := len(data) + queuedDatagramAccountingOverhead
		if s.recvErr != nil || s.queueLen >= streamDatagramQueueLen || !s.clearer.reserveDatagram(accountedSize) {
			continue
		}
		if s.queue == nil {
			s.queue = make([][]byte, 1)
		} else if s.queueLen == len(s.queue) {
			newCapacity := min(len(s.queue)*2, streamDatagramQueueLen)
			grown := make([][]byte, newCapacity)
			for i := range s.queueLen {
				grown[i] = s.queue[(s.queueHead+i)%len(s.queue)]
			}
			s.queue = grown
			s.queueHead = 0
		}
		index := (s.queueHead + s.queueLen) % len(s.queue)
		s.queue[index] = data
		s.queueLen++
		added = true
	}
	if added {
		s.signalHasDatagram()
	}
}

func (s *stateTrackingStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	var datagrams [1][]byte
	count, err := s.ReceiveDatagramsInto(ctx, datagrams[:])
	if err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, errors.New("invalid datagram batch result")
	}
	return datagrams[0], nil
}

func (s *stateTrackingStream) ReceiveDatagramsInto(ctx context.Context, datagrams [][]byte) (int, error) {
	if len(datagrams) < 1 {
		return 0, errors.New("empty datagram batch buffer")
	}
start:
	s.mx.Lock()
	if s.queueLen > 0 {
		batchSize := min(len(datagrams), s.queueLen)
		queuedBytes := 0
		for i := range batchSize {
			index := (s.queueHead + i) % len(s.queue)
			datagrams[i] = s.queue[index]
			queuedBytes += len(s.queue[index]) + queuedDatagramAccountingOverhead
			s.queue[index] = nil
		}
		s.queueHead = (s.queueHead + batchSize) % len(s.queue)
		s.queueLen -= batchSize
		if s.queueLen > 0 {
			s.signalHasDatagram()
		}
		s.mx.Unlock()
		s.clearer.releaseDatagram(queuedBytes)
		return batchSize, nil
	}
	if receiveErr := s.recvErr; receiveErr != nil {
		s.mx.Unlock()
		return 0, receiveErr
	}
	s.mx.Unlock()

	select {
	case <-ctx.Done():
		return 0, context.Cause(ctx)
	case <-s.recvClosed:
		return 0, s.recvErr
	case <-s.hasData:
	}
	goto start
}

func (s *stateTrackingStream) QUICStream() *quic.Stream {
	return s.Stream
}
