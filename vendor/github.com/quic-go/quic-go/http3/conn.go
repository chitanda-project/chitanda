package http3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/quicvarint"
)

const maxQuarterStreamID = 1<<60 - 1

// Bound queued HTTP Datagrams across all streams on one connection. A single
// authenticated UDP association needs far less than this, while the limit
// prevents unauthenticated streams from multiplying their per-stream queues.
const maxQueuedDatagramBytes = 8 << 20

// invalidStreamID is a stream ID that is invalid. The first valid stream ID in QUIC is 0.
const invalidStreamID = quic.StreamID(-1)

// rawConn is an HTTP/3 connection.
// It provides HTTP/3 specific functionality by wrapping a quic.Conn,
// in particular handling of unidirectional HTTP/3 streams, SETTINGS and datagrams.
type rawConn struct {
	conn *quic.Conn

	logger *slog.Logger

	enableDatagrams bool

	streamMx            sync.Mutex
	streams             map[quic.StreamID]*stateTrackingStream
	queuedDatagramBytes atomic.Int64

	rcvdControlStr      atomic.Bool
	rcvdQPACKEncoderStr atomic.Bool
	rcvdQPACKDecoderStr atomic.Bool
	controlStrHandler   func(*quic.ReceiveStream, *frameParser) // is called *after* the SETTINGS frame was parsed

	onStreamsEmpty func()

	settings         *Settings
	receivedSettings chan struct{}

	qlogger   qlogwriter.Recorder
	qloggerWG sync.WaitGroup // tracks goroutines that may produce qlog events
}

func newRawConn(
	quicConn *quic.Conn,
	enableDatagrams bool,
	onStreamsEmpty func(),
	controlStrHandler func(*quic.ReceiveStream, *frameParser),
	qlogger qlogwriter.Recorder,
	logger *slog.Logger,
) *rawConn {
	c := &rawConn{
		conn:              quicConn,
		logger:            logger,
		enableDatagrams:   enableDatagrams,
		receivedSettings:  make(chan struct{}),
		streams:           make(map[quic.StreamID]*stateTrackingStream),
		qlogger:           qlogger,
		onStreamsEmpty:    onStreamsEmpty,
		controlStrHandler: controlStrHandler,
	}
	if qlogger != nil {
		context.AfterFunc(quicConn.Context(), c.closeQlogger)
	}
	return c
}

func (c *rawConn) OpenUniStream() (*quic.SendStream, error) {
	return c.conn.OpenUniStream()
}

// openControlStream opens the control stream and sends the SETTINGS frame.
// It returns the control stream (needed by the server for sending GOAWAY later).
func (c *rawConn) openControlStream(settings *settingsFrame) (*quic.SendStream, error) {
	c.qloggerWG.Add(1)
	defer c.qloggerWG.Done()

	str, err := c.conn.OpenUniStream()
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, 64)
	b = quicvarint.Append(b, streamTypeControlStream)
	b = settings.Append(b)
	if c.qlogger != nil {
		sf := qlog.SettingsFrame{
			MaxFieldSectionSize: settings.MaxFieldSectionSize,
			Other:               maps.Clone(settings.Other),
		}
		if settings.Datagram {
			sf.Datagram = pointer(true)
		}
		if settings.ExtendedConnect {
			sf.ExtendedConnect = pointer(true)
		}
		c.qlogger.RecordEvent(qlog.FrameCreated{
			StreamID: str.StreamID(),
			Raw:      qlog.RawInfo{Length: len(b)},
			Frame:    qlog.Frame{Frame: sf},
		})
	}
	if _, err := str.Write(b); err != nil {
		return nil, err
	}
	return str, nil
}

func (c *rawConn) TrackStream(str *quic.Stream) *stateTrackingStream {
	hstr := newStateTrackingStream(
		str,
		c,
		func(ctx context.Context, b []byte) error { return c.sendDatagramContext(ctx, str.StreamID(), b) },
		func(ctx context.Context, datagrams [][]byte) error {
			return c.sendDatagramsContext(ctx, str.StreamID(), datagrams)
		},
	)

	c.streamMx.Lock()
	c.streams[str.StreamID()] = hstr
	c.qloggerWG.Add(1)
	c.streamMx.Unlock()
	return hstr
}

func (c *rawConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *rawConn) ConnectionState() quic.ConnectionState {
	return c.conn.ConnectionState()
}

func (c *rawConn) clearStream(id quic.StreamID) {
	c.streamMx.Lock()
	defer c.streamMx.Unlock()

	if _, ok := c.streams[id]; ok {
		delete(c.streams, id)
		c.qloggerWG.Done()
	}
	if len(c.streams) == 0 {
		c.onStreamsEmpty()
	}
}

func (c *rawConn) reserveDatagram(size int) bool {
	for {
		current := c.queuedDatagramBytes.Load()
		if size < 0 || current+int64(size) > maxQueuedDatagramBytes {
			return false
		}
		if c.queuedDatagramBytes.CompareAndSwap(current, current+int64(size)) {
			return true
		}
	}
}

func (c *rawConn) releaseDatagram(size int) {
	if size > 0 {
		c.queuedDatagramBytes.Add(-int64(size))
	}
}

func (c *rawConn) hasActiveStreams() bool {
	c.streamMx.Lock()
	defer c.streamMx.Unlock()

	return len(c.streams) > 0
}

func (c *rawConn) CloseWithError(code quic.ApplicationErrorCode, msg string) error {
	return c.conn.CloseWithError(code, msg)
}

func (c *rawConn) handleUnidirectionalStream(str *quic.ReceiveStream, isServer bool) {
	c.qloggerWG.Add(1)
	defer c.qloggerWG.Done()

	streamType, err := quicvarint.Read(quicvarint.NewReader(str))
	if err != nil {
		if c.logger != nil {
			c.logger.Debug("reading stream type on stream failed", "stream ID", str.StreamID(), "error", err)
		}
		return
	}
	// We're only interested in the control stream here.
	switch streamType {
	case streamTypeControlStream:
	case streamTypeQPACKEncoderStream:
		if isFirst := c.rcvdQPACKEncoderStr.CompareAndSwap(false, true); !isFirst {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate QPACK encoder stream")
		}
		// Our QPACK implementation doesn't use the dynamic table yet.
		return
	case streamTypeQPACKDecoderStream:
		if isFirst := c.rcvdQPACKDecoderStr.CompareAndSwap(false, true); !isFirst {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate QPACK decoder stream")
		}
		// Our QPACK implementation doesn't use the dynamic table yet.
		return
	case streamTypePushStream:
		if isServer {
			// only the server can push
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "")
		} else {
			// we never increased the Push ID, so we don't expect any push streams
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeIDError), "")
		}
		return
	default:
		str.CancelRead(quic.StreamErrorCode(ErrCodeStreamCreationError))
		return
	}
	// Only a single control stream is allowed.
	if isFirstControlStr := c.rcvdControlStr.CompareAndSwap(false, true); !isFirstControlStr {
		c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate control stream")
		return
	}
	c.handleControlStream(str)
}

func (c *rawConn) handleControlStream(str *quic.ReceiveStream) {
	fp := &frameParser{closeConn: c.conn.CloseWithError, r: str, streamID: str.StreamID()}
	f, err := fp.ParseNext(c.qlogger)
	if err != nil {
		var serr *quic.StreamError
		if err == io.EOF || errors.As(err, &serr) {
			c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeClosedCriticalStream), "")
			return
		}
		c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameError), "")
		return
	}
	sf, ok := f.(*settingsFrame)
	if !ok {
		c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeMissingSettings), "")
		return
	}
	c.settings = &Settings{
		EnableDatagrams:       sf.Datagram,
		EnableExtendedConnect: sf.ExtendedConnect,
		Other:                 sf.Other,
	}
	close(c.receivedSettings)
	if sf.Datagram {
		// If datagram support was enabled on our side as well as on the server side,
		// we can expect it to have been negotiated both on the transport and on the HTTP/3 layer.
		// Note: ConnectionState() will block until the handshake is complete (relevant when using 0-RTT).
		if c.enableDatagrams && !c.ConnectionState().SupportsDatagrams.Remote {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeSettingsError), "missing QUIC Datagram support")
			return
		}
		c.qloggerWG.Go(func() {
			if err := c.receiveDatagrams(); err != nil {
				c.closeDatagramReceivers(err)
				if c.logger != nil {
					c.logger.Debug("receiving datagrams failed", "error", err)
				}
			}
		})
	}

	if c.controlStrHandler != nil {
		c.controlStrHandler(str, fp)
	}
}

func (c *rawConn) closeDatagramReceivers(err error) {
	if err == nil {
		err = errors.New("HTTP Datagram receive loop stopped")
	}
	c.streamMx.Lock()
	streams := make([]*stateTrackingStream, 0, len(c.streams))
	for _, stream := range c.streams {
		streams = append(streams, stream)
	}
	c.streamMx.Unlock()
	// closeReceive can clear a fully closed stream and take streamMx. Never
	// call it while holding the connection's stream map lock.
	for _, stream := range streams {
		stream.closeReceive(err)
	}
}

func (c *rawConn) sendDatagramContext(ctx context.Context, streamID quic.StreamID, b []byte) error {
	// TODO: this creates a lot of garbage and an additional copy
	data := make([]byte, 0, len(b)+8)
	quarterStreamID := uint64(streamID / 4)
	data = quicvarint.Append(data, uint64(streamID/4))
	data = append(data, b...)
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.DatagramCreated{
			QuarterStreamID: quarterStreamID,
			Raw: qlog.RawInfo{
				Length:        len(data),
				PayloadLength: len(b),
			},
		})
	}
	return c.conn.SendDatagramNoCopyContext(ctx, data)
}

func (c *rawConn) sendDatagramsContext(ctx context.Context, streamID quic.StreamID, datagrams [][]byte) error {
	quarterStreamID := uint64(streamID / 4)
	prefix := quicvarint.Append(nil, quarterStreamID)
	totalSize := 0
	for _, datagram := range datagrams {
		totalSize += len(prefix) + len(datagram)
	}
	dataBuffer := make([]byte, totalSize)
	payloads := make([][]byte, len(datagrams))
	offset := 0
	for i, datagram := range datagrams {
		end := offset + len(prefix) + len(datagram)
		data := dataBuffer[offset:end:end]
		copy(data, prefix)
		copy(data[len(prefix):], datagram)
		payloads[i] = data
		offset = end
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.DatagramCreated{
				QuarterStreamID: quarterStreamID,
				Raw:             qlog.RawInfo{Length: len(data), PayloadLength: len(datagram)},
			})
		}
	}
	return c.conn.SendDatagramsNoCopyContext(ctx, payloads)
}

func (c *rawConn) receiveDatagrams() error {
	var datagrams [32][]byte
	var lastStreamID quic.StreamID = invalidStreamID
	var lastStream *stateTrackingStream
	for {
		count, receiveErr := c.conn.ReceiveDatagrams(context.Background(), datagrams[:])
		if count < 0 || count > len(datagrams) {
			return fmt.Errorf("invalid datagram batch size: %d", count)
		}
		var pendingStream *stateTrackingStream
		var pending [][]byte
		flush := func() {
			if pendingStream != nil && len(pending) > 0 {
				pendingStream.enqueueDatagrams(pending)
			}
			pendingStream = nil
			pending = pending[:0]
		}
		for i := range count {
			b := datagrams[i]
			quarterStreamID, n, err := quicvarint.Parse(b)
			if err != nil {
				c.CloseWithError(quic.ApplicationErrorCode(ErrCodeDatagramError), "")
				return fmt.Errorf("could not read quarter stream id: %w", err)
			}
			if c.qlogger != nil {
				c.qlogger.RecordEvent(qlog.DatagramParsed{
					QuarterStreamID: quarterStreamID,
					Raw: qlog.RawInfo{
						Length:        len(b),
						PayloadLength: len(b) - n,
					},
				})
			}
			if quarterStreamID > maxQuarterStreamID {
				c.CloseWithError(quic.ApplicationErrorCode(ErrCodeDatagramError), "")
				return fmt.Errorf("invalid quarter stream id: %d", quarterStreamID)
			}
			streamID := quic.StreamID(4 * quarterStreamID)
			var dg *stateTrackingStream
			if streamID == lastStreamID && lastStream != nil {
				dg = lastStream
			} else {
				c.streamMx.Lock()
				dg = c.streams[streamID]
				c.streamMx.Unlock()
				if dg != nil {
					lastStreamID = streamID
					lastStream = dg
				} else {
					lastStreamID = invalidStreamID
					lastStream = nil
				}
			}
			if dg == nil {
				continue
			}
			if pendingStream != dg {
				flush()
				pendingStream = dg
			}
			pending = append(pending, b[n:])
		}
		flush()
		for i := range count {
			datagrams[i] = nil
		}
		if receiveErr != nil {
			return receiveErr
		}
	}
}

// ReceivedSettings returns a channel that is closed once the peer's SETTINGS frame was received.
// Settings can be optained from the Settings method after the channel was closed.
func (c *rawConn) ReceivedSettings() <-chan struct{} { return c.receivedSettings }

// Settings returns the settings received on this connection.
// It is only valid to call this function after the channel returned by ReceivedSettings was closed.
func (c *rawConn) Settings() *Settings { return c.settings }

// closeQlogger waits for all goroutines that may produce qlog events to finish,
// then closes the qlogger.
func (c *rawConn) closeQlogger() {
	if c.qlogger == nil {
		return
	}
	c.qloggerWG.Wait()
	c.qlogger.Close()
}
