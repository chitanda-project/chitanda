package server

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/ipv4"

	"github.com/violetaini/chitanda/internal/auth"
	"github.com/violetaini/chitanda/internal/frame"
	"github.com/violetaini/chitanda/internal/quicconfig"
	"github.com/violetaini/chitanda/internal/target"
)

const (
	modeTCPv2          = "tcp-v2"
	modeUDPv2          = "udp-v2"
	udpAuthName        = "udp-association"
	privateOpenTimeout = 15 * time.Second
)

func NewHTTP3Server(handler http.Handler, tlsConfig *tls.Config, initialPacketSize uint16) *http3.Server {
	return &http3.Server{
		TLSConfig:       tlsConfig,
		QUICConfig:      quicconfig.Server(initialPacketSize),
		Handler:         handler,
		EnableDatagrams: true,
		MaxHeaderBytes:  16 << 10,
		IdleTimeout:     3 * time.Minute,
	}
}

func newHTTP3Server(address string, handler http.Handler, ticketKeyFile, certFile, keyFile string, initialPacketSize uint16, strictSNI string) (*http3.Server, error) {
	ticketKey, err := auth.LoadPSK(ticketKeyFile)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	var key [32]byte
	copy(key[:], ticketKey[:32])
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			if strictSNI != "" {
				if !strings.EqualFold(chi.ServerName, strictSNI) {
					log.Printf("HTTP/3 blocked connection from %v due to strict SNI mismatch: got %q, want %q", chi.Conn.RemoteAddr(), chi.ServerName, strictSNI)
					return nil, errors.New("strict SNI mismatch")
				}
			} else {
				if chi.ServerName == "" {
					log.Printf("HTTP/3 blocked connection from %v due to missing SNI", chi.Conn.RemoteAddr())
					return nil, errors.New("missing SNI")
				}
			}
			return nil, nil
		},
	}
	tlsConfig.SetSessionTicketKeys([][32]byte{key})
	server := NewHTTP3Server(handler, tlsConfig, initialPacketSize)
	server.Addr = address
	return server, nil
}

func (s *Server) serveHTTP3(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != s.path {
		s.serveFallback(w, r)
		return
	}
	targetAddress := r.Header.Get(headerTarget)
	timestamp := r.Header.Get(headerTimestamp)
	nonce := r.Header.Get(headerNonce)
	signature := r.Header.Get(headerSignature)
	switch {
	case r.Method == http.MethodGet && r.Header.Get(headerMode) == modeTCPv2:
		matchedUser, err := s.authorize(r, targetAddress, timestamp, nonce, signature)
		if err != nil {
			if errors.Is(err, errReplayDetected) {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}
			s.serveFallback(w, r)
			return
		}
		r = r.WithContext(ContextWithUser(r.Context(), matchedUser))
		s.serveHTTP3TCP(w, r, targetAddress)
	case r.Method == http.MethodConnect && r.Proto == "connect-udp" && r.Header.Get(headerMode) == modeUDPv2:
		if targetAddress != udpAuthName {
			s.serveFallback(w, r)
			return
		}
		matchedUser, err := s.authorize(r, targetAddress, timestamp, nonce, signature)
		if err != nil {
			if errors.Is(err, errReplayDetected) {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}
			s.serveFallback(w, r)
			return
		}
		r = r.WithContext(ContextWithUser(r.Context(), matchedUser))
		s.serveHTTP3UDP(w, r)
	default:
		s.serveFallback(w, r)
	}

}

func (s *Server) serveHTTP3TCP(w http.ResponseWriter, r *http.Request, targetAddress string) {
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		http.Error(w, "HTTP/3 stream unavailable", http.StatusInternalServerError)
		return
	}

	// Auth already validated by caller. Dial upstream.
	var upstream net.Conn
	var err error
	if s.dialTarget != nil {
		upstream, err = s.dialTarget(r.Context(), targetAddress)
	} else {
		upstream, err = target.DialContext(r.Context(), targetAddress)
	}
	if err != nil {
		log.Printf("authenticated HTTP/3 upstream dial failed: %v", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	useFraming := r.Header.Get(headerFraming) == "1" || r.Header.Get(headerMode) == "tcp-h2-framed"
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(headerSessionOK, "1")
	if useFraming {
		w.Header().Set(headerFraming, "1")
	}
	if r.TLS != nil && !r.TLS.HandshakeComplete {
		w.Header().Set("X-Session-Early", "1")
	}
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	stream := streamer.HTTPStream()
	defer func() {
		stream.CancelRead(0)
		_ = stream.Close()
	}()
	activityCh := make(chan struct{}, 64)
	signalActivity := func() {
		select {
		case activityCh <- struct{}{}:
		default:
		}
	}

	uploadDone := make(chan error, 1)
	downloadDone := make(chan error, 1)

	go func() {
		bufPtr := copyBufferPool.Get().(*[]byte)
		defer copyBufferPool.Put(bufPtr)
		var uploadErr error
		if useFraming {
			ar := &activityReader{r: stream, onActivity: signalActivity}
			uploadErr = copyDataFramesToTCP(ar, upstream)
		} else {
			ar := &activityReader{r: stream, onActivity: signalActivity}
			_, uploadErr = io.CopyBuffer(upstream, ar, *bufPtr)
		}
		if uploadErr != nil {
			_ = upstream.Close()
		} else {
			closeWriteConn(upstream)
		}
		uploadDone <- uploadErr
	}()

	go func() {
		var downloadErr error
		if useFraming {
			ar := &activityReader{r: upstream, onActivity: signalActivity}
			downloadErr = frame.CopyAsDataFramesAndClose(stream, ar)
		} else {
			bufPtr := copyBufferPool.Get().(*[]byte)
			defer copyBufferPool.Put(bufPtr)
			ar := &activityReader{r: upstream, onActivity: signalActivity}
			_, downloadErr = io.CopyBuffer(stream, ar, *bufPtr)
		}
		if downloadErr == nil && !useFraming {
			downloadErr = stream.Close() // FIN downlink without canceling upload.
		}
		downloadDone <- downloadErr
	}()

	waitRelay(r.Context(), activityCh, uploadDone, downloadDone, func() {
		_ = upstream.Close()
		stream.CancelRead(0)
		stream.CancelWrite(0)
	})
}

func copyDataFramesToTCP(stream io.Reader, upstream net.Conn) error {
	for {
		header, err := frame.ReadHeader(stream)
		if err != nil {
			return err
		}
		switch header.Type {
		case frame.TypeData:
			if _, err := io.CopyN(upstream, stream, int64(header.Length)); err != nil {
				return err
			}
		case frame.TypeHalfClose:
			if header.Length != 0 {
				return errors.New("HALF_CLOSE frame contains payload")
			}
			if tcp, ok := upstream.(*net.TCPConn); ok {
				return tcp.CloseWrite()
			}
			return nil
		case frame.TypeReset:
			return errors.New("peer reset stream")
		default:
			if _, err := io.CopyN(io.Discard, stream, int64(header.Length)); err != nil {
				return err
			}
		}
	}
}

func (s *Server) serveHTTP3UDP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Capsule-Protocol", "?1")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(headerSessionOK, "1")
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		return
	}
	stream := streamer.HTTPStream()
	defer func() {
		stream.CancelRead(0)
		_ = stream.Close()
	}()
	relay := newUDPRelay(r.Context(), stream, s.udpTargetBuffer)
	relay.dialUDP = s.dialUDP
	defer relay.Close()
	var packetBuffer [udpRelayBatchSize][]byte
	for {
		packets, err := receiveDatagramBatch(r.Context(), stream, packetBuffer[:])
		if err != nil {
			if r.Context().Err() == nil {
				log.Printf("HTTP/3 UDP receive stopped: %v", err)
			}
			return
		}
		if err := relay.ForwardBatch(packets); err != nil {
			log.Printf("HTTP/3 UDP datagram rejected")
		}
		for i := range packets {
			packetBuffer[i] = nil
		}
	}
}

type datagramBatchReceiver interface {
	ReceiveDatagramsInto(context.Context, [][]byte) (int, error)
}

func receiveDatagramBatch(ctx context.Context, stream *http3.Stream, buffer [][]byte) ([][]byte, error) {
	if receiver, ok := any(stream).(datagramBatchReceiver); ok {
		count, err := receiver.ReceiveDatagramsInto(ctx, buffer)
		if count < 0 || count > len(buffer) {
			return nil, errors.New("invalid HTTP Datagram batch size")
		}
		return buffer[:count], err
	}
	packet, err := stream.ReceiveDatagram(ctx)
	if err != nil {
		return nil, err
	}
	buffer[0] = packet
	return buffer[:1], nil
}

type datagramStream interface {
	SendDatagram([]byte) error
}

type datagramBatchStream interface {
	SendDatagrams([][]byte) error
}

type udpTarget struct {
	lastActive atomic.Int64
	address    string
	conn       net.Conn
	batch      *ipv4.PacketConn
	messages   [udpRelayBatchSize]ipv4.Message
}

const udpRelayBatchSize = 64

type udpRelay struct {
	ctx          context.Context
	cancel       context.CancelFunc
	stream       datagramStream
	targetBuffer int
	mu           sync.Mutex
	sendMu       sync.Mutex
	targets      map[string]*udpTarget
	replay       frame.ReplayWindow
	decoder      frame.DatagramCache
	sequence     atomic.Uint64
	waitGroup    sync.WaitGroup
	dialUDP      func(context.Context, string) (net.Conn, error)
	closed       bool
}

func newUDPRelay(ctx context.Context, stream datagramStream, targetBuffers ...int) *udpRelay {
	targetBuffer := 4 << 20
	if len(targetBuffers) > 0 && targetBuffers[0] > 0 {
		targetBuffer = targetBuffers[0]
	}
	ctx, cancel := context.WithCancel(ctx)
	return &udpRelay{ctx: ctx, cancel: cancel, stream: stream, targetBuffer: targetBuffer, targets: make(map[string]*udpTarget)}
}

func (r *udpRelay) Forward(packet []byte) error {
	return r.ForwardBatch([][]byte{packet})
}

func (r *udpRelay) ForwardBatch(packets [][]byte) error {
	var currentTarget *udpTarget
	var payloads [udpRelayBatchSize][]byte
	payloadCount := 0
	var firstErr error
	flush := func() {
		if payloadCount == 0 {
			return
		}
		if err := currentTarget.writeBatch(payloads[:payloadCount]); err != nil && firstErr == nil {
			firstErr = err
			r.removeTarget(currentTarget)
		}
		for i := range payloadCount {
			payloads[i] = nil
		}
		payloadCount = 0
	}

	for _, packet := range packets {
		sequence, address, payload, err := r.decoder.Decode(packet)
		if err != nil || !r.replay.Accept(sequence) {
			if firstErr == nil {
				firstErr = errors.New("invalid or replayed datagram")
			}
			continue
		}
		var targetConn *udpTarget
		if currentTarget != nil && address == currentTarget.address {
			targetConn = currentTarget
		} else {
			targetConn, err = r.target(address)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
		}
		if currentTarget != nil && targetConn != currentTarget {
			flush()
		}
		currentTarget = targetConn
		currentTarget.lastActive.Store(time.Now().UnixNano())
		payloads[payloadCount] = payload
		payloadCount++
		if payloadCount == len(payloads) {
			flush()
		}
	}
	flush()
	return firstErr
}

func (r *udpRelay) target(address string) (*udpTarget, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, net.ErrClosed
	}
	targetConn := r.targets[address]
	r.mu.Unlock()
	if targetConn != nil {
		return targetConn, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, net.ErrClosed
	}
	targetConn = r.targets[address]
	if targetConn == nil {
		if len(r.targets) >= 64 {
			return nil, errors.New("too many UDP targets")
		}
		var connection net.Conn
		var err error
		if r.dialUDP != nil {
			connection, err = r.dialUDP(r.ctx, address)
		} else {
			var resolved *net.UDPAddr
			resolved, err = target.ResolveUDPAddr(r.ctx, address)
			if err == nil {
				connection, err = net.DialUDP("udp", nil, resolved)
			}
		}
		if err != nil {
			return nil, err
		}
		targetConn = &udpTarget{address: address, conn: connection}
		targetConn.lastActive.Store(time.Now().UnixNano())
		if uc, ok := connection.(*net.UDPConn); ok {
			_ = uc.SetReadBuffer(r.targetBuffer)
			_ = uc.SetWriteBuffer(r.targetBuffer)
			if uc.RemoteAddr().(*net.UDPAddr).IP.To4() != nil {
				targetConn.batch = ipv4.NewPacketConn(uc)
				for i := range targetConn.messages {
					targetConn.messages[i].Buffers = make([][]byte, 1)
				}
			}
		}
		r.targets[address] = targetConn
		r.waitGroup.Add(1)
		go r.receive(targetConn)
	}
	return targetConn, nil
}

func (t *udpTarget) writeBatch(payloads [][]byte) error {
	if bw, ok := t.conn.(interface{ WriteBatch([][]byte) error }); ok && len(payloads) > 1 {
		return bw.WriteBatch(payloads)
	}
	if t.batch == nil || len(payloads) == 1 {
		for _, payload := range payloads {
			if _, err := t.conn.Write(payload); err != nil {
				return err
			}
		}
		return nil
	}

	for i, payload := range payloads {
		t.messages[i].Buffers[0] = payload
	}
	written, _ := t.batch.WriteBatch(t.messages[:len(payloads)], 0)
	written = max(0, min(written, len(payloads)))
	var fallbackErr error
	for _, payload := range payloads[written:] {
		if _, err := t.conn.Write(payload); err != nil {
			fallbackErr = err
			break
		}
	}
	for i := range payloads {
		t.messages[i].Buffers[0] = nil
	}
	if fallbackErr != nil {
		return fallbackErr
	}
	return nil
}

func (r *udpRelay) receive(targetConn *udpTarget) {
	defer r.waitGroup.Done()
	defer r.removeTarget(targetConn)
	if targetConn.batch != nil {
		r.receiveBatch(targetConn)
		return
	}
	r.receiveSingle(targetConn)
}

func (r *udpRelay) receiveSingle(targetConn *udpTarget) {
	buffer := make([]byte, 64<<10)
	datagramBuffer := make([]byte, frame.MaxDatagramSize)
	oversizeLogged := false
	for {
		var n int
		var err error
		_ = targetConn.conn.SetReadDeadline(time.Unix(0, targetConn.lastActive.Load()).Add(time.Minute))
		address := targetConn.conn.RemoteAddr().String()
		if reader, ok := targetConn.conn.(interface {
			ReadFrom([]byte) (int, net.Addr, error)
		}); ok {
			var from net.Addr
			n, from, err = reader.ReadFrom(buffer)
			if from != nil {
				address = from.String()
			}
		} else {
			n, err = targetConn.conn.Read(buffer)
		}
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() && time.Since(time.Unix(0, targetConn.lastActive.Load())) < time.Minute && r.ctx.Err() == nil {
				continue
			}
			return
		}
		targetConn.lastActive.Store(time.Now().UnixNano())
		if n > frame.MaxDatagramPayload {
			continue
		}
		packet, err := frame.EncodeDatagramInto(datagramBuffer, r.sequence.Add(1), address, buffer[:n])
		if err != nil {
			continue
		}
		if err := r.sendResponseBatch([][]byte{packet}, &oversizeLogged); err != nil {
			return
		}
	}
}

func (r *udpRelay) receiveBatch(targetConn *udpTarget) {
	var messages [udpRelayBatchSize]ipv4.Message
	var payloadBuffers [udpRelayBatchSize][]byte
	var datagramBuffers [udpRelayBatchSize][]byte
	var datagrams [udpRelayBatchSize][]byte
	for i := range messages {
		payloadBuffers[i] = make([]byte, frame.MaxDatagramPayload+1)
		messages[i].Buffers = [][]byte{payloadBuffers[i]}
		datagramBuffers[i] = make([]byte, frame.MaxDatagramSize)
	}
	oversizeLogged := false
	for {
		_ = targetConn.conn.SetReadDeadline(time.Unix(0, targetConn.lastActive.Load()).Add(time.Minute))
		count, readErr := targetConn.batch.ReadBatch(messages[:], 0)
		if count < 0 || count > len(messages) {
			return
		}
		datagramCount := 0
		if count > 0 {
			targetConn.lastActive.Store(time.Now().UnixNano())
		}
		for i := range count {
			if messages[i].N > frame.MaxDatagramPayload {
				continue
			}
			packet, err := frame.EncodeDatagramInto(
				datagramBuffers[datagramCount],
				r.sequence.Add(1),
				targetConn.conn.RemoteAddr().String(),
				messages[i].Buffers[0][:messages[i].N],
			)
			if err != nil {
				continue
			}
			datagrams[datagramCount] = packet
			datagramCount++
		}
		if err := r.sendResponseBatch(datagrams[:datagramCount], &oversizeLogged); err != nil {
			return
		}
		for i := range datagramCount {
			datagrams[i] = nil
		}
		if readErr != nil {
			if e, ok := readErr.(net.Error); ok && e.Timeout() && time.Since(time.Unix(0, targetConn.lastActive.Load())) < time.Minute && r.ctx.Err() == nil {
				continue
			}
			return
		}
	}
}

func (r *udpRelay) sendResponseBatch(datagrams [][]byte, oversizeLogged *bool) error {
	if len(datagrams) == 0 {
		return nil
	}
	r.sendMu.Lock()
	defer r.sendMu.Unlock()
	if sender, ok := r.stream.(datagramBatchStream); ok && len(datagrams) > 1 {
		err := sender.SendDatagrams(datagrams)
		if err == nil {
			return nil
		}
		var tooLarge *quic.DatagramTooLargeError
		if !errors.As(err, &tooLarge) {
			return err
		}
	}
	for _, datagram := range datagrams {
		if err := r.stream.SendDatagram(datagram); err != nil {
			var tooLarge *quic.DatagramTooLargeError
			if errors.As(err, &tooLarge) {
				if !*oversizeLogged {
					log.Printf("HTTP/3 UDP response dropped: path datagram limit=%d", tooLarge.MaxDatagramPayloadSize)
					*oversizeLogged = true
				}
				continue
			}
			return err
		}
	}
	return nil
}

func (r *udpRelay) removeTarget(targetConn *udpTarget) {
	r.mu.Lock()
	if r.targets[targetConn.address] == targetConn {
		delete(r.targets, targetConn.address)
	}
	r.mu.Unlock()
	_ = targetConn.conn.Close()
}

func (r *udpRelay) Close() {
	if r.cancel != nil {
		r.cancel()
	}
	r.mu.Lock()
	r.closed = true
	targets := r.targets
	r.targets = make(map[string]*udpTarget)
	r.mu.Unlock()
	for _, targetConn := range targets {
		_ = targetConn.conn.Close()
	}
	r.waitGroup.Wait()
}
