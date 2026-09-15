package server

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/violetaini/chitanda/pkg/auth"
	"github.com/violetaini/chitanda/internal/frame"
	"github.com/violetaini/chitanda/internal/h1session"
	"github.com/violetaini/chitanda/internal/target"
)

var copyBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 256<<10)
		return &b
	},
}

const (
	headerTarget    = "X-Session-Target"
	headerTimestamp = "X-Session-Time"
	headerNonce     = "X-Session-Nonce"
	headerSignature = "X-Session-Auth"
	headerMode      = "X-Session-Mode"
	headerSessionOK = "X-Session-OK"
	headerFraming   = "X-Session-Framing"
)

// Server implements the my_xray inbound handler
type Server struct {
	path            string
	psk             []byte
	replays         *auth.ReplayCache
	fallback        http.Handler
	udpTargetBuffer int
	dialTarget      func(ctx context.Context, address string) (net.Conn, error)
}

// NewServer creates a new Server instance
func NewServer(path string, psk []byte, replays *auth.ReplayCache, fallback http.Handler, udpTargetBuffer int) *Server {
	return &Server{
		path:            path,
		psk:             psk,
		replays:         replays,
		fallback:        fallback,
		udpTargetBuffer: udpTargetBuffer,
		dialTarget:      target.DialContext,
	}
}

// SetDialTargetForTest allows overriding upstream dialer in tests (e.g. for loopback echo servers).
func (s *Server) SetDialTargetForTest(fn func(ctx context.Context, address string) (net.Conn, error)) {
	s.dialTarget = fn
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead && r.URL.Path == s.path && r.Header.Get("X-Carrier-Probe") == "1" {
		timestamp := r.Header.Get(headerTimestamp)
		nonce := r.Header.Get(headerNonce)
		signature := r.Header.Get(headerSignature)
		if err := s.authorize(r, "", timestamp, nonce, signature); err == nil {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set(headerSessionOK, "1")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// Unauthenticated probe: route directly to fallback to prevent active probing oracle!
		s.serveFallback(w, r)
		return
	}
	if r.ProtoMajor == 3 {
		s.serveHTTP3(w, r)
		return
	}
	if r.ProtoMajor == 1 && r.Method == http.MethodPost && r.URL.Path == s.path {
		s.servePlainH1(w, r)
		return
	}
	if r.URL.Path != s.path || r.Method != http.MethodPost || r.ProtoMajor != 2 {
		s.serveFallback(w, r)
		return
	}
	targetAddress := r.Header.Get(headerTarget)
	timestamp := r.Header.Get(headerTimestamp)
	nonce := r.Header.Get(headerNonce)
	signature := r.Header.Get(headerSignature)
	if err := s.authorize(r, targetAddress, timestamp, nonce, signature); err != nil {
		if errors.Is(err, errReplayDetected) {
			// Fast-fail on replays to prevent DoS amplification (don't dial fallback)
			// Returning standard HTTP error mimics proxy error or fallback error
			// without the huge cost of a real upstream TLS connection.
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		s.serveFallback(w, r)
		return
	}

	upstream, err := s.dialTarget(r.Context(), targetAddress)
	if err != nil {
		log.Printf("authenticated upstream dial failed")
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
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

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
		ar := &activityReader{r: r.Body, onActivity: signalActivity}
		_, err := io.CopyBuffer(upstream, ar, *bufPtr)
		closeWriteConn(upstream)
		uploadDone <- err
	}()

	go func() {
		var err error
		if useFraming {
			ar := &activityReader{r: upstream, onActivity: signalActivity}
			err = frame.CopyAsDataFramesAndClose(flushWriter{w: w}, ar)
		} else {
			bufPtr := copyBufferPool.Get().(*[]byte)
			defer copyBufferPool.Put(bufPtr)
			ar := &activityReader{r: upstream, onActivity: signalActivity}
			_, err = io.CopyBuffer(flushWriter{w: w}, ar, *bufPtr)
		}
		downloadDone <- err
	}()

	idleTimer := time.NewTimer(DefaultIdleTimeout)
	defer idleTimer.Stop()

	var uploadFinished, downloadFinished bool

	for !uploadFinished || !downloadFinished {
		select {
		case <-r.Context().Done():
			_ = upstream.Close()
			return
		case <-activityCh:
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(DefaultIdleTimeout)
		case <-idleTimer.C:
			_ = upstream.Close()
			return
		case <-uploadDone:
			uploadFinished = true
		case <-downloadDone:
			downloadFinished = true
			if !uploadFinished {
				drainTimer := time.NewTimer(DefaultDrainTimeout)
				defer drainTimer.Stop()
				for !uploadFinished {
					select {
					case <-uploadDone:
						uploadFinished = true
					case <-activityCh:
						if !drainTimer.Stop() {
							select {
							case <-drainTimer.C:
							default:
							}
						}
						drainTimer.Reset(DefaultDrainTimeout)
					case <-drainTimer.C:
						_ = upstream.Close()
						return
					case <-r.Context().Done():
						_ = upstream.Close()
						return
					}
				}
			}
		}
	}
	_ = upstream.Close()
}

func (s *Server) authorize(r *http.Request, targetAddress, timestamp, nonce, signature string) error {
	mode := r.Header.Get(headerMode)
	if mode == "" {
		mode = modeTCPv2
	}
	now := time.Now()
	if !auth.Verify(s.psk, mode, r.Method, r.URL.Path, targetAddress, timestamp, nonce, signature, now) {
		return errInvalidSignature
	}
	if s.replays != nil {
		accepted, err := s.replays.Accept(nonce, now)
		if err != nil {
			log.Printf("replay cache unavailable")
		}
		if !accepted || err != nil {
			return errReplayDetected
		}
	}
	return nil
}

func (s *Server) servePlainH1(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	_ = rc.EnableFullDuplex()

	var clientHello [h1session.ClientHelloSize]byte
	if _, err := io.ReadFull(r.Body, clientHello[:]); err != nil {
		s.serveFallback(w, r)
		return
	}

	now := time.Now()
	clientNonce, ts, err := h1session.VerifyClientHello(s.psk, clientHello[:], now)
	if err != nil {
		s.serveFallback(w, r)
		return
	}

	nonceHex := hex.EncodeToString(clientNonce[:])
	if s.replays != nil {
		accepted, replayErr := s.replays.Accept(nonceHex, now)
		if replayErr != nil {
			log.Printf("replay cache error in plain-h1: %v", replayErr)
		}
		if !accepted || replayErr != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
	}

	// 1. Derive 0-RTT key
	k0RTT, err := h1session.Derive0RTTKey(s.psk, ts, clientNonce)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 2. Derive 1-RTT keys and ServerHello
	serverHello, clientKey, serverKey, err := h1session.CreateServerHello(s.psk, clientNonce)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 3. Send 200 OK + ServerHello
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(serverHello); err != nil {
		return
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	// 4. Read 0-RTT OPEN frame from Chunk 2
	var wireLenBuf [2]byte
	if _, err := io.ReadFull(r.Body, wireLenBuf[:]); err != nil {
		return
	}
	wireLen := int(binary.BigEndian.Uint16(wireLenBuf[:]))
	if wireLen == 0 || wireLen > h1session.MaxChunkWireLen {
		return
	}

	chunk0RTT := make([]byte, wireLen)
	if _, err := io.ReadFull(r.Body, chunk0RTT); err != nil {
		return
	}

	decryptedOpen, err := h1session.Decrypt0RTTChunk(k0RTT, chunk0RTT)
	if err != nil {
		log.Printf("plain-h1 0-rtt decryption failed: %v", err)
		return
	}

	targetAddress, initialPayload, err := h1session.DecodeOpenFrame(decryptedOpen)
	if err != nil {
		log.Printf("plain-h1 0-rtt invalid open frame: %v", err)
		return
	}

	upstream, err := s.dialTarget(r.Context(), targetAddress)
	if err != nil {
		log.Printf("authenticated plain-h1 upstream dial failed: %v", err)
		return
	}
	defer upstream.Close()

	if len(initialPayload) > 0 {
		if _, err := upstream.Write(initialPayload); err != nil {
			return
		}
	}

	// 5. Upgrade to 1-RTT full-duplex stream
	decStream, err := h1session.NewAEADStream(clientKey, h1session.DirClientToServer)
	if err != nil {
		return
	}
	encStream, err := h1session.NewAEADStream(serverKey, h1session.DirServerToClient)
	if err != nil {
		return
	}

	framedReader := h1session.NewFramedReader(r.Body, decStream)
	framedWriter := h1session.NewFramedWriter(w, encStream)

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
		ar := &activityReader{r: framedReader, onActivity: signalActivity}
		_, err := io.CopyBuffer(upstream, ar, *bufPtr)
		closeWriteConn(upstream)
		uploadDone <- err
	}()

	go func() {
		bufPtr := copyBufferPool.Get().(*[]byte)
		defer copyBufferPool.Put(bufPtr)
		ar := &activityReader{r: upstream, onActivity: signalActivity}
		_, err := io.CopyBuffer(framedWriter, ar, *bufPtr)
		downloadDone <- err
	}()

	idleTimer := time.NewTimer(DefaultIdleTimeout)
	defer idleTimer.Stop()

	var uploadFinished, downloadFinished bool

	for !uploadFinished || !downloadFinished {
		select {
		case <-r.Context().Done():
			_ = upstream.Close()
			return
		case <-activityCh:
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(DefaultIdleTimeout)
		case <-idleTimer.C:
			_ = upstream.Close()
			return
		case <-uploadDone:
			uploadFinished = true
		case <-downloadDone:
			downloadFinished = true
			if !uploadFinished {
				drainTimer := time.NewTimer(DefaultDrainTimeout)
				defer drainTimer.Stop()
				select {
				case <-uploadDone:
					uploadFinished = true
				case <-drainTimer.C:
					_ = upstream.Close()
					return
				case <-r.Context().Done():
					_ = upstream.Close()
					return
				}
			}
		}
	}
	_ = upstream.Close()
}
