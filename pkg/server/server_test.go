package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/chitanda/internal/auth"
	"github.com/violetaini/chitanda/internal/plainudp"
)

func TestServerAuthorizationAndReplay(t *testing.T) {
	psk := []byte("01234567890123456789012345678901") // 32 bytes
	replays := auth.NewReplayCache()
	defer replays.Close()

	fallbackCalled := false
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackCalled = true
		w.WriteHeader(http.StatusNotFound)
	})

	srv := NewServer("/test-path-12345678", psk, replays, fallback, 1024)

	// 1. Test invalid path -> fallback
	req := httptest.NewRequest(http.MethodPost, "/wrong-path", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if !fallbackCalled {
		t.Fatalf("expected fallback for wrong path")
	}
	fallbackCalled = false

	// 2. Test valid signature
	target := "1.1.1.1:80"
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "test-nonce-1"
	sig := auth.Signature(psk, modeTCPv2, http.MethodPost, "/test-path-12345678", target, ts, nonce)

	req = httptest.NewRequest(http.MethodPost, "/test-path-12345678", nil)
	req.ProtoMajor = 2
	req.Header.Set(headerMode, modeTCPv2)
	req.Header.Set(headerTarget, target)
	req.Header.Set(headerTimestamp, ts)
	req.Header.Set(headerNonce, nonce)
	req.Header.Set(headerSignature, sig)

	// Authorize call
	user, err := srv.authorize(req, target, ts, nonce, sig)
	if err != nil {
		t.Fatalf("expected authorization success, got: %v", err)
	}
	if user == nil {
		t.Fatalf("expected non-nil user")
	}

	// 3. Test replay of same nonce -> should return errReplayDetected
	_, err = srv.authorize(req, target, ts, nonce, sig)
	if err != errReplayDetected {
		t.Fatalf("expected errReplayDetected, got: %v", err)
	}


	// 4. Test replay in ServeHTTP -> should return 400 Bad Request directly without fallback
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if fallbackCalled {
		t.Fatalf("expected replay not to trigger fallback")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for replay, got: %d", w.Code)
	}
}

func TestStrictSNI(t *testing.T) {
	cfg := newTLSConfig("example.com")
	if cfg.GetConfigForClient == nil {
		t.Fatalf("expected GetConfigForClient to be configured")
	}

	// Test correct SNI
	chi := &tls.ClientHelloInfo{
		ServerName: "example.com",
	}
	_, err := cfg.GetConfigForClient(chi)
	if err != nil {
		t.Fatalf("expected correct SNI to pass, got: %v", err)
	}

	// Test uppercase / lowercase matching
	chi = &tls.ClientHelloInfo{
		ServerName: "EXAMPLE.COM",
	}
	_, err = cfg.GetConfigForClient(chi)
	if err != nil {
		t.Fatalf("expected case-insensitive SNI to pass, got: %v", err)
	}
}

func TestCarrierProbe(t *testing.T) {
	psk := []byte(strings.Repeat("p", 32))
	srv := NewServer("/test-path", psk, nil, nil, 1024)

	// 1. Authenticated carrier probe
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "probe-nonce-12345"
	sig := auth.Signature(psk, modeTCPv2, http.MethodHead, "/test-path", "", ts, nonce)

	req := httptest.NewRequest(http.MethodHead, "/test-path", nil)
	req.Header.Set("X-Carrier-Probe", "1")
	req.Header.Set(headerMode, modeTCPv2)
	req.Header.Set(headerTimestamp, ts)
	req.Header.Set(headerNonce, nonce)
	req.Header.Set(headerSignature, sig)

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content for authenticated carrier probe, got %d", w.Code)
	}
	if w.Header().Get(headerSessionOK) != "1" {
		t.Fatalf("expected X-Session-OK header on probe response")
	}

	// 2. Unauthenticated carrier probe (must fall back to decoy, NO X-Session-OK leakage!)
	unauthReq := httptest.NewRequest(http.MethodHead, "/test-path", nil)
	unauthReq.Header.Set("X-Carrier-Probe", "1")
	wUnauth := httptest.NewRecorder()
	srv.ServeHTTP(wUnauth, unauthReq)
	if wUnauth.Header().Get(headerSessionOK) == "1" {
		t.Fatalf("unauthenticated probe must NOT return X-Session-OK header")
	}
}

func TestNewFallback(t *testing.T) {
	// 1. Built-in ERP HTML response
	fb, err := NewFallback("", "erp.internal.corp")
	if err != nil {
		t.Fatalf("NewFallback empty: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	fb.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for ERP fallback, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Vanguard Global") {
		t.Fatalf("expected Vanguard Global title in response body")
	}

	// 2. Built-in ERP JSON response
	req = httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("Accept", "application/json")
	w = httptest.NewRecorder()
	fb.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for ERP API JSON, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Vanguard Global") {
		t.Fatalf("expected JSON body to contain organization name")
	}

	// 3. UDS target parsing
	udsFb, err := NewFallback("unix:/tmp/fake-nginx.sock", "site.corp")
	if err != nil {
		t.Fatalf("NewFallback unix socket: %v", err)
	}
	if udsFb == nil {
		t.Fatalf("expected non-nil UDS fallback handler")
	}
}

func TestPlainUDPServer(t *testing.T) {
	psk := []byte(strings.Repeat("u", 32))

	// 1. Local UDP echo server (the upstream destination)
	echoLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP echo: %v", err)
	}
	defer echoLn.Close()
	go func() {
		buf := make([]byte, 1024)
		for {
			n, client, err := echoLn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echoLn.WriteToUDP(buf[:n], client)
		}
	}()

	// 2. Server UDP listener
	srvLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP server: %v", err)
	}
	defer srvLn.Close()

	srv, err := NewPlainUDPServer(srvLn, psk)
	if err != nil {
		t.Fatalf("NewPlainUDPServer: %v", err)
	}
	srv.SetResolveUDPForTest(func(ctx context.Context, address string) (*net.UDPAddr, error) {
		return net.ResolveUDPAddr("udp", address)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = srv.Serve(ctx)
	}()

	// 3. Client sends encrypted plain-udp packet to server
	clientLn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("ListenUDP client: %v", err)
	}
	defer clientLn.Close()

	payload := []byte("UDP ping message")
	codec, _ := plainudp.NewCodec(psk)
	pkt, err := codec.EncodePacket(nil, plainudp.DirClientToServer, 0x8899aabbccddeeff, echoLn.LocalAddr().String(), payload, time.Now())
	if err != nil {
		t.Fatalf("EncodePacket: %v", err)
	}

	if _, err := clientLn.WriteToUDP(pkt, srvLn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("WriteToUDP: %v", err)
	}

	// 4. Client receives encrypted response from server
	recvBuf := make([]byte, 2048)
	_ = clientLn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := clientLn.ReadFromUDP(recvBuf)
	if err != nil {
		t.Fatalf("ReadFromUDP response: %v", err)
	}

	_, targetAddr, decodedPayload, _, _, err := codec.DecodePacket(recvBuf[:n], plainudp.DirServerToClient, time.Now())
	if err != nil {
		t.Fatalf("DecodePacket response: %v", err)
	}

	if targetAddr != echoLn.LocalAddr().String() {
		t.Fatalf("targetAddr = %q, want %q", targetAddr, echoLn.LocalAddr().String())
	}
	if string(decodedPayload) != string(payload) {
		t.Fatalf("decodedPayload = %q, want %q", string(decodedPayload), string(payload))
	}
}

func TestHTTP3_TCPFramingFlag(t *testing.T) {
	// ModeTCPv2 without X-Session-Framing MUST NOT enable private framing in H3 (must be raw streaming)
	req := httptest.NewRequest(http.MethodGet, "/path", nil)
	req.Header.Set(headerMode, modeTCPv2)
	useFraming := req.Header.Get(headerFraming) == "1" || req.Header.Get(headerMode) == "tcp-h2-framed"
	if useFraming {
		t.Fatal("expected useFraming=false for standard tcp-v2 in H3 to match client SDK")
	}

	// Explicit framing mode
	req.Header.Set(headerFraming, "1")
	useFraming = req.Header.Get(headerFraming) == "1" || req.Header.Get(headerMode) == "tcp-h2-framed"
	if !useFraming {
		t.Fatal("expected useFraming=true when X-Session-Framing: 1")
	}
}
