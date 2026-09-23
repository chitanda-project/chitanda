package server

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/auth"
	"github.com/violetaini/chitanda/pkg/client"
)


func TestServerMultiUserHTTP(t *testing.T) {
	users := []UserKey{
		{Email: "alice@chitanda.org", PSK: []byte("alice-key-at-least-32-bytes-long!"), Level: 0},
		{Email: "bob@chitanda.org", PSK: []byte("bob---key-at-least-32-bytes-long!"), Level: 1},
	}

	fallbackCalled := false
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fallback-content"))
	})

	srv := NewServerWithUsers("/api/sync", users, nil, fallback, 1024)

	var lastDialedUser *UserKey
	srv.SetDialTargetForTest(func(ctx context.Context, address string) (net.Conn, error) {
		u, ok := UserFromContext(ctx)
		if ok && u != nil {
			lastDialedUser = u
		}
		// Return loopback pipe
		serverSide, clientSide := net.Pipe()
		go func() {
			defer serverSide.Close()
			_, _ = io.WriteString(serverSide, "echo-response")
		}()
		return clientSide, nil
	})

	// 1. Test Alice request
	{
		target := "1.1.1.1:80"
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		nonce := "alice-nonce-1"
		sig := auth.Signature(users[0].PSK, modeTCPv2, http.MethodPost, "/api/sync", target, ts, nonce)

		req := httptest.NewRequest(http.MethodPost, "/api/sync", nil)
		req.ProtoMajor = 2
		req.Header.Set(headerMode, modeTCPv2)
		req.Header.Set(headerTarget, target)
		req.Header.Set(headerTimestamp, ts)
		req.Header.Set(headerNonce, nonce)
		req.Header.Set(headerSignature, sig)

		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if lastDialedUser == nil || lastDialedUser.Email != "alice@chitanda.org" {
			t.Fatalf("expected alice dial, got: %v", lastDialedUser)
		}
	}

	// 2. Test Bob request
	{
		target := "8.8.8.8:53"
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		nonce := "bob-nonce-1"
		sig := auth.Signature(users[1].PSK, modeTCPv2, http.MethodPost, "/api/sync", target, ts, nonce)

		req := httptest.NewRequest(http.MethodPost, "/api/sync", nil)
		req.ProtoMajor = 2
		req.Header.Set(headerMode, modeTCPv2)
		req.Header.Set(headerTarget, target)
		req.Header.Set(headerTimestamp, ts)
		req.Header.Set(headerNonce, nonce)
		req.Header.Set(headerSignature, sig)

		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if lastDialedUser == nil || lastDialedUser.Email != "bob@chitanda.org" {
			t.Fatalf("expected bob dial, got: %v", lastDialedUser)
		}
	}

	// 3. Test Unknown user request -> triggers Fallback
	{
		fallbackCalled = false
		unknownKey := []byte("unknown-key-at-least-32-bytes-long!")
		target := "1.1.1.1:80"
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		nonce := "unknown-nonce"
		sig := auth.Signature(unknownKey, modeTCPv2, http.MethodPost, "/api/sync", target, ts, nonce)

		req := httptest.NewRequest(http.MethodPost, "/api/sync", nil)
		req.ProtoMajor = 2
		req.Header.Set(headerMode, modeTCPv2)
		req.Header.Set(headerTarget, target)
		req.Header.Set(headerTimestamp, ts)
		req.Header.Set(headerNonce, nonce)
		req.Header.Set(headerSignature, sig)

		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if !fallbackCalled {
			t.Fatalf("expected fallback to be called for unauthorized request")
		}
	}
}

func TestServerMultiUserPlainH1(t *testing.T) {
	users := []UserKey{
		{Email: "alice@chitanda.org", PSK: []byte("alice-key-at-least-32-bytes-long!"), Level: 0},
		{Email: "bob@chitanda.org", PSK: []byte("bob---key-at-least-32-bytes-long!"), Level: 1},
	}

	// 1. Echo upstream
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	// 2. Server
	var lastDialedUser *UserKey
	var mu sync.Mutex
	srv := NewServerWithUsers("/api/sync", users, nil, nil, 1024)
	srv.SetDialTargetForTest(func(ctx context.Context, address string) (net.Conn, error) {
		u, ok := UserFromContext(ctx)
		if ok && u != nil {
			mu.Lock()
			lastDialedUser = u
			mu.Unlock()
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", address)
	})

	httpServer := &http.Server{Handler: srv}
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("http listen: %v", err)
	}
	defer httpLn.Close()
	go func() {
		_ = httpServer.Serve(httpLn)
	}()
	defer httpServer.Close()

	// 3. Client using Bob's PSK
	cli, err := client.New(client.Config{
		Server:       httpLn.Addr().String(),
		Path:         "/api/sync",
		PSK:          users[1].PSK,
		TCPTransport: client.TCPTransportPlainH1,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := cli.DialContext(ctx, "tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatalf("DialContext plain-h1 failed: %v", err)
	}
	defer conn.Close()

	msg := []byte("ping bob plain-h1")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("conn.Write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("io.ReadFull: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
	}

	mu.Lock()
	defer mu.Unlock()
	if lastDialedUser == nil || lastDialedUser.Email != "bob@chitanda.org" {
		t.Fatalf("expected bob dial, got %v", lastDialedUser)
	}
}

func TestStreamServerMultiUser(t *testing.T) {
	users := []UserKey{
		{Email: "alice@chitanda.org", PSK: []byte("alice-key-at-least-32-bytes-long!"), Level: 0},
		{Email: "bob@chitanda.org", PSK: []byte("bob---key-at-least-32-bytes-long!"), Level: 1},
	}

	// 1. Echo upstream
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	// 2. StreamServer
	var lastDialedUser *UserKey
	var mu sync.Mutex
	streamSrv := NewStreamServerWithUsers(users, "srv-01", nil, func(ctx context.Context, network, address string) (net.Conn, error) {
		u, ok := UserFromContext(ctx)
		if ok && u != nil {
			mu.Lock()
			lastDialedUser = u
			mu.Unlock()
		}
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	})
	defer streamSrv.Close()

	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("stream listen: %v", err)
	}
	defer srvLn.Close()
	go func() {
		_ = streamSrv.Serve(srvLn)
	}()

	// 3. Client using Alice's PSK
	cli, err := client.New(client.Config{
		Server:       srvLn.Addr().String(),
		ServerID:     "srv-01",
		PSK:          users[0].PSK,
		TCPTransport: client.TCPTransportStream,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := cli.DialContext(ctx, "tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatalf("DialContext stream failed: %v", err)
	}
	defer conn.Close()

	msg := []byte("ping alice rawstream")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("conn.Write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("io.ReadFull: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
	}

	mu.Lock()
	defer mu.Unlock()
	if lastDialedUser == nil || lastDialedUser.Email != "alice@chitanda.org" {
		t.Fatalf("expected alice dial, got %v", lastDialedUser)
	}
}
