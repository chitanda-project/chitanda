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

	"github.com/violetaini/chitanda/internal/plainudp"
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

	srv, err := NewServerWithUsers("/api/sync", users, nil, fallback, 1024)
	if err != nil {
		t.Fatal(err)
	}

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

func TestStreamServerMultiUserNativeUDP(t *testing.T) {
	aliceKey := []byte("alice-key-at-least-32-bytes-long!")
	bobKey := []byte("bob---key-at-least-32-bytes-long!")
	users := []UserKey{{Email: "alice", PSK: aliceKey}, {Email: "bob", PSK: bobKey}}

	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		var b [2048]byte
		for {
			n, peer, readErr := echo.ReadFromUDP(b[:])
			if readErr != nil {
				return
			}
			_, _ = echo.WriteToUDP(b[:n], peer)
		}
	}()

	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if _, err := NewPlainUDPServer(listener, nil); err == nil {
		t.Fatal("empty PSK must not create a UDP proxy")
	}
	stream, err := NewStreamServerWithUsers(users, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err := stream.AttachUDP(listener); err != nil {
		t.Fatal(err)
	}
	stream.UDPServer().SetResolveUDPForTest(func(_ context.Context, address string) (*net.UDPAddr, error) {
		return net.ResolveUDPAddr("udp", address)
	})

	for _, tc := range []struct {
		name string
		key  []byte
	}{{"alice", aliceKey}, {"bob", bobKey}} {
		t.Run(tc.name, func(t *testing.T) {
			codec, err := plainudp.NewCodec(tc.key)
			if err != nil {
				t.Fatal(err)
			}
			client, err := net.ListenUDP("udp", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			// Both clients intentionally use the same session ID and first sequence.
			packet, err := codec.EncodePacket(nil, plainudp.DirClientToServer, 42, echo.LocalAddr().String(), []byte(tc.name), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.WriteToUDP(packet, listener.LocalAddr().(*net.UDPAddr)); err != nil {
				t.Fatal(err)
			}
			var response [2048]byte
			_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _, err := client.ReadFromUDP(response[:])
			if err != nil {
				t.Fatal(err)
			}
			sid, _, payload, _, _, err := codec.DecodePacket(response[:n], plainudp.DirServerToClient, time.Now())
			if err != nil || sid != 42 || string(payload) != tc.name {
				t.Fatalf("user response mismatch: sid=%d payload=%q err=%v", sid, payload, err)
			}
		})
	}

	// An unauthenticated client cannot use the old empty-key behavior.
	badCodec, err := plainudp.NewCodec(nil)
	if err != nil {
		t.Fatal(err)
	}
	badClient, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer badClient.Close()
	badPacket, err := badCodec.EncodePacket(nil, plainudp.DirClientToServer, 43, echo.LocalAddr().String(), []byte("unauthorized"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := badClient.WriteToUDP(badPacket, listener.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	_ = badClient.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	var response [2048]byte
	if _, _, err := badClient.ReadFromUDP(response[:]); err == nil {
		t.Fatal("empty-key datagram reached the UDP proxy")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("expected silent drop, got %v", err)
	}
}

func TestMultiUserConstructorsRejectAmbiguousKeys(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	for name, users := range map[string][]UserKey{
		"missing":          nil,
		"short key":        {{Email: "alice", PSK: []byte("short")}},
		"missing identity": {{PSK: key}, {Email: "bob", PSK: []byte("fedcba9876543210fedcba9876543210")}},
		"duplicate email":  {{Email: "Alice", PSK: key}, {Email: "alice", PSK: []byte("fedcba9876543210fedcba9876543210")}},
		"duplicate key":    {{Email: "alice", PSK: key}, {Email: "bob", PSK: key}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewServerWithUsers("/api/sync", users, nil, nil, 1024); err == nil {
				t.Fatal("HTTP constructor accepted ambiguous users")
			}
			if _, err := NewStreamServerWithUsers(users, "", nil, nil); err == nil {
				t.Fatal("RawStream constructor accepted ambiguous users")
			}
		})
	}
	users := []UserKey{{Email: "alice", PSK: append([]byte(nil), key...)}}
	srv, err := NewServerWithUsers("/api/sync", users, nil, nil, 1024)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := NewStreamServerWithUsers(users, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	users[0].PSK[0] ^= 0xff
	if srv.users[0].PSK[0] != key[0] || stream.users[0].PSK[0] != key[0] {
		t.Fatal("constructor retained caller-owned mutable key bytes")
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
	srv, err := NewServerWithUsers("/api/sync", users, nil, nil, 1024)
	if err != nil {
		t.Fatal(err)
	}
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
	streamSrv, err := NewStreamServerWithUsers(users, "srv-01", nil, func(ctx context.Context, network, address string) (net.Conn, error) {
		u, ok := UserFromContext(ctx)
		if ok && u != nil {
			mu.Lock()
			lastDialedUser = u
			mu.Unlock()
		}
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	})
	if err != nil {
		t.Fatal(err)
	}
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
