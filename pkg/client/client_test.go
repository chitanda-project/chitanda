package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/violetaini/chitanda/internal/auth"
	"github.com/violetaini/chitanda/pkg/server"
)

func TestConfigValidation(t *testing.T) {
	// Missing PSK / invalid PSK
	_, err := New(Config{Server: "127.0.0.1:11322", ServerName: "example.com", Path: "/test"})
	if err == nil {
		t.Fatal("expected error for missing PSK")
	}

	// Valid config
	psk := []byte("01234567890123456789012345678901")
	c, err := New(Config{
		Server:     "127.0.0.1:11322",
		ServerName: "example.com",
		Path:       "/test",
		PSK:        psk,
	})
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}
	defer c.Close()

	if c.cfg.TCPTransport != TCPTransportH2 {
		t.Fatalf("default TCPTransport = %q, want %q", c.cfg.TCPTransport, TCPTransportH2)
	}
}

func TestSignRequest(t *testing.T) {
	psk := []byte("01234567890123456789012345678901")
	req, err := http.NewRequest(http.MethodPost, "https://example.com/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signRequest(req, psk, "/test", "1.1.1.1:443", ModeTCPv2); err != nil {
		t.Fatal(err)
	}

	target := req.Header.Get(HeaderTarget)
	timestamp := req.Header.Get(HeaderTimestamp)
	nonce := req.Header.Get(HeaderNonce)
	sig := req.Header.Get(HeaderSignature)

	if target != "1.1.1.1:443" {
		t.Fatalf("target = %q, want 1.1.1.1:443", target)
	}
	if !auth.Verify(psk, ModeTCPv2, http.MethodPost, "/test", target, timestamp, nonce, sig, time.Now()) {
		t.Fatal("signature verification failed")
	}
}

func TestH3PoolSizingAndReservation(t *testing.T) {
	psk := []byte("01234567890123456789012345678901")
	tests := []struct {
		name      string
		transport string
		poolSize  int
		wantH3    int
	}{
		{name: "h2 keeps one H3 manager for UDP", transport: TCPTransportH2, poolSize: 3, wantH3: 1},
		{name: "h3 uses configured pool", transport: TCPTransportH3, poolSize: 3, wantH3: 3},
		{name: "auto prepares H3 fallback pool", transport: TCPTransportAuto, poolSize: 3, wantH3: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := New(Config{
				Server:       "127.0.0.1:11322",
				ServerName:   "example.com",
				Path:         "/test",
				PSK:          psk,
				TCPTransport: tt.transport,
				TCPPoolSize:  tt.poolSize,
			})
			if err != nil {
				t.Fatalf("New() error: %v", err)
			}
			defer c.Close()

			if got := len(c.h3Managers); got != tt.wantH3 {
				t.Fatalf("H3 manager count = %d, want %d", got, tt.wantH3)
			}
			if tt.wantH3 < 3 {
				return
			}

			selected := make(map[*h3TransportManager]int)
			for range tt.wantH3 {
				manager := c.reserveH3Manager()
				if manager == nil {
					t.Fatal("pickBestH3Manager() returned nil")
				}
				manager.activeStreams.Add(1)
				selected[manager]++
			}
			for _, manager := range c.h3Managers {
				if selected[manager] != 1 {
					t.Fatalf("carrier selected %d times, want 1", selected[manager])
				}
				manager.activeStreams.Add(-1)
			}
		})
	}
}

func TestClientImplementsInterfaces(t *testing.T) {
	type dialer interface {
		DialContext(ctx context.Context, network, address string) (net.Conn, error)
	}
	type packetListener interface {
		ListenPacket(ctx context.Context) (net.PacketConn, error)
	}

	var _ dialer = (*Client)(nil)
	var _ packetListener = (*Client)(nil)
}

func TestPlainH1EndToEnd(t *testing.T) {
	psk := []byte(strings.Repeat("p", 32))
	replays := auth.NewReplayCache()
	defer replays.Close()

	// 1. Start a local TCP echo server (the upstream destination)
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen echo: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	// 2. Start a local HTTP server running MyXray server
	srvHandler := server.NewServer("/test-plain-h1", psk, replays, nil, 1024)
	srvHandler.SetDialTargetForTest(func(ctx context.Context, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", address)
	})
	httpServer := &http.Server{
		Handler: srvHandler,
	}
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen http: %v", err)
	}
	defer httpLn.Close()
	go func() {
		_ = httpServer.Serve(httpLn)
	}()
	defer httpServer.Close()

	// 3. Create MyXray client in plain-h1 mode
	c, err := New(Config{
		Server:       httpLn.Addr().String(),
		Path:         "/test-plain-h1",
		PSK:          psk,
		TCPTransport: TCPTransportPlainH1,
	})
	if err != nil {
		t.Fatalf("New plain-h1 client: %v", err)
	}
	defer c.Close()

	// 4. Dial the upstream echo target through plain-h1
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := c.DialContext(ctx, "tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatalf("DialContext plain-h1: %v", err)
	}
	defer conn.Close()

	// 5. Send message and verify round-trip
	msg := []byte("Hello Plain-H1 Full-Duplex AEAD Stream!")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("conn.Write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("conn.Read: %v", err)
	}

	if string(buf) != string(msg) {
		t.Fatalf("echoed %q != sent %q", string(buf), string(msg))
	}
}

func TestPlainUDP_ListenPacket(t *testing.T) {
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

	srv, err := server.NewPlainUDPServer(srvLn, psk)
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

	// 3. Client initializes plain-h1 client and calls ListenPacket
	c, err := New(Config{
		Server:       srvLn.LocalAddr().String(),
		Path:         "/test-udp",
		PSK:          psk,
		TCPTransport: TCPTransportPlainH1,
	})
	if err != nil {
		t.Fatalf("New plain-h1 client: %v", err)
	}
	defer c.Close()

	pconn, err := c.ListenPacket(ctx)
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pconn.Close()

	// 4. Send datagram to echoLn via PacketConn
	msg := []byte("Hello Native Plain-UDP Datagram!")
	if _, err := pconn.WriteTo(msg, echoLn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	recvBuf := make([]byte, 2048)
	_ = pconn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, rAddr, err := pconn.ReadFrom(recvBuf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}

	if rAddr.String() != echoLn.LocalAddr().String() {
		t.Fatalf("rAddr = %q, want %q", rAddr.String(), echoLn.LocalAddr().String())
	}
	if string(recvBuf[:n]) != string(msg) {
		t.Fatalf("received %q != expected %q", string(recvBuf[:n]), string(msg))
	}
}

func TestPlainH1_BoundsProtection(t *testing.T) {
	// Test chunkedReader rejection of negative chunk length (prevents slice bounds out of range panic)
	cr := newChunkedReader(bufio.NewReader(strings.NewReader("-10\r\npayload\r\n")))
	buf := make([]byte, 1024)
	_, err := cr.Read(buf)
	if err == nil {
		t.Fatal("expected error reading negative chunk length, got nil")
	}

	// Test chunkedReader rejection of oversized chunk length
	cr2 := newChunkedReader(bufio.NewReader(strings.NewReader("ffffffff\r\npayload\r\n")))
	_, err = cr2.Read(buf)
	if err == nil {
		t.Fatal("expected error reading oversized chunk length, got nil")
	}
}

func TestRawStreamEndToEnd(t *testing.T) {
	psk := []byte(strings.Repeat("k", 32))
	replays := auth.NewReplayCache()
	defer replays.Close()

	// 1. Upstream TCP echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen echo: %v", err)
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

	// 2. Start RawStream server
	streamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen rawstream: %v", err)
	}
	defer streamLn.Close()

	srv := server.NewStreamServer(psk, "test-node", replays, func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", address)
	})
	defer srv.Close()

	go func() {
		_ = srv.Serve(streamLn)
	}()

	// 3. Client in RawStream mode
	c, err := New(Config{
		Server:       streamLn.Addr().String(),
		ServerID:     "test-node",
		PSK:          psk,
		TCPTransport: TCPTransportStream,
	})
	if err != nil {
		t.Fatalf("New rawstream client: %v", err)
	}
	defer c.Close()

	// 4. Dial echo target
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := c.DialContext(ctx, "tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatalf("DialContext rawstream: %v", err)
	}
	defer conn.Close()

	// 5. Send message and verify
	msg := []byte("Hello Polymorphic Handshake & Dynamic Record Sizing RawStream!")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("conn.Write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("conn.Read: %v", err)
	}

	if string(buf) != string(msg) {
		t.Fatalf("got %q, want %q", string(buf), string(msg))
	}
}

func TestH2PaddingEndToEnd(t *testing.T) {
	psk := []byte(strings.Repeat("h2pad", 7)[:32])
	replays := auth.NewReplayCache()
	defer replays.Close()

	// 1. Upstream TCP echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen echo: %v", err)
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

	// 2. Server running MyXray H2
	srvHandler := server.NewServer("/test-h2-pad", psk, replays, nil, 1024)
	srvHandler.SetDialTargetForTest(func(ctx context.Context, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", address)
	})

	ts := httptest.NewUnstartedServer(srvHandler)
	if err := http2.ConfigureServer(ts.Config, &http2.Server{}); err != nil {
		t.Fatalf("ConfigureServer: %v", err)
	}
	ts.TLS = &tls.Config{NextProtos: []string{"h2"}}
	ts.StartTLS()
	defer ts.Close()

	// 3. Client configured in H2 mode
	c, err := New(Config{
		Server:             ts.Listener.Addr().String(),
		ServerName:         "example.com",
		Path:               "/test-h2-pad",
		PSK:                psk,
		TCPTransport:       TCPTransportH2,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("New H2 client: %v", err)
	}
	defer c.Close()

	// 4. Dial echo server via H2
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := c.DialContext(ctx, "tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatalf("DialContext H2: %v", err)
	}
	defer conn.Close()

	// 5. Transfer 1MB of data and verify SHA-256
	dataSize := 1024 * 1024 // 1 MB
	testData := make([]byte, dataSize)
	for i := range testData {
		testData[i] = byte(i * 31)
	}
	sentHasher := sha256.New()
	sentHasher.Write(testData)
	expectedHash := sentHasher.Sum(nil)

	recvHasher := sha256.New()
	errCh := make(chan error, 1)

	go func() {
		_, err := io.CopyN(recvHasher, conn, int64(dataSize))
		errCh <- err
	}()

	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("conn.Write: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("read echo error: %v", err)
	}

	actualHash := recvHasher.Sum(nil)
	if !bytes.Equal(actualHash, expectedHash) {
		t.Fatalf("SHA-256 hash mismatch after 1MB H2 transfer with dynamic padding")
	}
}

func TestH1ChunkReaderBoundary(t *testing.T) {
	// A full 16KB encrypted payload produces 16402 bytes wire format:
	// "4012\r\n<16402 bytes>\r\n0\r\n\r\n"
	payload := bytes.Repeat([]byte("A"), 16402)
	var raw bytes.Buffer
	raw.WriteString("4012\r\n")
	raw.Write(payload)
	raw.WriteString("\r\n0\r\n\r\n")

	cr := newChunkedReader(bufio.NewReader(&raw))
	buf := make([]byte, 32768)
	total := 0
	for {
		n, err := cr.Read(buf)
		total += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("unexpected chunk reading error: %v", err)
		}
	}

	if total != 16402 {
		t.Fatalf("expected to read 16402 bytes, read %d", total)
	}
}
