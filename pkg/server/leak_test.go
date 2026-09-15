package server

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/client"
)

func TestStreamServer_TargetClosesFirst(t *testing.T) {
	psk := []byte("01234567890123456789012345678901")

	// Upstream server that sends response and closes immediately (like HTTP server)
	targetL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	defer targetL.Close()

	go func() {
		for {
			c, err := targetL.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				buf := make([]byte, 1024)
				n, _ := conn.Read(buf)
				if n > 0 {
					_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
				}
				// Target closes its connection!
				_ = conn.Close()
			}(c)
		}
	}()

	srvL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer srvL.Close()

	srv := NewStreamServer(psk, "", nil, func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	})
	defer srv.Close()

	go func() {
		_ = srv.Serve(srvL)
	}()

	cli, err := client.New(client.Config{
		Server:       srvL.Addr().String(),
		PSK:          psk,
		TCPTransport: client.TCPTransportStream,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := cli.DialContext(ctx, "tcp", targetL.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}

	// Send request
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))

	// Read response
	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	t.Logf("Read %d bytes: %q, err: %v", n, resp[:n], err)

	// Target FIN must reach the client promptly without forcibly closing upload.
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(resp); err != io.EOF {
		t.Fatalf("expected authenticated downlink EOF, got %v", err)
	}
	_ = conn.Close()
	deadline := time.Now().Add(time.Second)
	for srv.activeConns.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if active := srv.activeConns.Load(); active != 0 {
		t.Fatalf("%d active connections after client Close", active)
	}
}

func TestStreamServer_GameBurstRequests_NoFDLeak(t *testing.T) {
	psk := []byte("01234567890123456789012345678901")

	// Target upstream simulating game API server
	targetL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	defer targetL.Close()

	go func() {
		for {
			c, err := targetL.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				buf := make([]byte, 1024)
				n, _ := conn.Read(buf)
				if n > 0 {
					_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{\"status\":\"ok\"}"))
				}
				// Game server closes socket
				_ = conn.Close()
			}(c)
		}
	}()

	srvL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer srvL.Close()

	srv := NewStreamServer(psk, "", nil, func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	})
	defer srv.Close()

	go func() {
		_ = srv.Serve(srvL)
	}()

	cli, err := client.New(client.Config{
		Server:       srvL.Addr().String(),
		PSK:          psk,
		TCPTransport: client.TCPTransportStream,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	defer cli.Close()

	const burstCount = 50
	errCh := make(chan error, burstCount)

	for i := 0; i < burstCount; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			conn, err := cli.DialContext(ctx, "tcp", targetL.Addr().String())
			if err != nil {
				errCh <- err
				return
			}
			_, _ = conn.Write([]byte("POST /api/click HTTP/1.1\r\nContent-Length: 0\r\n\r\n"))
			buf := make([]byte, 1024)
			_, err = conn.Read(buf)
			// Intentionally do NOT close conn immediately to simulate pooled client
			time.AfterFunc(100*time.Millisecond, func() {
				_ = conn.Close()
			})
			errCh <- err
		}()
	}

	for i := 0; i < burstCount; i++ {
		if err := <-errCh; err != nil {
			t.Errorf("burst request failed: %v", err)
		}
	}

	// Allow clients' delayed Close calls and worker cleanup to finish.
	time.Sleep(600 * time.Millisecond)

	active := srv.activeConns.Load()
	t.Logf("Active conns after burst: %d", active)
	if active != 0 {
		t.Errorf("LEAK DETECTED! Server has %d active conns remaining after burst of %d requests!", active, burstCount)
	}
}
