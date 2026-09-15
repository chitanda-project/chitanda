package client

import (
	"context"
	"github.com/violetaini/chitanda/pkg/server"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHalfCloseAllowsDelayedUpload(t *testing.T) {
	for _, mode := range []string{"stream", "h1", "h2", "h3"} {
		t.Run(mode, func(t *testing.T) {
			psk := []byte(strings.Repeat("x", 32))
			target, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			accepted := make(chan *net.TCPConn, 1)
			go func() {
				c, e := target.AcceptTCP()
				if e == nil {
					accepted <- c
				}
			}()
			dial := func(ctx context.Context, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", target.Addr().String())
			}
			s := server.NewServer("/review", psk, nil, nil, 1024)
			s.SetDialTargetForTest(dial)
			var c *Client
			if mode == "h3" {
				var cleanup func()
				c, cleanup = reviewH3(t, s)
				defer cleanup()
			} else {
				var addr string
				if mode == "stream" {
					ln, e := net.Listen("tcp", "127.0.0.1:0")
					if e != nil {
						t.Fatal(e)
					}
					defer ln.Close()
					srv := server.NewStreamServer(psk, "", nil, func(ctx context.Context, _, address string) (net.Conn, error) { return dial(ctx, address) })
					defer srv.Close()
					go srv.Serve(ln)
					addr = ln.Addr().String()
				} else {
					hs := httptest.NewUnstartedServer(s)
					if mode == "h2" {
						hs.EnableHTTP2 = true
						hs.StartTLS()
					} else {
						hs.Start()
					}
					defer hs.Close()
					addr = hs.Listener.Addr().String()
				}
				c, err = New(Config{Server: addr, ServerName: "localhost", PSK: psk, Path: "/review", TCPTransport: mode, InsecureSkipVerify: true})
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := c.DialContext(ctx, "tcp", "192.0.2.1:80")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			var peer *net.TCPConn
			select {
			case peer = <-accepted:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			defer peer.Close()
			// Reproduce the SSH symptom: no application traffic for over five
			// seconds must not close an otherwise healthy established stream.
			time.Sleep(6 * time.Second)
			conn.SetDeadline(time.Now().Add(time.Second))
			peer.SetDeadline(time.Now().Add(time.Second))
			if _, err := conn.Write([]byte("idle")); err != nil {
				t.Fatal(err)
			}
			idleReply := make([]byte, 4)
			if _, err := io.ReadFull(peer, idleReply); err != nil {
				t.Fatalf("upload after idle: %v", err)
			}
			if _, err := peer.Write(idleReply); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(conn, idleReply); err != nil {
				t.Fatalf("download after idle: %v", err)
			}
			conn.SetDeadline(time.Time{})
			peer.SetDeadline(time.Time{})
			if err := peer.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			conn.SetReadDeadline(time.Now().Add(time.Second))
			if n, err := conn.Read(make([]byte, 1)); n != 0 || err != io.EOF {
				t.Fatalf("downlink half-close: n=%d err=%v", n, err)
			}
			time.Sleep(600 * time.Millisecond)
			if _, err := conn.Write([]byte("late-upload")); err != nil {
				t.Fatal(err)
			}
			peer.SetReadDeadline(time.Now().Add(time.Second))
			b := make([]byte, 11)
			if _, err := io.ReadFull(peer, b); err != nil {
				t.Fatal(err)
			}
			if string(b) != "late-upload" {
				t.Fatalf("corrupted upload: %q", b)
			}
			if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if n, err := peer.Read(b); n != 0 || err != io.EOF {
				t.Fatalf("upload half-close: n=%d err=%v", n, err)
			}
		})
	}
}
