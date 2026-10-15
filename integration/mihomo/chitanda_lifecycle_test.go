package outbound

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/violetaini/chitanda/pkg/server"
)

func TestChitandaCloseTerminatesRawTCPAndUDP(t *testing.T) {
	for _, mode := range []string{"stream", "h1", "plain-h1"} {
		t.Run(mode, func(t *testing.T) {
			psk := bytes.Repeat([]byte{'x'}, 32)
			dialTarget := func(context.Context, string) (net.Conn, error) {
				a, b := net.Pipe()
				go func() { defer b.Close(); _, _ = io.Copy(b, b) }()
				return a, nil
			}
			var addr string
			if mode == "stream" {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				srv := server.NewStreamServer(psk, "", nil, func(ctx context.Context, _, address string) (net.Conn, error) { return dialTarget(ctx, address) })
				go srv.Serve(ln)
				defer srv.Close()
				addr = ln.Addr().String()
			} else {
				srv := server.NewServer("/lifecycle", psk, nil, nil, 16)
				srv.SetDialTargetForTest(dialTarget)
				hs := httptest.NewServer(srv)
				defer hs.Close()
				addr = hs.Listener.Addr().String()
			}
			host, portText, err := net.SplitHostPort(addr)
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				t.Fatal(err)
			}
			node, err := NewChitanda(ChitandaOption{Server: host, Port: port, PSK: string(psk), Path: "/lifecycle", Transport: mode})
			if err != nil {
				t.Fatal(err)
			}
			defer node.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := node.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "echo.invalid", DstPort: 80})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			if _, err := conn.Write([]byte("before")); err != nil {
				t.Fatal(err)
			}
			var reply [6]byte
			if _, err := io.ReadFull(conn, reply[:]); err != nil || string(reply[:]) != "before" {
				t.Fatalf("baseline echo: %q %v", reply, err)
			}
			packets, err := node.ListenPacketContext(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer packets.Close()
			if err := node.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write([]byte("after")); err == nil {
				t.Fatal("adapter.Close left RawStream/H1 TCP writable")
			}
			if _, err := packets.WriteTo([]byte("after"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}); err == nil {
				t.Fatal("adapter.Close left Plain-UDP writable")
			}
		})
	}
}
