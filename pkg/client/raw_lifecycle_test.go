package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/server"
)

func rawTestConfig(mode string) Config {
	return Config{Server: "127.0.0.1:443", PSK: bytes.Repeat([]byte{'x'}, 32), TCPTransport: mode, Path: "/raw-lifetime"}
}

func TestRawClientCloseStopsActiveTCP(t *testing.T) {
	for _, mode := range []string{"stream", "h1", "plain-h1"} {
		t.Run(mode, func(t *testing.T) {
			cfg := rawTestConfig(mode)
			dial := func(context.Context, string) (net.Conn, error) {
				a, b := net.Pipe()
				go func() { defer b.Close(); _, _ = io.Copy(b, b) }()
				return a, nil
			}
			if mode == "stream" {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				srv := server.NewStreamServer(cfg.PSK, "", nil, func(ctx context.Context, _, target string) (net.Conn, error) { return dial(ctx, target) })
				go srv.Serve(ln)
				defer srv.Close()
				cfg.Server = ln.Addr().String()
			} else {
				srv := server.NewServer(cfg.Path, cfg.PSK, nil, nil, 16)
				srv.SetDialTargetForTest(dial)
				hs := httptest.NewServer(srv)
				defer hs.Close()
				cfg.Server = hs.Listener.Addr().String()
			}
			var retainedDialContext context.Context
			cfg.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				retainedDialContext = ctx
				var dialer net.Dialer
				return dialer.DialContext(ctx, network, address)
			}
			c, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := c.DialContext(ctx, "tcp", "192.0.2.1:80")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			cancel() // A dial-only context must not kill a returned proxy chain.
			if retainedDialContext.Err() != nil {
				t.Fatal("successful raw dial canceled its embedding context")
			}
			echo := func(s string) error {
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				if _, err := conn.Write([]byte(s)); err != nil {
					return err
				}
				got := make([]byte, len(s))
				_, err := io.ReadFull(conn, got)
				if err == nil && string(got) != s {
					return errors.New("echo mismatch")
				}
				return err
			}
			if err := echo("before-close"); err != nil {
				t.Fatal(err)
			}
			if mode == "stream" {
				if _, ok := conn.(interface{ WriteBatch([][]byte) (int, error) }); !ok {
					t.Fatal("raw socket ownership hid WriteBatch")
				}
			}
			c.Close()
			waitRawTest(t, retainedDialContext.Done(), "socket shutdown did not release embedding context")
			if err := echo("after-close"); err == nil {
				t.Fatal("Client.Close left authenticated TCP usable")
			}
			c.mu.Lock()
			remaining := len(c.rawConnections)
			c.mu.Unlock()
			if remaining != 0 {
				t.Fatal("closed connection retained")
			}
		})
	}
}

func TestRawPacketHandoffKeepsEmbeddingContextUntilClose(t *testing.T) {
	cfg := rawTestConfig("stream")
	var retained context.Context
	cfg.DialPacket = func(ctx context.Context, _ *net.UDPAddr) (net.PacketConn, error) {
		retained = ctx
		return net.ListenPacket("udp", "127.0.0.1:0")
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := c.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	cancel()
	if retained.Err() != nil {
		t.Fatal("successful packet dial canceled its embedding context")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	waitRawTest(t, retained.Done(), "packet close retained embedding context")
	c.mu.Lock()
	remaining := len(c.rawConnections)
	c.mu.Unlock()
	if remaining != 0 {
		t.Fatal("individually closed packet socket retained by Client")
	}
}

type lifecyclePacketSocket struct {
	net.PacketConn
	closes atomic.Int32
}

func (p *lifecyclePacketSocket) Close() error { p.closes.Add(1); return p.PacketConn.Close() }

func TestRawClientCloseStopsPlainUDPAndIsIdempotent(t *testing.T) {
	for _, mode := range []string{"stream", "h1", "plain-h1"} {
		t.Run(mode, func(t *testing.T) {
			cfg := rawTestConfig(mode)
			var sockets []*lifecyclePacketSocket
			cfg.ListenPacket = func(context.Context, string, string) (net.PacketConn, error) {
				pc, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					return nil, err
				}
				p := &lifecyclePacketSocket{PacketConn: pc}
				sockets = append(sockets, p)
				return p, nil
			}
			c, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			first, err := c.ListenPacket(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			second, err := c.ListenPacket(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			if err := first.Close(); err != nil {
				t.Fatal(err)
			}
			if sockets[1].closes.Load() != 0 {
				t.Fatal("closing one association closed its sibling")
			}
			readDone := make(chan error, 1)
			go func() { _, _, err := second.ReadFrom(make([]byte, 100)); readDone <- err }()
			var wg sync.WaitGroup
			for range 16 {
				wg.Add(1)
				go func() { defer wg.Done(); c.Close(); _ = first.Close(); _ = second.Close() }()
			}
			wg.Wait()
			select {
			case err := <-readDone:
				if !errors.Is(err, net.ErrClosed) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("Client.Close did not wake native UDP ReadFrom")
			}
			if _, err := second.WriteTo([]byte("after-close"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}); !errors.Is(err, net.ErrClosed) {
				t.Fatal(err)
			}
			for _, socket := range sockets {
				if socket.closes.Load() != 1 {
					t.Fatalf("physical Close calls=%d", socket.closes.Load())
				}
			}
		})
	}
}

func waitRawTest(t *testing.T, done <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal(message)
	}
}

func TestRawClientCloseCancelsPendingOpen(t *testing.T) {
	for _, mode := range []string{"stream", "h1", "plain-h1"} {
		for _, stage := range []string{"resolve", "dial", "handshake"} {
			t.Run(mode+"/"+stage, func(t *testing.T) {
				cfg := rawTestConfig(mode)
				entered := make(chan struct{})
				peerDone := make(chan struct{})
				switch stage {
				case "resolve":
					cfg.Server = "resolver.invalid:443"
					cfg.ResolveUDP = func(ctx context.Context, _, _ string) (*net.UDPAddr, error) {
						close(entered)
						<-ctx.Done()
						return nil, ctx.Err()
					}
				case "dial":
					cfg.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
						close(entered)
						<-ctx.Done()
						return nil, ctx.Err()
					}
				case "handshake":
					cfg.DialContext = func(context.Context, string, string) (net.Conn, error) {
						a, b := net.Pipe()
						go func() {
							defer close(peerDone)
							defer b.Close()
							var flight [4096]byte
							_, _ = b.Read(flight[:])
							close(entered)
							_, _ = b.Read(flight[:])
						}()
						return a, nil
					}
				}
				c, err := New(cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				done := make(chan struct{})
				var openErr error
				go func() {
					defer close(done)
					if stage == "resolve" {
						_, openErr = c.ListenPacket(ctx)
					} else {
						_, openErr = c.DialContext(ctx, "tcp", "192.0.2.1:80")
					}
				}()
				waitRawTest(t, entered, "open did not reach barrier")
				c.Close()
				waitRawTest(t, done, "pending raw operation survived Close")
				if openErr == nil {
					t.Fatal("closed client published a connection")
				}
				if stage == "handshake" {
					waitRawTest(t, peerDone, "handshake peer not closed")
				}
			})
		}
	}
}

func TestRawClientCloseRejectsLateDialResults(t *testing.T) {
	for _, packet := range []bool{false, true} {
		t.Run(map[bool]string{false: "tcp", true: "udp"}[packet], func(t *testing.T) {
			cfg := rawTestConfig("stream")
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			var closes atomic.Int32
			if packet {
				cfg.DialPacket = func(context.Context, *net.UDPAddr) (net.PacketConn, error) {
					close(entered)
					<-release
					pc, err := net.ListenPacket("udp", "127.0.0.1:0")
					if err != nil {
						return nil, err
					}
					return &latePacketSocket{PacketConn: pc, closes: &closes}, nil
				}
			} else {
				cfg.DialContext = func(context.Context, string, string) (net.Conn, error) {
					close(entered)
					<-release
					a, b := net.Pipe()
					_ = b.Close()
					return &lateRawSocket{Conn: a, closes: &closes}, nil
				}
			}
			c, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			done := make(chan struct{})
			var openErr error
			go func() {
				defer close(done)
				if packet {
					_, openErr = c.ListenPacket(context.Background())
				} else {
					_, openErr = c.DialContext(context.Background(), "tcp", "192.0.2.1:80")
				}
			}()
			waitRawTest(t, entered, "dial did not start")
			c.Close() // Must not hold a lifecycle lock waiting for an opaque dialer.
			unblock()
			waitRawTest(t, done, "late dial failed to finish")
			if openErr == nil || closes.Load() != 1 {
				t.Fatalf("late socket escaped: err=%v closes=%d", openErr, closes.Load())
			}
		})
	}
}

type lateRawSocket struct {
	net.Conn
	closes *atomic.Int32
}

func (c *lateRawSocket) Close() error { c.closes.Add(1); return c.Conn.Close() }

type latePacketSocket struct {
	net.PacketConn
	closes *atomic.Int32
}

func (c *latePacketSocket) Close() error { c.closes.Add(1); return c.PacketConn.Close() }
