package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"github.com/violetaini/chitanda/internal/plainudp"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestRegressionOctober15H2AdvertisedReceiveWindow(t *testing.T) {
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	cert := fixture.TLS.Certificates[0]
	fixture.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	result := make(chan uint32, 1)
	serverErr := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer raw.Close()
		tc := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
		tc.SetDeadline(time.Now().Add(2 * time.Second))
		if err := tc.Handshake(); err != nil {
			serverErr <- err
			return
		}
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(tc, preface); err != nil {
			serverErr <- err
			return
		}
		if string(preface) != http2.ClientPreface {
			serverErr <- errors.New("invalid preface")
			return
		}
		fr := http2.NewFramer(tc, tc)
		f, err := fr.ReadFrame()
		if err != nil {
			serverErr <- err
			return
		}
		settings, ok := f.(*http2.SettingsFrame)
		if !ok {
			serverErr <- errors.New("initial frame not SETTINGS")
			return
		}
		settings.ForeachSetting(func(s http2.Setting) error {
			if s.ID == http2.SettingInitialWindowSize {
				result <- s.Val
			}
			return nil
		})
	}()
	h, err := newH2TransportClient(ln.Addr().String(), "localhost", "https://localhost/", "https://localhost/test", "/test", bytes.Repeat([]byte{'x'}, 32), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = h.dialH2TCPOnce(ctx, "192.0.2.1:80")
	select {
	case n := <-result:
		if n != 64<<20 {
			t.Fatalf("actual SETTINGS_INITIAL_WINDOW_SIZE=%d; want 64MiB", n)
		}
	case err := <-serverErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal("SETTINGS not observed")
	}
}

func TestRegressionOctober15PlainUDPResponseClockRollback(t *testing.T) {
	key := bytes.Repeat([]byte{'x'}, 32)
	sender, _ := plainudp.NewCodec(key, "audit")
	receiver, _ := plainudp.NewCodec(key, "audit")
	now := time.Now()
	packets := make([][]byte, 0, 2050)
	for range 2049 {
		b, err := sender.EncodePacket(nil, plainudp.DirServerToClient, 1, "1.1.1.1:53", []byte("a"), now)
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, b)
	}
	fresh, err := sender.EncodePacket(nil, plainudp.DirServerToClient, 1, "1.1.1.1:53", []byte("b"), now.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, _, err = receiver.DecodePacket(fresh, plainudp.DirServerToClient, now); err != nil {
		t.Fatal("fixture not valid", err)
	}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	p := &plainUDPConn{sessionID: 1, codec: receiver, serverAddr: addr, conn: &regressionPackets{packets: append(packets, fresh), server: addr}}
	defer p.Close()
	var b [10]byte
	for range 2049 {
		if _, _, err := p.ReadFrom(b[:]); err != nil {
			t.Fatal(err)
		}
	}
	n, _, err := p.ReadFrom(b[:])
	if err != nil || string(b[:n]) != "b" {
		t.Fatalf("authenticated higher-sequence response dropped after 1-second sender clock rollback: n=%d err=%v", n, err)
	}
}

type audit15HeaderConn struct {
	*bytes.Reader
	consumed int
}

func (c *audit15HeaderConn) Read(p []byte) (int, error) {
	n, e := c.Reader.Read(p)
	c.consumed += n
	return n, e
}
func (c *audit15HeaderConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *audit15HeaderConn) Close() error                     { return nil }
func (c *audit15HeaderConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *audit15HeaderConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *audit15HeaderConn) SetDeadline(time.Time) error      { return nil }
func (c *audit15HeaderConn) SetReadDeadline(time.Time) error  { return nil }
func (c *audit15HeaderConn) SetWriteDeadline(time.Time) error { return nil }

func TestRegressionOctober15H1UnauthenticatedResponseHeadersBounded(t *testing.T) {
	wire := append([]byte("HTTP/1.1 200 OK\r\nX-Fill: "), bytes.Repeat([]byte{'a'}, 2<<20)...)
	wire = append(wire, []byte("\r\n\r\n28\r\n")...)
	wire = append(wire, make([]byte, 40)...)
	rc := &audit15HeaderConn{Reader: bytes.NewReader(wire)}
	c, err := New(Config{Server: "127.0.0.1:80", Path: "/test", TCPTransport: "h1", PSK: bytes.Repeat([]byte{'x'}, 32), DialContext: func(context.Context, string, string) (net.Conn, error) { return rc, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.DialContext(context.Background(), "tcp", "192.0.2.1:80")
	if err == nil {
		t.Fatal("invalid server authentication accepted")
	}
	if rc.consumed > 64<<10 {
		t.Fatalf("unauthenticated HTTP headers consumed %d bytes before rejection: %v", rc.consumed, err)
	}
}

type audit15PartialHeader struct {
	first bool
	tail  *bytes.Reader
}

func (r *audit15PartialHeader) Read(p []byte) (int, error) {
	if !r.first {
		r.first = true
		p[0] = '1'
		return 1, os.ErrDeadlineExceeded
	}
	return r.tail.Read(p)
}

func TestRegressionOctober15H1PartialChunkHeaderTimeoutRecovery(t *testing.T) {
	input := &audit15PartialHeader{tail: bytes.NewReader([]byte("0\r\nAAAAAAAAAAAAAAAA\r\n0\r\n\r\n"))}
	r := newChunkedReader(bufio.NewReader(input))
	p := make([]byte, 16)
	if _, err := r.Read(p); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("first read = %v", err)
	}
	n, err := io.ReadFull(r, p)
	if err != nil || string(p[:n]) != "AAAAAAAAAAAAAAAA" {
		t.Fatalf("partial header '1' lost across timeout; got n=%d err=%v payload=%q", n, err, p[:n])
	}
}

func TestRegressionOctober15ClientCloseWakesH3UDPRead(t *testing.T) {
	c, cleanup := reviewH3(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderSessionOK, "1")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer cleanup()
	p, err := c.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	readDone := make(chan error, 1)
	go func() { _, _, err := p.ReadFrom(make([]byte, 100)); readDone <- err }()
	c.Close()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("closed client returned successful read")
		}
	case <-time.After(300 * time.Millisecond):
		p.Close()
		<-readDone
		t.Fatal("Client.Close closed QUIC but did not wake pending UDP ReadFrom; explicit PacketConn.Close required")
	}
}
