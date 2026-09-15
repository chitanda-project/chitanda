package client

import (
	"context"
	"crypto/tls"
	"github.com/quic-go/quic-go/http3"
	"github.com/violetaini/chitanda/pkg/server"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func reviewH3(t *testing.T, h http.Handler) (*Client, func()) {
	t.Helper()
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	cert := ts.TLS.Certificates[0]
	ts.Close()
	u, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	hs := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{http3.NextProtoH3}}, EnableDatagrams: true, Handler: h}
	go hs.Serve(u)
	c, e := New(Config{Server: u.LocalAddr().String(), ServerName: "localhost", Path: "/review", PSK: []byte(strings.Repeat("x", 32)), TCPTransport: "h3", InsecureSkipVerify: true, TCPPoolSize: 1})
	if e != nil {
		t.Fatal(e)
	}
	return c, func() { c.Close(); hs.Close(); u.Close() }
}
func TestReviewH3HandshakeCancellation(t *testing.T) {
	for _, mode := range []string{"tcp", "udp"} {
		t.Run(mode, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			c, cleanup := reviewH3(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(entered); <-release }))
			defer cleanup()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() {
				if mode == "tcp" {
					_, _ = c.DialContext(ctx, "tcp", "192.0.2.1:80")
				} else {
					_, _ = c.ListenPacket(ctx)
				}
				close(done)
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				close(release)
				t.Fatal("handler not reached")
			}
			cancel()
			select {
			case <-done:
				close(release)
			case <-time.After(150 * time.Millisecond):
				close(release)
				<-done
				t.Error("H3 response-header wait ignores caller cancellation")
			}
		})
	}
}
func TestReviewH3DeadlineUpdate(t *testing.T) {
	release := make(chan struct{})
	c, cleanup := reviewH3(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderSessionOK, "1")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		w.(http3.HTTPStreamer).HTTPStream()
		<-release
	}))
	defer cleanup()
	defer close(release)
	p, e := c.ListenPacket(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	done := make(chan struct{})
	go func() { _, _, _ = p.ReadFrom(make([]byte, 100)); close(done) }()
	time.Sleep(20 * time.Millisecond)
	p.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case <-done:
	case <-time.After(150 * time.Millisecond):
		p.Close()
		<-done
		t.Error("updated UDP deadline does not interrupt pending ReadFrom")
	}
}
func TestReviewH1HandshakeCancellation(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go io.Copy(io.Discard, b)
	c, e := New(Config{Server: "127.0.0.1:9999", PSK: []byte(strings.Repeat("x", 32)), Path: "/review", TCPTransport: "h1", DialContext: func(context.Context, string, string) (net.Conn, error) { return a, nil }})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { _, _ = c.DialContext(ctx, "tcp", "192.0.2.1:80"); close(done) }()
	select {
	case <-done:
	case <-time.After(150 * time.Millisecond):
		a.Close()
		<-done
		t.Error("H1 response-header wait ignores caller timeout")
	}
}
func TestReviewH2TargetHalfClose(t *testing.T) {
	psk := []byte(strings.Repeat("x", 32))
	ln, e := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() { p, _ := ln.AcceptTCP(); accepted <- p }()
	s := server.NewServer("/review", psk, nil, nil, 1024)
	s.SetDialTargetForTest(func(ctx context.Context, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ln.Addr().String())
	})
	hs := httptest.NewUnstartedServer(s)
	hs.EnableHTTP2 = true
	hs.StartTLS()
	defer hs.Close()
	c, e := New(Config{Server: hs.Listener.Addr().String(), ServerName: "localhost", PSK: psk, Path: "/review", TCPTransport: "h2", InsecureSkipVerify: true})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	conn, e := c.DialContext(context.Background(), "tcp", "192.0.2.1:80")
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	p := <-accepted
	defer p.Close()
	p.CloseWrite()
	time.Sleep(400 * time.Millisecond)
	_, we := conn.Write([]byte("late-upload"))
	p.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	b := make([]byte, 11)
	n, re := io.ReadFull(p, b)
	if n != 11 {
		t.Errorf("target CloseWrite ended legitimate continuing upload: n=%d write=%v read=%v", n, we, re)
	}
}
