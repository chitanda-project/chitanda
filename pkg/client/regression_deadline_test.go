package client

import (
	"context"
	"github.com/quic-go/quic-go/http3"
	"github.com/violetaini/chitanda/internal/frame"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func TestReviewH3DeadlineContextRetention(t *testing.T) {
	ready := make(chan *http3.Stream, 1)
	release := make(chan struct{})
	c, cleanup := reviewH3(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderSessionOK, "1")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		ready <- w.(http3.HTTPStreamer).HTTPStream()
		<-release
	}))
	defer cleanup()
	defer close(release)
	p, e := c.ListenPacket(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	stream := <-ready
	p.SetReadDeadline(time.Now().Add(time.Minute))
	for i := 1; i <= 5; i++ {
		b, e := frame.EncodeDatagram(uint64(i), "192.0.2.1:53", []byte("x"))
		if e != nil {
			t.Fatal(e)
		}
		if e = stream.SendDatagram(b); e != nil {
			t.Fatal(e)
		}
		if _, _, e = p.ReadFrom(make([]byte, 100)); e != nil {
			t.Fatal(e)
		}
	}
	ctx := p.(*quicPacketConn).ctx
	children := reflect.ValueOf(ctx).Elem().FieldByName("children")
	if children.IsValid() && children.Len() != 0 {
		t.Errorf("completed 5 datagram reads retain %d uncanceled child contexts", children.Len())
	}
}
func TestReviewH3ConcurrentReadDeadline(t *testing.T) {
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
	done := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go func() { p.ReadFrom(make([]byte, 100)); done <- struct{}{} }()
	}
	time.Sleep(30 * time.Millisecond)
	p.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	time.Sleep(120 * time.Millisecond)
	if n := len(done); n != 2 {
		t.Errorf("deadline woke %d of 2 pending UDP reads", n)
	}
	p.Close()
}
