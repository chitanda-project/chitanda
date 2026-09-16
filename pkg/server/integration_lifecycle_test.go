package server

import (
	"context"
	"errors"
	"github.com/violetaini/chitanda/internal/plainudp"
	"net"
	"testing"
	"time"
)

func TestRegressionPlainUDPShutdown(t *testing.T) {
	for _, action := range []string{"close", "cancel"} {
		t.Run(action, func(t *testing.T) {
			pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			s, err := NewPlainUDPServer(pc, []byte("01234567890123456789012345678901"))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			ready := make(chan struct{}, 1)
			s.SetResolveUDP(func(context.Context, string) (*net.UDPAddr, error) {
				ready <- struct{}{}
				return nil, errors.New("audit: no target dial")
			})
			done := make(chan error, 1)
			go func() { done <- s.Serve(ctx) }()
			sender, err := net.DialUDP("udp", nil, pc.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			pkt, err := s.codec.EncodePacket(nil, plainudp.DirClientToServer, 123, "example.invalid:53", []byte("ready"), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = sender.Write(pkt); err != nil {
				t.Fatal(err)
			}
			select {
			case <-ready:
			case <-time.After(time.Second):
				t.Fatal("serve did not start")
			}
			// Either Close or cancellation alone should stop the receive/worker loop.
			if action == "close" {
				s.Close()
			} else {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(250 * time.Millisecond):
				t.Errorf("%s alone did not terminate Serve", action)
			}
			cancel()
			s.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
			}
		})
	}
}

func TestRegressionH3FailedTargetIsEvicted(t *testing.T) {
	r := newUDPRelay(context.Background(), nil)
	defer r.Close()
	calls := 0
	r.dialUDP = func(context.Context, string) (net.Conn, error) {
		calls++
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	first, err := r.target("example.invalid:53")
	if err != nil {
		t.Fatal(err)
	}
	r.waitGroup.Wait() // Read failed: there is now no response reader for this target.
	second, err := r.target("example.invalid:53")
	if err != nil {
		t.Fatal(err)
	}
	if first == second || calls != 2 {
		t.Errorf("failed target remained cached; dial count=%d, same target=%v", calls, first == second)
	}
}
