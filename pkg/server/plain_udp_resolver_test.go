package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/violetaini/chitanda/internal/plainudp"
)

// Exercise the actual worker path while the resolver is replaced. AttachUDP
// starts workers before callers can configure their target policy.
func TestPlainUDPServer_ConcurrentResolverUpdate(t *testing.T) {
	var calls atomic.Int64
	resolve := func(context.Context, string) (*net.UDPAddr, error) {
		calls.Add(1)
		return nil, errors.New("test resolver: do not dial")
	}
	// The resolver fails before a codec is used; one slot makes this a valid
	// authenticated worker task without changing the resolver race under test.
	s := &PlainUDPServer{resolveUDP: resolve, codecs: make([]*plainudp.Codec, 1)}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(5)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 2000; i++ {
			s.SetResolveUDPForTest(resolve)
		}
	}()
	for worker := 0; worker < 4; worker++ {
		go func(id uint64) {
			defer wg.Done()
			<-start
			for seq := uint64(1); seq <= 2000; seq++ {
				s.processTask(context.Background(), udpTask{
					sessionID: id, seq: seq, targetAddr: "example.invalid:53",
					clientAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
				})
			}
		}(uint64(worker + 1))
	}
	close(start)
	wg.Wait()
	if got := calls.Load(); got != 8000 {
		t.Fatalf("resolver calls = %d, want 8000", got)
	}
}

func TestPlainUDPServer_ResolverCanUpdateItself(t *testing.T) {
	s := &PlainUDPServer{codecs: make([]*plainudp.Codec, 1)}
	s.SetResolveUDP(func(context.Context, string) (*net.UDPAddr, error) {
		// A resolver must not execute while the configuration lock is held.
		s.SetResolveUDP(nil)
		return nil, errors.New("do not dial")
	})
	done := make(chan struct{})
	go func() {
		s.processTask(context.Background(), udpTask{sessionID: 1, seq: 1, targetAddr: "example.invalid:53"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("resolver update blocked inside callback")
	}
	// nil must restore the safe default, not silently allow private targets.
	s.resolveMu.RLock()
	resolve := s.resolveUDP
	s.resolveMu.RUnlock()
	if _, err := resolve(context.Background(), "127.0.0.1:53"); err == nil {
		t.Fatal("default resolver must reject private targets")
	}
}
