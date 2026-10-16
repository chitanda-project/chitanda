package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/chitanda/internal/plainudp"
)

// Cancel after read/admission but before enqueue, using a real authenticated
// loopback packet and a validated maximum-size user list. No production hook
// or codec override substitutes for the decoder under test.
func TestPlainUDPShutdownDrainsLateDecodedPacket(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	users := make([]UserKey, MaxUserKeys)
	for i := range users {
		users[i] = UserKey{Email: fmt.Sprintf("shutdown-%d@test.invalid", i), PSK: []byte(fmt.Sprintf("shutdown-regression-key-%016d", i))}
	}
	s, err := NewPlainUDPServerWithUsers(conn, users)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	sender, err := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	wire, err := s.codecs[len(s.codecs)-1].EncodePacket(nil, plainudp.DirClientToServer, 9, "192.0.2.1:53", bytes.Repeat([]byte{'p'}, 60<<10), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sender.Write(wire); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for s.inFlightMem.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("packet did not enter authentication")
		}
		runtime.Gosched()
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
	queued := 0
	for _, queue := range s.workers {
		queued += len(queue)
	}
	if queued != 0 || s.inFlightMem.Load() != 0 {
		t.Fatalf("shutdown retained decoded packet: queued=%d memory=%d", queued, s.inFlightMem.Load())
	}
}

func TestPlainUDPQueueMemoryAndPayloadOwnership(t *testing.T) {
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewPlainUDPServer(conn, bytes.Repeat([]byte{'a'}, 32))
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	s.SetResolveUDP(func(ctx context.Context, _ string) (*net.UDPAddr, error) {
		close(entered)
		select {
		case <-release:
			return target.LocalAddr().(*net.UDPAddr), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { unblock(); cancel(); _ = s.Close() }()
	go s.Serve(ctx)
	sender, err := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	const count = 32
	var reserved int64
	for i := 0; i < count; i++ {
		wire, err := s.codec.EncodePacket(nil, plainudp.DirClientToServer, 9, "queue.test:53", bytes.Repeat([]byte{byte(i)}, 1200), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		reserved += plainUDPTaskMemoryCost(len(wire))
		if _, err := sender.Write(wire); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("first target creation did not block")
			}
		}
	}
	queue := s.workers[9%len(s.workers)]
	deadline := time.Now().Add(3 * time.Second)
	for len(queue) != count-1 {
		if time.Now().After(deadline) {
			t.Fatal("authenticated burst did not reach the worker queue")
		}
		runtime.Gosched()
	}
	if got := s.inFlightMem.Load(); got != reserved {
		t.Fatalf("retained memory reservation = %d, want %d", got, reserved)
	}
	t.Logf("32 queued 1200-byte datagrams: reservation=%d bytes; former raw-buffer reservation=%d", reserved, count*(64<<10))
	unblock()
	_ = target.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 1400)
	for i := 0; i < count; i++ {
		n, _, err := target.ReadFromUDP(buffer)
		if err != nil || !bytes.Equal(buffer[:n], bytes.Repeat([]byte{byte(i)}, 1200)) {
			t.Fatalf("packet %d corrupted or reordered: n=%d err=%v", i, n, err)
		}
	}
}

func TestPlainUDPTaskMemoryBudgetIncludesBackingClasses(t *testing.T) {
	for _, size := range []int{0, 64, 256, 257, 1200, 32768, 32769, 65536} {
		cost := plainUDPTaskMemoryCost(size)
		backing := cost - plainUDPTaskOverhead
		if cost < int64(size)+plainUDPTaskOverhead || backing&(backing-1) != 0 {
			t.Fatalf("wire=%d cost=%d undercounts or ignores backing size", size, cost)
		}
	}
}
