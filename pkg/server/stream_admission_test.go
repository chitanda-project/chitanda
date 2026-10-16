package server

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type admissionProbeConn struct {
	net.Conn
	first   sync.Once
	events  chan<- bool
	release <-chan struct{}
}

func (c *admissionProbeConn) Read([]byte) (int, error) {
	c.first.Do(func() { c.events <- true })
	<-c.release
	return 0, io.EOF
}
func (c *admissionProbeConn) Close() error {
	c.first.Do(func() { c.events <- false })
	return nil
}
func (*admissionProbeConn) SetDeadline(time.Time) error { return nil }

// All admitted handshakes stay blocked until every attempt has either entered
// Read or been rejected. Thus admitted is a simultaneous reservation count,
// not the total number of connections admitted over an arbitrary time window.
func TestStreamAdmissionConcurrentLimit(t *testing.T) {
	s := NewStreamServer(bytes.Repeat([]byte{'s'}, 32), "", nil, nil)
	s.SetMaxConns(1)
	defer s.Close()
	const attempts = 64
	for round := 0; round < 100; round++ {
		events, start, release := make(chan bool, attempts), make(chan struct{}), make(chan struct{})
		var workers sync.WaitGroup
		for i := 0; i < attempts; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-start
				s.HandleConnContext(context.Background(), &admissionProbeConn{events: events, release: release})
			}()
		}
		close(start)
		admitted := 0
		for i := 0; i < attempts; i++ {
			select {
			case ok := <-events:
				if ok {
					admitted++
				}
			case <-time.After(3 * time.Second):
				close(release)
				workers.Wait()
				t.Fatal("admission did not settle")
			}
		}
		close(release)
		workers.Wait()
		if admitted != 1 {
			t.Fatalf("round %d: simultaneous admissions=%d, configured limit=1", round, admitted)
		}
		if s.activeConns.Load() != 0 {
			t.Fatal("connection reservation was not released")
		}
	}
}

func TestStreamAdmissionRejectReleasesReservation(t *testing.T) {
	s := NewStreamServer(bytes.Repeat([]byte{'s'}, 32), "", nil, nil)
	s.SetMaxConns(1)
	s.SetHandshakeLimit(0) // No pending handshakes can be admitted.
	events := make(chan bool, 1)
	s.HandleConnContext(context.Background(), &admissionProbeConn{events: events})
	if admitted := <-events; admitted || s.activeConns.Load() != 0 {
		t.Fatal("handshake rejection retained a connection reservation")
	}
	_ = s.Close()
	if s.reserveConnection() {
		t.Fatal("closed server admitted a new connection")
	}
	if s.activeConns.Load() != 0 {
		t.Fatal("closed server retained a connection reservation")
	}
}

func TestStreamAdmissionLimitValues(t *testing.T) {
	for _, limit := range []int{0, -1, 1, 4} {
		s := NewStreamServer(bytes.Repeat([]byte{'s'}, 32), "", nil, nil)
		s.SetMaxConns(limit)
		accepted := 0
		for i := 0; i < 10; i++ {
			if s.reserveConnection() {
				accepted++
			}
		}
		want := limit
		if limit <= 0 {
			want = 10
		}
		s.activeConns.Add(-int64(accepted))
		_ = s.Close()
		if accepted != want {
			t.Fatalf("limit %d: reserved %d, want %d", limit, accepted, want)
		}
	}
}
