package server

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestUDPBudgetPerIdentityAndExactlyOnceRelease(t *testing.T) {
	identity := UDPResourceIdentity([]byte(t.Name()))
	var releases []func()
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	for i := 0; i < MaxUserUDPTargets; i++ {
		release, ok := ReserveUDPTarget(identity)
		if !ok {
			t.Fatal("early exhaustion")
		}
		releases = append(releases, release)
	}
	if release, ok := ReserveUDPTarget(identity); ok {
		release()
		t.Fatal("quota exceeded")
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); releases[0]() }()
	}
	wg.Wait()
	release, ok := ReserveUDPTarget(identity)
	if !ok {
		t.Fatal("capacity not returned")
	}
	release()
}

func TestH3SlowTargetDoesNotHoldTableAndCloseCancelsDial(t *testing.T) {
	r := newUDPRelay(context.Background(), nil)
	defer r.Close()
	r.identity = UDPResourceIdentity([]byte(t.Name()))
	entered, done := make(chan struct{}), make(chan error, 1)
	r.dialUDP = func(ctx context.Context, _ string) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	go func() { _, err := r.target("slow.invalid:53"); done <- err }()
	<-entered
	lookup := make(chan error, 1)
	go func() {
		p, _, err := r.beginTarget("fast.invalid:53")
		if err == nil {
			err = r.finishTarget("fast.invalid:53", p, nil, nil, errors.New("test failure"))
		}
		lookup <- err
	}()
	select {
	case <-lookup:
	case <-time.After(time.Second):
		t.Fatal("unrelated target blocked")
	}
	closed := make(chan struct{})
	go func() { r.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close failed to cancel dial")
	}
	if err := <-done; err == nil {
		t.Fatal("closed relay created target")
	}
	udpTargetsBudget.Lock()
	used := udpTargetsBudget.users[r.identity]
	udpTargetsBudget.Unlock()
	if used != 0 {
		t.Fatalf("lease leak: %d", used)
	}
}

func TestH3TargetOpeningIsSingleFlightAndCombinedQuota(t *testing.T) {
	r := newUDPRelay(context.Background(), nil)
	defer func() {
		for address, p := range r.opening {
			r.finishTarget(address, p, nil, nil, net.ErrClosed)
		}
		r.Close()
	}()
	for i := 0; i < 64; i++ {
		address := net.JoinHostPort("127.0.0.1", strconv.Itoa(i+1))
		p, create, err := r.beginTarget(address)
		if err != nil || !create {
			t.Fatal("early admission failure")
		}
		other, create, err := r.beginTarget(address)
		if err != nil || create || other != p {
			t.Fatal("duplicate creation")
		}
	}
	if _, _, err := r.beginTarget("icmp:8.8.8.8"); err == nil {
		t.Fatal("opening targets escaped combined cap")
	}
	for address, p := range r.opening {
		r.finishTarget(address, p, nil, nil, net.ErrClosed)
	}
}
