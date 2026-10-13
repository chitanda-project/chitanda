package chitanda

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestNativeRouteBudgetReleaseIsExactlyOnce(t *testing.T) {
	user := "budget-test"
	releases := make([]func(), 0, maxNativeUDPUserRoutes)
	defer func() {
		for _, release := range releases {
			release()
			release()
		}
	}()
	for i := 0; i < maxNativeUDPUserRoutes; i++ {
		release, ok := reserveNativeRoute(user)
		if !ok {
			t.Fatal("early limit")
		}
		releases = append(releases, release)
	}
	if release, ok := reserveNativeRoute(user); ok {
		release()
		t.Fatal("user exceeded route limit")
	}
	releases[0]()
	releases[0]()
	release, ok := reserveNativeRoute(user)
	if !ok {
		t.Fatal("release did not restore capacity")
	}
	release()
}

func TestNativeRouteOpeningDoesNotHoldTableLock(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	r := newUDPRoutes(context.Background(), nil, nil, a)
	defer r.Close()
	first := udpRouteKey{0, 1, "slow"}
	second := udpRouteKey{0, 1, "fast"}
	_, _, pending, err := r.beginRoute(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, other, e := r.beginRoute(context.Background(), second)
		if e == nil {
			e = r.finishRoute(second, other, nil, nil, net.ErrClosed)
		}
		done <- e
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("unrelated target blocked by opening")
	}
	if err := r.finishRoute(first, pending, nil, nil, net.ErrClosed); err == nil {
		t.Fatal("failed route unexpectedly succeeded")
	}
}
