package auth

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestSharedReplayOwnershipAndLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.cache")
	a, err := OpenSharedReplayCache(path, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, err := OpenSharedReplayCache(path, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("same state not shared")
	}
	if other, err := OpenReplayCache(path, time.Now()); err == nil {
		other.Close()
		t.Fatal("concurrent independent owner allowed")
	}
	a.Close()
	if ok, err := b.Accept("still-open", time.Now()); !ok || err != nil {
		t.Fatalf("premature close: %v %v", ok, err)
	}
	b.Close()
	c, err := OpenReplayCache(path, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if ok, err := c.Accept("still-open", time.Now()); ok || err != nil {
		t.Fatal("restart lost record")
	}
}

func TestReplayConcurrentCloseAndAdmissionsDoNotHang(t *testing.T) {
	cache, err := OpenReplayCache(filepath.Join(t.TempDir(), "concurrent.cache"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; _, _ = cache.Accept("pending", time.Now()); _ = cache.Close() }()
	}
	close(start)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("close/admission deadlock")
	}
	if ok, err := cache.Accept("after-close", time.Now()); ok || err == nil {
		t.Fatal("closed cache accepted admission")
	}
}
