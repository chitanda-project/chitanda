package outbound

import (
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestChitandaDeadlineCoalescesExtensionsAndPreservesShortening(t *testing.T) {
	var d chitandaReadDeadline
	defer func() {
		d.mu.Lock()
		d.closed = true
		if d.timer != nil {
			d.timer.Stop()
		}
		d.mu.Unlock()
	}()
	var calls atomic.Int64
	apply := func(time.Time) error { calls.Add(1); return nil }
	base := time.Now().Add(time.Minute)
	if err := d.set(base, apply); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 10000; i++ {
		if err := d.set(base.Add(time.Duration(i)*time.Microsecond), apply); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("extension calls = %d", calls.Load())
	}
	short := time.Now().Add(time.Second)
	d.set(short, apply)
	if calls.Load() != 2 || !d.forwarded.Equal(short) {
		t.Fatal("shortening delayed")
	}
	d.set(time.Time{}, apply)
	if calls.Load() != 3 || !d.forwarded.IsZero() {
		t.Fatal("clearing delayed")
	}
	if !d.retryTimeout(os.ErrDeadlineExceeded, apply) {
		t.Fatal("cleared stale timeout was exposed")
	}
	d.set(time.Now().Add(-time.Second), apply)
	if d.retryTimeout(os.ErrDeadlineExceeded, apply) {
		t.Fatal("real expired timeout retried")
	}
}
