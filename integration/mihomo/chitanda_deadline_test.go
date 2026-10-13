package outbound

import (
	"context"
	"errors"
	quic "github.com/quic-go/quic-go"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

type terminalTimeoutPacketConn struct {
	net.PacketConn
	reads int
}

func (c *terminalTimeoutPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	c.reads++
	if c.reads > 1 {
		return 0, nil, net.ErrClosed // Bound a broken retry loop in the test.
	}
	return 0, nil, &quic.IdleTimeoutError{}
}

func (c *terminalTimeoutPacketConn) SetReadDeadline(time.Time) error { return nil }

func TestChitandaReadFromPropagatesTerminalTimeoutOnce(t *testing.T) {
	pc := &terminalTimeoutPacketConn{}
	c := &chitandaICMPPacketConn{PacketConn: pc}
	c.SetReadDeadline(time.Now().Add(time.Minute))
	_, _, err := c.ReadFrom(make([]byte, 1))
	var timeout *quic.IdleTimeoutError
	if !errors.As(err, &timeout) || pc.reads != 1 {
		t.Fatalf("transport timeout not propagated: reads=%d err=%v", pc.reads, err)
	}
}

func TestChitandaDeadlineDoesNotRetryTransportTimeout(t *testing.T) {
	var d chitandaReadDeadline
	apply := func(time.Time) error { return nil }
	d.set(time.Now().Add(time.Minute), apply)
	if d.retryTimeout(&quic.IdleTimeoutError{}, apply) {
		t.Fatal("terminal QUIC idle timeout swallowed; dead association keeps retrying")
	}
	d.set(time.Time{}, apply)
	if d.retryTimeout(&quic.HandshakeTimeoutError{}, apply) {
		t.Fatal("terminal QUIC handshake timeout swallowed")
	}
	if !d.retryTimeout(context.DeadlineExceeded, apply) {
		t.Fatal("stale SDK read deadline did not retry")
	}
}

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
