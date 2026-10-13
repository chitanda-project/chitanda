package outbound

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

// Debounce only routine extensions. Shortening, clearing, expired deadlines
// and shutdown retain immediate PacketConn semantics. A timeout from a stale
// underlying deadline is refreshed and retried, never exposed prematurely.
type chitandaReadDeadline struct {
	mu                             sync.Mutex
	requested, forwarded, lastCall time.Time
	timer                          *time.Timer
	closed                         bool
	generation                     uint64
}

func (d *chitandaReadDeadline) set(t time.Time, apply func(time.Time) error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return net.ErrClosed
	}
	d.requested = t
	now := time.Now()
	if !t.IsZero() && t.After(d.forwarded) && d.forwarded.After(now.Add(2*time.Second)) && now.Sub(d.lastCall) < time.Second {
		if d.timer == nil {
			d.generation++
			generation := d.generation
			d.timer = time.AfterFunc(time.Second-now.Sub(d.lastCall), func() {
				d.mu.Lock()
				defer d.mu.Unlock()
				if generation != d.generation {
					return
				}
				if !d.closed {
					_ = apply(d.requested)
					d.forwarded, d.lastCall = d.requested, time.Now()
				}
				d.timer = nil
			})
		}
		return nil
	}
	if d.timer != nil {
		d.generation++
		d.timer.Stop()
		d.timer = nil
	}
	err := apply(t)
	if err == nil {
		d.forwarded, d.lastCall = t, now
	}
	return err
}

func (d *chitandaReadDeadline) retryTimeout(err error, apply func(time.Time) error) bool {
	// A transport timeout (e.g. QUIC idle/handshake timeout) is terminal.
	// Retrying every net.Error.Timeout keeps a dead association alive and
	// can spin on ReadFrom. Only local socket/SDK deadlines are recoverable.
	if !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || (!d.requested.IsZero() && !d.requested.After(time.Now())) {
		return false
	}
	if d.timer != nil {
		d.generation++
		d.timer.Stop()
		d.timer = nil
	}
	if err := apply(d.requested); err != nil {
		return false
	}
	d.forwarded, d.lastCall = d.requested, time.Now()
	return true
}

func (c *chitandaICMPPacketConn) SetReadDeadline(t time.Time) error {
	return c.deadline.set(t, c.PacketConn.SetReadDeadline)
}

func (c *chitandaICMPPacketConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.PacketConn.SetWriteDeadline(t)
}

func (c *chitandaICMPPacketConn) Close() error {
	c.deadline.mu.Lock()
	c.deadline.closed = true
	c.deadline.generation++
	if c.deadline.timer != nil {
		c.deadline.timer.Stop()
		c.deadline.timer = nil
	}
	c.deadline.mu.Unlock()
	return c.PacketConn.Close()
}
