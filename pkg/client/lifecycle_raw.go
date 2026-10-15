package client

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
)

type rawOpeningKey struct{}

// Keep an embedding core's dial context alive until the socket closes. Some
// proxy dialers retain it for their forwarding task; canceling on successful
// dial would tear down a newly established proxy chain.
type rawOpening struct {
	ctx          context.Context
	parent       context.Context
	cancel       context.CancelFunc
	stopCaller   func() bool
	stopLifetime func() bool
	once         sync.Once
}

func (o *rawOpening) close() {
	o.once.Do(func() { o.stopCaller(); o.stopLifetime(); o.cancel() })
}

func (o *rawOpening) establish() error {
	o.stopCaller()
	if err := o.parent.Err(); err != nil {
		return err
	}
	return o.ctx.Err()
}

// Cancel DNS/dial/handshake on caller or Client shutdown. After handoff only
// socket/Client shutdown cancels the retained context, not the dial caller.
func (c *Client) beginRawOpen(ctx context.Context) (*rawOpening, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	if c.rawLifetime == nil {
		c.rawLifetime, c.rawCancel = context.WithCancel(context.Background())
	}
	lifetime := c.rawLifetime
	c.mu.Unlock()
	parent := ctx
	ctx, cancel := context.WithCancel(context.WithoutCancel(parent))
	stop := context.AfterFunc(lifetime, cancel)
	o := &rawOpening{parent: parent, cancel: cancel, stopLifetime: stop, stopCaller: context.AfterFunc(parent, cancel)}
	o.ctx = context.WithValue(ctx, rawOpeningKey{}, o)
	return o, nil
}

func rawHandshakeDeadline(ctx context.Context) (time.Time, bool) {
	if opening, ok := ctx.Value(rawOpeningKey{}).(*rawOpening); ok {
		return opening.parent.Deadline()
	}
	return ctx.Deadline()
}

// Registration and the Close snapshot share the same lock. A late dial result
// cannot escape a closed Client, even if an embedding dialer ignores cancel.
func (c *Client) registerRaw(conn io.Closer) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if c.rawConnections == nil {
		c.rawConnections = make(map[io.Closer]struct{})
	}
	c.rawConnections[conn] = struct{}{}
	return nil
}

func (c *Client) releaseRaw(conn io.Closer) {
	c.mu.Lock()
	delete(c.rawConnections, conn)
	c.mu.Unlock()
}

// Own the physical TCP socket below the protocol wrapper, preserving the
// original RawStream WriteBatch and authenticated half-close implementations.
type ownedRawConn struct {
	net.Conn
	owner   *Client
	opening *rawOpening
	once    sync.Once
	err     error
}

func (c *ownedRawConn) Close() error {
	c.once.Do(func() {
		if c.opening != nil {
			c.opening.close()
		}
		c.err = c.Conn.Close()
		c.owner.releaseRaw(c)
	})
	return c.err
}

func (c *ownedRawConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

func (c *ownedRawConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *ownedRawConn) SetKeepAlive(enabled bool) error {
	if tc, ok := c.Conn.(interface{ SetKeepAlive(bool) error }); ok {
		return tc.SetKeepAlive(enabled)
	}
	return nil
}

func (c *ownedRawConn) SetKeepAlivePeriod(period time.Duration) error {
	if tc, ok := c.Conn.(interface{ SetKeepAlivePeriod(time.Duration) error }); ok {
		return tc.SetKeepAlivePeriod(period)
	}
	return nil
}
