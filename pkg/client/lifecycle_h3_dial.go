package client

import (
	"context"
	"sync"
)

// A dial-only caller owns cancellation until handoff; the manager and physical
// carrier own it afterwards. Values survive for Xray's chained Dispatcher.
type h3DialLifetime struct {
	ctx, parent             context.Context
	cancel                  context.CancelFunc
	stopCaller, stopManager func() bool
	once                    sync.Once
}

func newH3DialLifetime(parent, manager context.Context) *h3DialLifetime {
	ctx, cancel := context.WithCancel(context.WithoutCancel(parent))
	d := &h3DialLifetime{ctx: ctx, parent: parent, cancel: cancel}
	d.stopCaller = context.AfterFunc(parent, cancel)
	d.stopManager = context.AfterFunc(manager, cancel)
	if parent.Err() != nil || manager.Err() != nil {
		cancel()
	}
	return d
}

func (d *h3DialLifetime) establish() error {
	d.stopCaller()
	if err := d.parent.Err(); err != nil {
		return err
	}
	return d.ctx.Err()
}

func (d *h3DialLifetime) close() {
	d.once.Do(func() { d.stopCaller(); d.stopManager(); d.cancel() })
}
