package client

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestH3WriteDeadlineInterruptsPendingSend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := &quicPacketConn{ctx: ctx}
	started := make(chan struct{})
	var startOnce sync.Once
	result := make(chan error, 1)
	go func() {
		result <- conn.sendWithWriteDeadline(func(ctx context.Context) error {
			startOnce.Do(func() { close(started) })
			<-ctx.Done()
			return ctx.Err()
		})
	}()
	<-started
	if err := conn.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("pending send returned %v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("updated write deadline did not interrupt pending send")
	}
}

func TestH3WriteDeadlineExtensionRetriesPendingSend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := &quicPacketConn{ctx: ctx}
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		calls := 0
		result <- conn.sendWithWriteDeadline(func(ctx context.Context) error {
			calls++
			if calls == 1 {
				close(started)
				<-ctx.Done()
				return ctx.Err()
			}
			return nil
		})
	}()
	<-started
	if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("send after deadline extension: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline extension did not retry pending send")
	}
}

func TestH3WriteDeadlineClearRetriesPendingSend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := &quicPacketConn{ctx: ctx}
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		calls := 0
		result <- conn.sendWithWriteDeadline(func(ctx context.Context) error {
			calls++
			if calls == 1 {
				close(started)
				<-ctx.Done()
				return ctx.Err()
			}
			if _, hasDeadline := ctx.Deadline(); hasDeadline {
				return errors.New("cleared write deadline retained a timer")
			}
			return nil
		})
	}()
	<-started
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("send after clearing deadline: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("clearing deadline did not retry pending send")
	}
}
