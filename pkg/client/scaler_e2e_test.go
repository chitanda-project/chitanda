package client_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/client"
	"github.com/violetaini/chitanda/pkg/plugin/autoscaler"
)

func TestClient_AutoscalerE2E(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 2048)
				for {
					_, err := c.Read(buf)
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	testPSK := make([]byte, 32)
	for i := range testPSK {
		testPSK[i] = 0x55
	}

	scaler := autoscaler.New(autoscaler.Config{
		MaxCarriers:      4,
		ScaleUpThreshold: 2, // scale up when all carriers have >= 2 streams
		ScaleDownIdle:    50 * time.Millisecond,
		Cooldown:         20 * time.Millisecond,
		SweepInterval:    50 * time.Millisecond,
	})

	cli, err := client.New(client.Config{
		Server:       ln.Addr().String(),
		ServerName:   "localhost",
		Path:         "/e2e",
		PSK:          testPSK,
		TCPTransport: client.TCPTransportH2,
		TCPPoolSize:  2,
		MaxPoolSize:  4,
		Autoscaler:   scaler,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", ln.Addr().String())
		},
	})
	if err != nil {
		t.Fatalf("New client error: %v", err)
	}
	defer cli.Close()

	// 1. Initial State: 2 base carriers
	stats := cli.Stats("h2")
	if stats.TotalCarriers != 2 {
		t.Fatalf("expected 2 initial carriers, got %d", stats.TotalCarriers)
	}

	// 2. Simulate Load: Artificially record 2 streams per carrier by calling Stats check or pickBest
	// Under threshold=2, calling pickBest twice on 2 carriers gives activeStreams=0 initially
	// Let's verify stats are working
	if stats.MinActiveStreams != 0 {
		t.Fatalf("expected 0 active streams initially, got %d", stats.MinActiveStreams)
	}

	// Directly trigger AddCarrier through pool controller to verify scaler works with client
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := cli.AddCarrier(ctx, "h2"); err != nil {
		t.Fatalf("AddCarrier failed: %v", err)
	}

	stats = cli.Stats("h2")
	if stats.TotalCarriers != 3 {
		t.Fatalf("expected 3 carriers after AddCarrier, got %d", stats.TotalCarriers)
	}

	// Wait for idle duration (50ms) and trigger sweep
	time.Sleep(100 * time.Millisecond)
	scaler.TriggerSweep()

	stats = cli.Stats("h2")
	if stats.TotalCarriers != 2 {
		t.Fatalf("expected carrier to be evicted back to 2 base carriers, got %d", stats.TotalCarriers)
	}
}
