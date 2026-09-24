package client_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/client"
	"github.com/violetaini/chitanda/pkg/plugin/autoscaler"
	"github.com/violetaini/chitanda/pkg/server"
	"golang.org/x/net/http2"
)

func startE2EH2Server(t *testing.T, psk []byte) (*httptest.Server, func()) {
	srvHandler := server.NewServer("/e2e", psk, nil, nil, 1024)
	srvHandler.SetDialTargetForTest(func(ctx context.Context, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", address)
	})
	ts := httptest.NewUnstartedServer(srvHandler)
	if err := http2.ConfigureServer(ts.Config, &http2.Server{}); err != nil {
		t.Fatalf("ConfigureServer: %v", err)
	}
	ts.TLS = &tls.Config{NextProtos: []string{"h2"}}
	ts.StartTLS()
	return ts, func() { ts.Close() }
}

func TestClient_AutoscalerE2E(t *testing.T) {
	testPSK := make([]byte, 32)
	for i := range testPSK {
		testPSK[i] = 0x55
	}

	ts, cleanup := startE2EH2Server(t, testPSK)
	defer cleanup()

	scaler := autoscaler.New(autoscaler.Config{
		MaxCarriers:      4,
		ScaleUpThreshold: 2, // scale up when all carriers have >= 2 streams
		ScaleDownIdle:    50 * time.Millisecond,
		Cooldown:         20 * time.Millisecond,
		SweepInterval:    50 * time.Millisecond,
	})

	cli, err := client.New(client.Config{
		Server:             ts.Listener.Addr().String(),
		ServerName:         "localhost",
		Path:               "/e2e",
		PSK:                testPSK,
		TCPTransport:       client.TCPTransportH2,
		TCPPoolSize:        2,
		MaxPoolSize:        4,
		InsecureSkipVerify: true,
		Autoscaler:         scaler,
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
	if stats.BaseCarriers != 2 {
		t.Fatalf("expected 2 base carriers, got %d", stats.BaseCarriers)
	}

	// 2. Verified Physical AddCarrier
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := cli.AddCarrier(ctx, "h2"); err != nil {
		t.Fatalf("AddCarrier failed: %v", err)
	}

	stats = cli.Stats("h2")
	if stats.TotalCarriers != 3 {
		t.Fatalf("expected 3 carriers after AddCarrier, got %d", stats.TotalCarriers)
	}
	if stats.DynamicCarriers != 1 {
		t.Fatalf("expected 1 dynamic carrier, got %d", stats.DynamicCarriers)
	}

	// 3. Wait for idle duration (50ms) and trigger sweep
	time.Sleep(100 * time.Millisecond)
	scaler.TriggerSweep()

	stats = cli.Stats("h2")
	if stats.TotalCarriers != 2 {
		t.Fatalf("expected carrier to be evicted back to 2 base carriers, got %d", stats.TotalCarriers)
	}
}
