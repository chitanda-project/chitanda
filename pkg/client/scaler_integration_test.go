package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/server"
	"golang.org/x/net/http2"
)

type dummyAutoscaler struct {
	controller PoolController
	activityN  int
	mu         sync.Mutex
}

func (d *dummyAutoscaler) Init(c PoolController) error {
	d.controller = c
	return nil
}

func (d *dummyAutoscaler) OnActivity(transport string, minActive int64, totalCarriers int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.activityN++
}

func (d *dummyAutoscaler) Close() error {
	return nil
}

func startMockH2Server(t *testing.T, psk []byte) (*httptest.Server, func()) {
	srvHandler := server.NewServer("/test", psk, nil, nil, 1024)
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

func TestClient_ScalerPoolController(t *testing.T) {
	testPSK := make([]byte, 32)
	for i := range testPSK {
		testPSK[i] = 0x42
	}

	ts, cleanup := startMockH2Server(t, testPSK)
	defer cleanup()

	dummyScaler := &dummyAutoscaler{}

	cli, err := New(Config{
		Server:             ts.Listener.Addr().String(),
		ServerName:         "localhost",
		Path:               "/test",
		PSK:                testPSK,
		TCPTransport:       TCPTransportH2,
		TCPPoolSize:        2,
		UDPPoolSize:        2,
		MaxPoolSize:        5,
		InsecureSkipVerify: true,
		Autoscaler:         dummyScaler,
	})
	if err != nil {
		t.Fatalf("New client error: %v", err)
	}
	defer cli.Close()

	if dummyScaler.controller == nil {
		t.Fatal("expected autoscaler to be initialized with PoolController")
	}

	// 1. Initial Pool Stats
	stats := cli.Stats("h2")
	if stats.TotalCarriers != 2 {
		t.Fatalf("expected 2 initial H2 carriers, got %d", stats.TotalCarriers)
	}
	if stats.BaseCarriers != 2 {
		t.Fatalf("expected 2 base carriers, got %d", stats.BaseCarriers)
	}
	if stats.DynamicCarriers != 0 {
		t.Fatalf("expected 0 dynamic carriers initially, got %d", stats.DynamicCarriers)
	}

	// 2. Trigger pickBestH2Client and verify OnActivity was called
	h2Cli := cli.pickBestH2Client()
	if h2Cli == nil {
		t.Fatal("pickBestH2Client returned nil")
	}
	defer h2Cli.activeStreams.Add(-1)
	dummyScaler.mu.Lock()
	actCount := dummyScaler.activityN
	dummyScaler.mu.Unlock()
	if actCount != 1 {
		t.Fatalf("expected OnActivity to be called once, got %d", actCount)
	}

	// 3. Dynamically Add Carrier
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := cli.AddCarrier(ctx, "h2"); err != nil {
		t.Fatalf("AddCarrier failed: %v", err)
	}

	stats = cli.Stats("h2")
	if stats.TotalCarriers != 3 {
		t.Fatalf("expected 3 carriers after scale-up, got %d", stats.TotalCarriers)
	}
	if stats.DynamicCarriers != 1 {
		t.Fatalf("expected 1 dynamic carrier after scale-up, got %d", stats.DynamicCarriers)
	}
	// A selected carrier must be reserved before the idle sweeper can evict it.
	cli.h2Clients[0].activeStreams.Add(100)
	cli.h2Clients[1].activeStreams.Add(100)
	selected := cli.pickBestH2Client()
	if selected != cli.h2Clients[2] || selected.activeStreams.Load() != 1 {
		t.Fatal("dynamic H2 carrier was not reserved during selection")
	}
	if removed, err := cli.RemoveIdleCarrier("h2", 0); err != nil || removed {
		t.Fatalf("reserved H2 carrier was evicted: removed=%v err=%v", removed, err)
	}
	selected.activeStreams.Add(-1)
	cli.h2Clients[0].activeStreams.Add(-100)
	cli.h2Clients[1].activeStreams.Add(-100)

	// 4. Remove Dynamic Idle Carrier
	removed, err := cli.RemoveIdleCarrier("h2", 0)
	if err != nil {
		t.Fatalf("RemoveIdleCarrier failed: %v", err)
	}
	if !removed {
		t.Fatalf("expected dynamic carrier to be removed")
	}

	stats = cli.Stats("h2")
	if stats.TotalCarriers != 2 {
		t.Fatalf("expected 2 carriers after scale-down, got %d", stats.TotalCarriers)
	}
	if stats.DynamicCarriers != 0 {
		t.Fatalf("expected 0 dynamic carriers after scale-down, got %d", stats.DynamicCarriers)
	}

	// 5. Verify Base Carriers Are NEVER Removed
	removed, err = cli.RemoveIdleCarrier("h2", 0)
	if err != nil {
		t.Fatalf("RemoveIdleCarrier failed on base pool: %v", err)
	}
	if removed {
		t.Fatalf("base carrier should never be removed!")
	}
	stats = cli.Stats("h2")
	if stats.TotalCarriers != 2 {
		t.Fatalf("expected pool to stay at 2 base carriers, got %d", stats.TotalCarriers)
	}
}

func TestClient_H3CarrierProbeConfirmsHandshake(t *testing.T) {
	cli, cleanup := reviewH3(t, http.NotFoundHandler())
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := cli.AddCarrier(ctx, "h3"); err != nil {
		t.Fatalf("H3 carrier handshake probe failed: %v", err)
	}
	if stats := cli.Stats("h3"); stats.TotalCarriers != 2 || stats.DynamicCarriers != 1 {
		t.Fatalf("H3 carrier was not added after handshake: %+v", stats)
	}
}

func TestClient_H3CarrierProbeRejectsUnreachablePeer(t *testing.T) {
	cli, err := New(Config{
		Server: "127.0.0.1:59999", ServerName: "localhost", Path: "/probe-fail",
		PSK: []byte("test-only-key-that-is-at-least-32-bytes"), TCPTransport: TCPTransportH3,
		TCPPoolSize: 1, MaxPoolSize: 2, InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := cli.AddCarrier(ctx, "h3"); err == nil {
		t.Fatal("unreachable H3 carrier was accepted")
	}
	if stats := cli.Stats("h3"); stats.TotalCarriers != 1 {
		t.Fatalf("failed H3 probe expanded pool: %+v", stats)
	}
}

func TestClient_ScalerConcurrentSafety(t *testing.T) {
	testPSK := make([]byte, 32)
	for i := range testPSK {
		testPSK[i] = 0x99
	}

	ts, cleanup := startMockH2Server(t, testPSK)
	defer cleanup()

	cli, err := New(Config{
		Server:             ts.Listener.Addr().String(),
		ServerName:         "localhost",
		Path:               "/test",
		PSK:                testPSK,
		TCPTransport:       TCPTransportH2,
		TCPPoolSize:        2,
		MaxPoolSize:        6,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("New client error: %v", err)
	}
	defer cli.Close()

	var wg sync.WaitGroup
	ctx := context.Background()

	// Launch parallel pickers
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				c := cli.pickBestH2Client()
				if c != nil {
					time.Sleep(10 * time.Microsecond)
					c.activeStreams.Add(-1)
				}
			}
		}()
	}

	// Launch parallel scale-up and scale-down operations
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 5 {
				_ = cli.AddCarrier(ctx, "h2")
				time.Sleep(50 * time.Microsecond)
				_, _ = cli.RemoveIdleCarrier("h2", 0)
			}
		}()
	}

	// Launch parallel stats readers
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				_ = cli.Stats("h2")
				time.Sleep(20 * time.Microsecond)
			}
		}()
	}

	wg.Wait()
}

// TestClient_BaseCarriersPreservedUnderAutoMode verifies Codex bug #2:
// Under Auto mode with TCPPoolSize: 4, UDPPoolSize: 2, 4 H3 managers are initialized as base channels.
// They must NOT be misclassified as dynamic channels or evicted on idle sweep!
func TestClient_BaseCarriersPreservedUnderAutoMode(t *testing.T) {
	testPSK := make([]byte, 32)
	for i := range testPSK {
		testPSK[i] = 0x33
	}

	cli, err := New(Config{
		Server:       "127.0.0.1:443",
		ServerName:   "localhost",
		Path:         "/auto-test",
		PSK:          testPSK,
		TCPTransport: TCPTransportAuto,
		TCPPoolSize:  4,
		UDPPoolSize:  2,
		MaxPoolSize:  8,
	})
	if err != nil {
		t.Fatalf("New client error: %v", err)
	}
	defer cli.Close()

	// Under Auto mode with TCP=4, UDP=2:
	// H2 base count is 4.
	// H3 base count is max(4, 2) = 4 (for failover).
	h3Stats := cli.Stats("h3")
	if h3Stats.BaseCarriers != 4 {
		t.Fatalf("expected 4 base H3 carriers, got %d", h3Stats.BaseCarriers)
	}
	if h3Stats.DynamicCarriers != 0 {
		t.Fatalf("expected 0 dynamic H3 carriers initially, got %d", h3Stats.DynamicCarriers)
	}

	// Try to remove idle carrier: MUST return false and not evict any of the 4 initial H3 carriers
	removed, err := cli.RemoveIdleCarrier("h3", 0)
	if err != nil {
		t.Fatalf("RemoveIdleCarrier failed: %v", err)
	}
	if removed {
		t.Fatalf("CRITICAL BUG REPRODUCED: initial H3 base carrier was wrongly evicted!")
	}

	h3Stats = cli.Stats("h3")
	if h3Stats.TotalCarriers != 4 {
		t.Fatalf("expected pool to retain all 4 base carriers, got %d", h3Stats.TotalCarriers)
	}
}

// TestClient_AddCarrier_FailsOnCanceledContextOrUnreachableServer verifies Codex bug #3:
// AddCarrier must NOT return success if the context is canceled or the server is unreachable.
func TestClient_AddCarrier_FailsOnCanceledContextOrUnreachableServer(t *testing.T) {
	testPSK := make([]byte, 32)
	for i := range testPSK {
		testPSK[i] = 0x22
	}

	cli, err := New(Config{
		Server:       "127.0.0.1:59999", // Unreachable port
		ServerName:   "localhost",
		Path:         "/probe-fail",
		PSK:          testPSK,
		TCPTransport: TCPTransportH2,
		TCPPoolSize:  2,
		MaxPoolSize:  6,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New("connection refused by mock")
		},
	})
	if err != nil {
		t.Fatalf("New client error: %v", err)
	}
	defer cli.Close()

	// 1. Context already canceled
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	err = cli.AddCarrier(canceledCtx, "h2")
	if err == nil {
		t.Fatalf("expected AddCarrier to fail with canceled context, got nil")
	}

	// 2. Server unreachable (probe fails)
	validCtx, cancelValid := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancelValid()
	err = cli.AddCarrier(validCtx, "h2")
	if err == nil {
		t.Fatalf("CRITICAL BUG REPRODUCED: AddCarrier returned success on unreachable server!")
	}

	// Pool should NOT have expanded
	stats := cli.Stats("h2")
	if stats.TotalCarriers != 2 {
		t.Fatalf("expected pool to remain at 2, got %d", stats.TotalCarriers)
	}
}
