package client

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
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

func startMockListener(t *testing.T) (net.Listener, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	stopCh := make(chan struct{})
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

	cleanup := func() {
		close(stopCh)
		_ = ln.Close()
	}
	return ln, cleanup
}

func TestClient_ScalerPoolController(t *testing.T) {
	ln, cleanup := startMockListener(t)
	defer cleanup()

	dummyScaler := &dummyAutoscaler{}
	testPSK := make([]byte, 32)
	for i := range testPSK {
		testPSK[i] = 0x42
	}

	cli, err := New(Config{
		Server:       ln.Addr().String(),
		ServerName:   "localhost",
		Path:         "/test",
		PSK:          testPSK,
		TCPTransport: TCPTransportH2,
		TCPPoolSize:  2,
		UDPPoolSize:  2,
		MaxPoolSize:  5,
		Autoscaler:   dummyScaler,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", ln.Addr().String())
		},
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

func TestClient_ScalerConcurrentSafety(t *testing.T) {
	ln, cleanup := startMockListener(t)
	defer cleanup()

	testPSK := make([]byte, 32)
	for i := range testPSK {
		testPSK[i] = 0x99
	}

	cli, err := New(Config{
		Server:       ln.Addr().String(),
		ServerName:   "localhost",
		Path:         "/concurrent",
		PSK:          testPSK,
		TCPTransport: TCPTransportH2,
		TCPPoolSize:  2,
		MaxPoolSize:  6,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", ln.Addr().String())
		},
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
					c.activeStreams.Add(1)
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
