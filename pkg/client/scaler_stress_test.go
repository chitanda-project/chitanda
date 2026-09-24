package client_test

import (
	"context"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/client"
	"github.com/violetaini/chitanda/pkg/plugin/autoscaler"
)

// startDuplexLoopbackServer creates a raw TCP echo listener for client stress testing.
func startDuplexLoopbackServer(t *testing.T) (net.Listener, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create stress listener: %v", err)
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
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					// Echo back
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return ln, func() {
		close(stopCh)
		_ = ln.Close()
	}
}

// -----------------------------------------------------------------------------
// 1. Extreme Concurrency on Real Client: 200 Workers + Active Scaling
// -----------------------------------------------------------------------------
func TestClient_Stress_MassiveParallelScaling(t *testing.T) {
	ln, cleanup := startDuplexLoopbackServer(t)
	defer cleanup()

	testPSK := make([]byte, 32)
	for i := range testPSK {
		testPSK[i] = 0x77
	}

	scaler := autoscaler.New(autoscaler.Config{
		MaxCarriers:      6,
		ScaleUpThreshold: 5,
		Cooldown:         10 * time.Millisecond,
		SweepInterval:    20 * time.Millisecond,
		ScaleDownIdle:    20 * time.Millisecond,
	})

	cli, err := client.New(client.Config{
		Server:       ln.Addr().String(),
		ServerName:   "localhost",
		Path:         "/stress",
		PSK:          testPSK,
		TCPTransport: client.TCPTransportH2,
		TCPPoolSize:  2,
		MaxPoolSize:  6,
		Autoscaler:   scaler,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", ln.Addr().String())
		},
	})
	if err != nil {
		t.Fatalf("New client failed: %v", err)
	}
	defer cli.Close()

	const numWorkers = 200
	var wg sync.WaitGroup
	wg.Add(numWorkers)

	var successOps atomic.Int64
	var failedOps atomic.Int64

	startSignal := make(chan struct{})

	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			<-startSignal

			for j := 0; j < 50; j++ {
				// Query stats
				stats := cli.Stats("h2")
				if stats.TotalCarriers < 2 || stats.TotalCarriers > 6 {
					failedOps.Add(1)
					return
				}

				// Trigger expansion check
				if j%10 == 0 {
					scaler.OnActivity("h2", 10, stats.TotalCarriers)
				}
				if j%15 == 0 {
					scaler.TriggerSweep()
				}
				successOps.Add(1)
				time.Sleep(100 * time.Microsecond)
			}
		}(i)
	}

	close(startSignal)
	wg.Wait()

	if failed := failedOps.Load(); failed > 0 {
		t.Fatalf("Encountered %d pool bounds violations during extreme concurrency", failed)
	}

	stats := cli.Stats("h2")
	t.Logf("Massive Parallel Scaling Passed: 200 workers, %d ops, FinalCarriers=%d (ScaleUps=%d, ScaleDowns=%d)",
		successOps.Load(), stats.TotalCarriers, scaler.ScaleUpCount(), scaler.ScaleDownCount())
}

// -----------------------------------------------------------------------------
// 2. High-Contention Race: Concurrent AddCarrier vs RemoveIdleCarrier
// -----------------------------------------------------------------------------
func TestClient_Stress_AddRemoveCollisionRace(t *testing.T) {
	ln, cleanup := startDuplexLoopbackServer(t)
	defer cleanup()

	testPSK := make([]byte, 32)
	for i := range testPSK {
		testPSK[i] = 0xAA
	}

	cli, err := client.New(client.Config{
		Server:       ln.Addr().String(),
		ServerName:   "localhost",
		Path:         "/collision",
		PSK:          testPSK,
		TCPTransport: client.TCPTransportH2,
		TCPPoolSize:  2,
		MaxPoolSize:  8,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", ln.Addr().String())
		},
	})
	if err != nil {
		t.Fatalf("New client failed: %v", err)
	}
	defer cli.Close()

	ctx := context.Background()
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// 10 Goroutines repeatedly adding carriers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = cli.AddCarrier(ctx, "h2")
					time.Sleep(50 * time.Microsecond)
				}
			}
		}()
	}

	// 10 Goroutines repeatedly removing carriers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = cli.RemoveIdleCarrier("h2", 0)
					time.Sleep(50 * time.Microsecond)
				}
			}
		}()
	}

	// 20 Goroutines reading stats
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					s := cli.Stats("h2")
					if s.TotalCarriers < 2 || s.TotalCarriers > 8 {
						t.Errorf("Pool size out of bounds: %d", s.TotalCarriers)
						return
					}
					time.Sleep(20 * time.Microsecond)
				}
			}
		}()
	}

	// Let the collision race run full blast for 500ms
	time.Sleep(500 * time.Millisecond)
	close(stop)
	wg.Wait()

	finalStats := cli.Stats("h2")
	if finalStats.TotalCarriers < 2 || finalStats.TotalCarriers > 8 {
		t.Fatalf("Final pool size out of bounds: %d", finalStats.TotalCarriers)
	}
	t.Logf("Add/Remove Collision Race Passed: FinalCarriers=%d (2..8)", finalStats.TotalCarriers)
}

// -----------------------------------------------------------------------------
// 3. Client Lifecycle Zero-Leak Benchmark
// -----------------------------------------------------------------------------
func TestClient_Stress_ZeroLeakLifecycle(t *testing.T) {
	ln, cleanup := startDuplexLoopbackServer(t)
	defer cleanup()

	testPSK := make([]byte, 32)
	for i := range testPSK {
		testPSK[i] = 0x88
	}

	initialGR := runtime.NumGoroutine()

	for cycle := 0; cycle < 15; cycle++ {
		scaler := autoscaler.New(autoscaler.Config{
			MaxCarriers:      6,
			ScaleUpThreshold: 5,
			Cooldown:         5 * time.Millisecond,
			SweepInterval:    10 * time.Millisecond,
		})

		cli, err := client.New(client.Config{
			Server:       ln.Addr().String(),
			ServerName:   "localhost",
			Path:         "/leak",
			PSK:          testPSK,
			TCPTransport: client.TCPTransportH2,
			TCPPoolSize:  2,
			MaxPoolSize:  6,
			Autoscaler:   scaler,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", ln.Addr().String())
			},
		})
		if err != nil {
			t.Fatalf("New client error: %v", err)
		}

		// Fire rapid scale-up
		ctx := context.Background()
		_ = cli.AddCarrier(ctx, "h2")
		_ = cli.AddCarrier(ctx, "h2")
		scaler.OnActivity("h2", 15, 4)

		time.Sleep(15 * time.Millisecond)
		cli.Close()
	}

	time.Sleep(100 * time.Millisecond)
	finalGR := runtime.NumGoroutine()
	diff := finalGR - initialGR

	if diff > 5 {
		t.Fatalf("Client lifecycle goroutine leak detected: Initial=%d, Final=%d, Diff=%d",
			initialGR, finalGR, diff)
	}
	t.Logf("Zero Leak Lifecycle Passed: InitialGR=%d, FinalGR=%d, Diff=%d", initialGR, finalGR, diff)
}
