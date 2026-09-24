package client_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/client"
	"github.com/violetaini/chitanda/pkg/plugin/autoscaler"
	"github.com/violetaini/chitanda/pkg/server"
	"golang.org/x/net/http2"
)

// startStressH2Server creates a real H2 TLS server for client stress testing.
func startStressH2Server(t *testing.T, psk []byte) (*httptest.Server, func()) {
	srvHandler := server.NewServer("/stress", psk, nil, nil, 1024)
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

// -----------------------------------------------------------------------------
// 1. Extreme Concurrency on Real Client: 200 Workers + Active Scaling
// -----------------------------------------------------------------------------
func TestClient_Stress_MassiveParallelScaling(t *testing.T) {
	testPSK := make([]byte, 32)
	for i := range testPSK {
		testPSK[i] = 0x77
	}

	ts, cleanup := startStressH2Server(t, testPSK)
	defer cleanup()

	scaler := autoscaler.New(autoscaler.Config{
		MaxCarriers:      6,
		ScaleUpThreshold: 5,
		Cooldown:         10 * time.Millisecond,
		SweepInterval:    20 * time.Millisecond,
		ScaleDownIdle:    20 * time.Millisecond,
	})

	cli, err := client.New(client.Config{
		Server:             ts.Listener.Addr().String(),
		ServerName:         "localhost",
		Path:               "/stress",
		PSK:                testPSK,
		TCPTransport:       client.TCPTransportH2,
		TCPPoolSize:        2,
		MaxPoolSize:        6,
		InsecureSkipVerify: true,
		Autoscaler:         scaler,
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
				stats := cli.Stats("h2")
				if stats.TotalCarriers < 2 || stats.TotalCarriers > 6 {
					failedOps.Add(1)
					return
				}

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
	testPSK := make([]byte, 32)
	for i := range testPSK {
		testPSK[i] = 0xAA
	}

	ts, cleanup := startStressH2Server(t, testPSK)
	defer cleanup()

	cli, err := client.New(client.Config{
		Server:             ts.Listener.Addr().String(),
		ServerName:         "localhost",
		Path:               "/stress",
		PSK:                testPSK,
		TCPTransport:       client.TCPTransportH2,
		TCPPoolSize:        2,
		MaxPoolSize:        8,
		InsecureSkipVerify: true,
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

	time.Sleep(300 * time.Millisecond)
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
	testPSK := make([]byte, 32)
	for i := range testPSK {
		testPSK[i] = 0x88
	}

	ts, cleanup := startStressH2Server(t, testPSK)
	defer cleanup()

	initialGR := runtime.NumGoroutine()

	for cycle := 0; cycle < 15; cycle++ {
		scaler := autoscaler.New(autoscaler.Config{
			MaxCarriers:      6,
			ScaleUpThreshold: 5,
			Cooldown:         5 * time.Millisecond,
			SweepInterval:    10 * time.Millisecond,
		})

		cli, err := client.New(client.Config{
			Server:             ts.Listener.Addr().String(),
			ServerName:         "localhost",
			Path:               "/stress",
			PSK:                testPSK,
			TCPTransport:       client.TCPTransportH2,
			TCPPoolSize:        2,
			MaxPoolSize:        6,
			InsecureSkipVerify: true,
			Autoscaler:         scaler,
		})
		if err != nil {
			t.Fatalf("New client error: %v", err)
		}

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
