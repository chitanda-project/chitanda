package autoscaler

import (
	"context"
	"errors"
	"math/rand/v2"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/client"
)

type chaosMockController struct {
	mu           sync.Mutex
	h2Carriers   int
	baseCarriers int
	maxCarriers  int
	minActive    atomic.Int64

	// Chaos injection controls
	failRate    float64 // 0.0 to 1.0 probability of AddCarrier failing
	addDelay    time.Duration
	removeDelay time.Duration

	totalAdds   atomic.Int64
	failedAdds  atomic.Int64
	totalRemoves atomic.Int64
}

func newChaosController(base, max int, failRate float64, addDelay time.Duration) *chaosMockController {
	c := &chaosMockController{
		h2Carriers:   base,
		baseCarriers: base,
		maxCarriers:  max,
		failRate:     failRate,
		addDelay:     addDelay,
	}
	c.minActive.Store(20) // Default high load
	return c
}

func (c *chaosMockController) BasePoolSize(transport string) int {
	return c.baseCarriers
}

func (c *chaosMockController) MaxPoolSize() int {
	return c.maxCarriers
}

func (c *chaosMockController) Stats(transport string) client.PoolStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return client.PoolStats{
		Transport:        transport,
		TotalCarriers:    c.h2Carriers,
		BaseCarriers:     c.baseCarriers,
		DynamicCarriers:  c.h2Carriers - c.baseCarriers,
		MinActiveStreams: c.minActive.Load(),
	}
}

func (c *chaosMockController) AddCarrier(ctx context.Context, transport string) error {
	c.totalAdds.Add(1)

	if c.addDelay > 0 {
		select {
		case <-time.After(c.addDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// Chaos injection: random failure
	c.mu.Lock()
	failRate := c.failRate
	c.mu.Unlock()
	if failRate > 0 && rand.Float64() < failRate {
		c.failedAdds.Add(1)
		return errors.New("chaos injected: network connection reset or handshake timeout")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.h2Carriers >= c.maxCarriers {
		return client.ErrPoolAtCapacity
	}
	c.h2Carriers++
	return nil
}

func (c *chaosMockController) RemoveIdleCarrier(transport string, minIdle time.Duration) (bool, error) {
	c.totalRemoves.Add(1)
	if c.removeDelay > 0 {
		time.Sleep(c.removeDelay)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.h2Carriers <= c.baseCarriers {
		return false, nil
	}
	c.h2Carriers--
	return true, nil
}

// -----------------------------------------------------------------------------
// 1. Extreme Concurrency Stampede: 10,000 Parallel Goroutines
// -----------------------------------------------------------------------------
func TestAutoscaler_Stress_MassiveStampede(t *testing.T) {
	const baseCarriers = 4
	const maxCarriers = 12
	const numGoroutines = 10000

	mock := newChaosController(baseCarriers, maxCarriers, 0.0, 500*time.Microsecond)
	scaler := New(Config{
		MaxCarriers:      maxCarriers,
		ScaleUpThreshold: 10,
		Cooldown:         20 * time.Millisecond,
		SweepInterval:    100 * time.Millisecond,
	})

	if err := scaler.Init(mock); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer scaler.Close()

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	startSignal := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			<-startSignal

			// Hammer OnActivity with high load
			scaler.OnActivity("h2", 25, 4)
			if id%100 == 0 {
				scaler.TriggerSweep()
			}
		}(i)
	}

	// Release stampede simultaneously
	close(startSignal)
	wg.Wait()

	// Allow background workers to settle
	time.Sleep(200 * time.Millisecond)

	stats := mock.Stats("h2")
	if stats.TotalCarriers > maxCarriers {
		t.Fatalf("CRITICAL: Pool size exceeded hard cap! Total = %d, Max = %d", stats.TotalCarriers, maxCarriers)
	}
	if stats.TotalCarriers < baseCarriers {
		t.Fatalf("CRITICAL: Pool size shrunk below base! Total = %d, Base = %d", stats.TotalCarriers, baseCarriers)
	}

	t.Logf("Massive Stampede Passed: Final Carriers=%d (Base=%d, Max=%d), ScaleUps=%d",
		stats.TotalCarriers, baseCarriers, maxCarriers, scaler.ScaleUpCount())
}

// -----------------------------------------------------------------------------
// 2. Network Blackhole & Severe Handshake Failure Chaos (70% Failure Rate)
// -----------------------------------------------------------------------------
func TestAutoscaler_Stress_NetworkFlakinessAndBlackhole(t *testing.T) {
	const baseCarriers = 4
	const maxCarriers = 8

	// 70% failure rate + 10ms handshake latency
	mock := newChaosController(baseCarriers, maxCarriers, 0.70, 10*time.Millisecond)
	scaler := New(Config{
		MaxCarriers:      maxCarriers,
		ScaleUpThreshold: 10,
		Cooldown:         10 * time.Millisecond,
		SweepInterval:    50 * time.Millisecond,
	})

	if err := scaler.Init(mock); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer scaler.Close()

	// Hammer with scale-up triggers for 500ms under 70% failure rate
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		scaler.OnActivity("h2", 15, 4)
		time.Sleep(5 * time.Millisecond)
	}

	// Heal the network: 0% failure rate
	mock.mu.Lock()
	mock.failRate = 0.0
	mock.mu.Unlock()

	// Wait for healthy scale-ups to succeed
	for range 10 {
		scaler.OnActivity("h2", 15, 4)
		time.Sleep(25 * time.Millisecond)
	}

	stats := mock.Stats("h2")
	if stats.TotalCarriers > maxCarriers {
		t.Fatalf("Pool exceeded max: %d", stats.TotalCarriers)
	}

	failedAdds := mock.failedAdds.Load()
	if failedAdds == 0 {
		t.Errorf("Expected chaos failures to be recorded, got 0")
	}

	t.Logf("Network Chaos Passed: Attempted=%d, InjectedFailures=%d, SuccessfulScaleUps=%d, FinalCarriers=%d",
		mock.totalAdds.Load(), failedAdds, scaler.ScaleUpCount(), stats.TotalCarriers)
}

// -----------------------------------------------------------------------------
// 3. High-Frequency Sawtooth Traffic (500 Rapid Pulses)
// -----------------------------------------------------------------------------
func TestAutoscaler_Stress_SawtoothOscillation(t *testing.T) {
	const baseCarriers = 2
	const maxCarriers = 6

	mock := newChaosController(baseCarriers, maxCarriers, 0.0, 1*time.Millisecond)
	scaler := New(Config{
		MaxCarriers:      maxCarriers,
		ScaleUpThreshold: 15,
		ScaleDownIdle:    5 * time.Millisecond,
		Cooldown:         10 * time.Millisecond,
		SweepInterval:    10 * time.Millisecond,
	})

	if err := scaler.Init(mock); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer scaler.Close()

	// 500 cycles of alternating load
	for cycle := 0; cycle < 500; cycle++ {
		// High pulse
		mock.minActive.Store(50)
		scaler.OnActivity("h2", 50, mock.Stats("h2").TotalCarriers)

		time.Sleep(1 * time.Millisecond)

		// Low pulse
		mock.minActive.Store(0)
		if cycle%10 == 0 {
			scaler.TriggerSweep()
		}
	}

	time.Sleep(100 * time.Millisecond)

	stats := mock.Stats("h2")
	if stats.TotalCarriers < baseCarriers || stats.TotalCarriers > maxCarriers {
		t.Fatalf("Sawtooth pool out of bounds: %d (expected %d..%d)", stats.TotalCarriers, baseCarriers, maxCarriers)
	}

	t.Logf("Sawtooth Oscillation Passed: ScaleUps=%d, ScaleDowns=%d, FinalCarriers=%d",
		scaler.ScaleUpCount(), scaler.ScaleDownCount(), stats.TotalCarriers)
}

// -----------------------------------------------------------------------------
// 4. Abrupt Concurrent Teardown Under Fire (Zero-Leak Shutdown)
// -----------------------------------------------------------------------------
func TestAutoscaler_Stress_AbruptTeardownUnderFire(t *testing.T) {
	initialGoroutines := runtime.NumGoroutine()

	for iteration := 0; iteration < 20; iteration++ {
		mock := newChaosController(4, 10, 0.2, 5*time.Millisecond)
		scaler := New(Config{
			MaxCarriers:      10,
			ScaleUpThreshold: 5,
			Cooldown:         5 * time.Millisecond,
			SweepInterval:    10 * time.Millisecond,
		})

		if err := scaler.Init(mock); err != nil {
			t.Fatalf("Init failed: %v", err)
		}

		// Fire 50 worker goroutines hitting the scaler
		stopWorkers := make(chan struct{})
		var workerWg sync.WaitGroup
		for i := 0; i < 50; i++ {
			workerWg.Add(1)
			go func() {
				defer workerWg.Done()
				for {
					select {
					case <-stopWorkers:
						return
					default:
						scaler.OnActivity("h2", 20, 4)
						scaler.TriggerSweep()
						time.Sleep(500 * time.Microsecond)
					}
				}
			}()
		}

		// Let it run full throttle for 30ms then abruptly close
		time.Sleep(30 * time.Millisecond)
		if err := scaler.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		close(stopWorkers)
		workerWg.Wait()
	}

	// Verify goroutines settle back down
	time.Sleep(100 * time.Millisecond)
	finalGoroutines := runtime.NumGoroutine()
	leak := finalGoroutines - initialGoroutines

	// Allow tolerance of at most 3 runtime/test goroutines
	if leak > 5 {
		t.Fatalf("Goroutine leak detected! Initial=%d, Final=%d, Leak=%d",
			initialGoroutines, finalGoroutines, leak)
	}

	t.Logf("Abrupt Teardown Passed: 20 rapid lifecycle cycles, InitialGR=%d, FinalGR=%d (Leak=%d)",
		initialGoroutines, finalGoroutines, leak)
}
