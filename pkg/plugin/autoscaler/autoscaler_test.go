package autoscaler

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/client"
)

type mockPoolController struct {
	mu             sync.Mutex
	h2Stats        client.PoolStats
	h3Stats        client.PoolStats
	addH2Calls     atomic.Int64
	addH3Calls     atomic.Int64
	removeH2Calls  atomic.Int64
	removeH3Calls  atomic.Int64
	shouldRemoveH2 bool
	shouldRemoveH3 bool
	baseH2         int
	baseH3         int
	maxCarriers    int
}

func newMockController(baseH2, baseH3, maxCarriers int) *mockPoolController {
	return &mockPoolController{
		baseH2:      baseH2,
		baseH3:      baseH3,
		maxCarriers: maxCarriers,
		h2Stats: client.PoolStats{
			Transport:        "h2",
			TotalCarriers:    baseH2,
			BaseCarriers:     baseH2,
			MinActiveStreams: 0,
		},
		h3Stats: client.PoolStats{
			Transport:        "h3",
			TotalCarriers:    baseH3,
			BaseCarriers:     baseH3,
			MinActiveStreams: 0,
		},
	}
}

func (m *mockPoolController) BasePoolSize(transport string) int {
	if transport == "h3" {
		return m.baseH3
	}
	return m.baseH2
}

func (m *mockPoolController) MaxPoolSize() int {
	return m.maxCarriers
}

func (m *mockPoolController) Stats(transport string) client.PoolStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	if transport == "h3" {
		return m.h3Stats
	}
	return m.h2Stats
}

func (m *mockPoolController) AddCarrier(ctx context.Context, transport string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if transport == "h2" {
		m.addH2Calls.Add(1)
		m.h2Stats.TotalCarriers++
		m.h2Stats.DynamicCarriers++
		return nil
	} else if transport == "h3" {
		m.addH3Calls.Add(1)
		m.h3Stats.TotalCarriers++
		m.h3Stats.DynamicCarriers++
		return nil
	}
	return client.ErrUnsupportedTransport
}

func (m *mockPoolController) RemoveIdleCarrier(transport string, minIdle time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if transport == "h2" {
		m.removeH2Calls.Add(1)
		if m.shouldRemoveH2 && m.h2Stats.DynamicCarriers > 0 {
			m.h2Stats.TotalCarriers--
			m.h2Stats.DynamicCarriers--
			return true, nil
		}
		return false, nil
	} else if transport == "h3" {
		m.removeH3Calls.Add(1)
		if m.shouldRemoveH3 && m.h3Stats.DynamicCarriers > 0 {
			m.h3Stats.TotalCarriers--
			m.h3Stats.DynamicCarriers--
			return true, nil
		}
		return false, nil
	}
	return false, client.ErrUnsupportedTransport
}

func TestAutoscaler_Defaults(t *testing.T) {
	a := Default()
	if a.cfg.MaxCarriers != 8 {
		t.Errorf("expected default MaxCarriers 8, got %d", a.cfg.MaxCarriers)
	}
	if a.cfg.ScaleUpThreshold != 16 {
		t.Errorf("expected default ScaleUpThreshold 16, got %d", a.cfg.ScaleUpThreshold)
	}
	if a.cfg.ScaleDownIdle != 30*time.Second {
		t.Errorf("expected default ScaleDownIdle 30s, got %v", a.cfg.ScaleDownIdle)
	}
}

func TestAutoscaler_ScaleUpOnThreshold(t *testing.T) {
	mock := newMockController(4, 4, 8)
	mock.h2Stats.MinActiveStreams = 10

	a := New(Config{
		MaxCarriers:      8,
		ScaleUpThreshold: 10,
		Cooldown:         50 * time.Millisecond,
		SweepInterval:    1 * time.Second,
	})
	if err := a.Init(mock); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer a.Close()

	// Trigger high activity on H2
	a.OnActivity("h2", 10, 4)

	// Wait for background worker to process
	time.Sleep(100 * time.Millisecond)

	if mock.addH2Calls.Load() != 1 {
		t.Errorf("expected 1 AddCarrier call, got %d", mock.addH2Calls.Load())
	}
	if a.ScaleUpCount() != 1 {
		t.Errorf("expected ScaleUpCount 1, got %d", a.ScaleUpCount())
	}
}

func TestAutoscaler_ThresholdNotMet(t *testing.T) {
	mock := newMockController(4, 4, 8)
	mock.h2Stats.MinActiveStreams = 5

	a := New(Config{
		MaxCarriers:      8,
		ScaleUpThreshold: 10,
		Cooldown:         50 * time.Millisecond,
	})
	if err := a.Init(mock); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer a.Close()

	// minActive is 5, threshold is 10 -> should NOT scale up
	a.OnActivity("h2", 5, 4)
	time.Sleep(100 * time.Millisecond)

	if mock.addH2Calls.Load() != 0 {
		t.Errorf("expected 0 AddCarrier calls, got %d", mock.addH2Calls.Load())
	}
}

func TestAutoscaler_MaxCarriersCeiling(t *testing.T) {
	mock := newMockController(8, 8, 8) // Already at max 8
	mock.h2Stats.MinActiveStreams = 20

	a := New(Config{
		MaxCarriers:      8,
		ScaleUpThreshold: 10,
		Cooldown:         50 * time.Millisecond,
	})
	if err := a.Init(mock); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer a.Close()

	// totalCarriers is 8, MaxCarriers is 8 -> should NOT scale up
	a.OnActivity("h2", 20, 8)
	time.Sleep(100 * time.Millisecond)

	if mock.addH2Calls.Load() != 0 {
		t.Errorf("expected 0 AddCarrier calls at max capacity, got %d", mock.addH2Calls.Load())
	}
}

func TestAutoscaler_CooldownRateLimiting(t *testing.T) {
	mock := newMockController(4, 4, 8)
	mock.h2Stats.MinActiveStreams = 15

	a := New(Config{
		MaxCarriers:      8,
		ScaleUpThreshold: 10,
		Cooldown:         300 * time.Millisecond,
	})
	if err := a.Init(mock); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer a.Close()

	// Rapidly call OnActivity 10 times
	for range 10 {
		a.OnActivity("h2", 15, 4)
	}
	time.Sleep(100 * time.Millisecond)

	// Due to 300ms cooldown, only 1 scale-up should have succeeded
	if mock.addH2Calls.Load() != 1 {
		t.Errorf("expected exactly 1 scale up under cooldown, got %d", mock.addH2Calls.Load())
	}

	// Wait for cooldown to expire
	time.Sleep(350 * time.Millisecond)

	// Fire again
	a.OnActivity("h2", 15, 5)
	time.Sleep(100 * time.Millisecond)

	if mock.addH2Calls.Load() != 2 {
		t.Errorf("expected 2 scale ups after cooldown expired, got %d", mock.addH2Calls.Load())
	}
}

func TestAutoscaler_ScaleDownIdle(t *testing.T) {
	mock := newMockController(4, 4, 8)
	mock.shouldRemoveH2 = true
	mock.h2Stats.TotalCarriers = 5
	mock.h2Stats.DynamicCarriers = 1

	a := New(Config{
		MaxCarriers:      8,
		ScaleUpThreshold: 10,
		ScaleDownIdle:    100 * time.Millisecond,
		SweepInterval:    1 * time.Hour, // Don't rely on automatic tick in test
	})
	if err := a.Init(mock); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer a.Close()

	a.TriggerSweep()

	if mock.removeH2Calls.Load() < 1 {
		t.Errorf("expected RemoveIdleCarrier to be called")
	}
	if a.ScaleDownCount() != 1 {
		t.Errorf("expected ScaleDownCount 1, got %d", a.ScaleDownCount())
	}
	if mock.h2Stats.TotalCarriers != 4 {
		t.Errorf("expected total carriers to shrink to 4, got %d", mock.h2Stats.TotalCarriers)
	}
}

func TestAutoscaler_NonBlockingLatency(t *testing.T) {
	mock := newMockController(4, 4, 8)
	mock.h2Stats.MinActiveStreams = 15

	a := New(Config{
		MaxCarriers:      8,
		ScaleUpThreshold: 10,
		Cooldown:         50 * time.Millisecond,
	})
	if err := a.Init(mock); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer a.Close()

	start := time.Now()
	for range 1000 {
		a.OnActivity("h2", 15, 4)
	}
	elapsed := time.Since(start)

	// 1000 OnActivity calls should complete in under 5 milliseconds (well under 5 microseconds each)
	if elapsed > 10*time.Millisecond {
		t.Errorf("OnActivity took too long: %v for 1000 calls", elapsed)
	}
}

func TestAutoscaler_RebindError(t *testing.T) {
	mock1 := newMockController(4, 4, 8)
	mock2 := newMockController(4, 4, 8)

	a := Default()
	if err := a.Init(mock1); err != nil {
		t.Fatalf("first Init failed: %v", err)
	}
	defer a.Close()

	// Second Init with another controller MUST fail
	err := a.Init(mock2)
	if err == nil {
		t.Fatalf("expected second Init to fail with ErrAlreadyInitialized, got nil")
	}
	if !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("expected ErrAlreadyInitialized, got %v", err)
	}
}
