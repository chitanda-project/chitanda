package autoscaler

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/violetaini/chitanda/pkg/client"
)

var (
	// ErrAlreadyInitialized indicates Init was called multiple times on the same Autoscaler.
	ErrAlreadyInitialized = errors.New("autoscaler: already initialized")
	// ErrNotInitialized indicates an operation was attempted before Init.
	ErrNotInitialized = errors.New("autoscaler: not initialized")
)

// Config configures dynamic connection pool auto-scaling behavior.
type Config struct {
	// MaxCarriers is the upper bound on total carriers (default: 8, max: 16).
	MaxCarriers int

	// ScaleUpThreshold is the minimum active streams on all active carriers required to trigger expansion.
	// For example, if set to 16, a new carrier is added only when every existing carrier is handling >= 16 streams.
	// Default: 16.
	ScaleUpThreshold int64

	// ScaleDownIdle is the duration a dynamic carrier must maintain 0 active streams before being evicted.
	// Default: 30s.
	ScaleDownIdle time.Duration

	// Cooldown is the minimum duration required between successive carrier additions.
	// Default: 2s.
	Cooldown time.Duration

	// SweepInterval is how often the background monitor scans for idle dynamic carriers.
	// Default: 5s.
	SweepInterval time.Duration
}

// Autoscaler is a modular plugin that monitors client carrier load and dynamically expands and shrinks connection pools.
type Autoscaler struct {
	cfg        Config
	controller client.PoolController

	scaleUpH2Ch chan struct{}
	scaleUpH3Ch chan struct{}

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	scaleMu       sync.Mutex
	lastScaleUpH2 time.Time
	lastScaleUpH3 time.Time

	scaleUpCount   atomic.Int64
	scaleDownCount atomic.Int64

	initialized atomic.Bool
	closed      atomic.Bool
}

// New creates an Autoscaler plugin with the specified configuration.
func New(cfg Config) *Autoscaler {
	if cfg.MaxCarriers <= 0 {
		cfg.MaxCarriers = 8
	}
	if cfg.MaxCarriers > 16 {
		cfg.MaxCarriers = 16
	}
	if cfg.ScaleUpThreshold <= 0 {
		cfg.ScaleUpThreshold = 16
	}
	if cfg.ScaleDownIdle <= 0 {
		cfg.ScaleDownIdle = 30 * time.Second
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 2 * time.Second
	}
	if cfg.SweepInterval <= 0 {
		cfg.SweepInterval = 5 * time.Second
	}

	return &Autoscaler{
		cfg:         cfg,
		scaleUpH2Ch: make(chan struct{}, 1),
		scaleUpH3Ch: make(chan struct{}, 1),
	}
}

// Default creates an Autoscaler with production-safe gateway defaults.
func Default() *Autoscaler {
	return New(Config{})
}

// Init binds the autoscaler to a Client's PoolController and launches the background controller loop.
func (a *Autoscaler) Init(controller client.PoolController) error {
	if controller == nil {
		return errors.New("autoscaler: nil pool controller")
	}
	if !a.initialized.CompareAndSwap(false, true) {
		return ErrAlreadyInitialized
	}
	a.controller = controller

	if max := controller.MaxPoolSize(); max > 0 && max < a.cfg.MaxCarriers {
		a.cfg.MaxCarriers = max
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.ctx = ctx
	a.cancel = cancel

	a.wg.Add(1)
	go a.runLoop()
	return nil
}

// OnActivity is invoked by the Client when dispatching a stream. It performs non-blocking evaluation of load.
func (a *Autoscaler) OnActivity(transport string, minActive int64, totalCarriers int) {
	if a.closed.Load() {
		return
	}
	if minActive < a.cfg.ScaleUpThreshold {
		return
	}
	if totalCarriers >= a.cfg.MaxCarriers {
		return
	}

	if transport == "h2" {
		select {
		case a.scaleUpH2Ch <- struct{}{}:
		default:
		}
	} else if transport == "h3" {
		select {
		case a.scaleUpH3Ch <- struct{}{}:
		default:
		}
	}
}

func (a *Autoscaler) runLoop() {
	defer a.wg.Done()

	ticker := time.NewTicker(a.cfg.SweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.scaleUpH2Ch:
			a.tryScaleUp("h2")
		case <-a.scaleUpH3Ch:
			a.tryScaleUp("h3")
		case <-ticker.C:
			a.tryScaleDown("h2")
			a.tryScaleDown("h3")
		}
	}
}

func (a *Autoscaler) tryScaleUp(transport string) {
	a.scaleMu.Lock()
	defer a.scaleMu.Unlock()

	var lastScale *time.Time
	if transport == "h2" {
		lastScale = &a.lastScaleUpH2
	} else {
		lastScale = &a.lastScaleUpH3
	}

	if time.Since(*lastScale) < a.cfg.Cooldown {
		return
	}

	stats := a.controller.Stats(transport)
	if stats.TotalCarriers >= a.cfg.MaxCarriers {
		return
	}
	if stats.TotalCarriers > 0 && stats.MinActiveStreams < a.cfg.ScaleUpThreshold {
		return
	}

	ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
	defer cancel()

	err := a.controller.AddCarrier(ctx, transport)
	if err == nil {
		*lastScale = time.Now()
		a.scaleUpCount.Add(1)
	}
}

func (a *Autoscaler) tryScaleDown(transport string) {
	removed, err := a.controller.RemoveIdleCarrier(transport, a.cfg.ScaleDownIdle)
	if err == nil && removed {
		a.scaleDownCount.Add(1)
	}
}

// ScaleUpCount returns total scale-up operations performed.
func (a *Autoscaler) ScaleUpCount() int64 {
	return a.scaleUpCount.Load()
}

// ScaleDownCount returns total scale-down operations performed.
func (a *Autoscaler) ScaleDownCount() int64 {
	return a.scaleDownCount.Load()
}

// TriggerSweep forces an immediate idle sweep (useful for tests).
func (a *Autoscaler) TriggerSweep() {
	a.tryScaleDown("h2")
	a.tryScaleDown("h3")
}

// Close gracefully terminates the autoscaler background loop.
func (a *Autoscaler) Close() error {
	if a.closed.Swap(true) {
		return nil
	}
	if a.cancel != nil {
		a.cancel()
	}
	a.wg.Wait()
	return nil
}
