package client

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrPoolAtCapacity indicates the carrier pool cannot expand further.
	ErrPoolAtCapacity = errors.New("chitanda: connection pool reached maximum capacity")

	// ErrUnsupportedTransport indicates that the selected transport does not support pooling or scaling.
	ErrUnsupportedTransport = errors.New("chitanda: transport does not support carrier scaling")
)

// PoolStats provides a point-in-time snapshot of carrier health and load distribution.
type PoolStats struct {
	Transport          string
	TotalCarriers      int
	BaseCarriers       int
	DynamicCarriers    int
	ActiveStreams      []int64
	MinActiveStreams   int64
	MaxActiveStreams   int64
	TotalActiveStreams int64
}

// PoolController defines the interface exposed to autoscaler plugins to inspect and modify connection pools.
type PoolController interface {
	Stats(transport string) PoolStats
	AddCarrier(ctx context.Context, transport string) error
	RemoveIdleCarrier(transport string, minIdle time.Duration) (bool, error)
	BasePoolSize(transport string) int
	MaxPoolSize() int
}

// AutoscalerPlugin is the interface that connection pool autoscaling plugins must implement.
type AutoscalerPlugin interface {
	Init(controller PoolController) error
	OnActivity(transport string, minActive int64, totalCarriers int)
	Close() error
}

// BasePoolSize returns the statically configured minimum base carriers for the given transport.
func (c *Client) BasePoolSize(transport string) int {
	if transport == "h3" {
		return c.baseH3Carriers
	}
	return c.baseH2Carriers
}

// MaxPoolSize returns the upper bound limit for total carriers.
func (c *Client) MaxPoolSize() int {
	return c.maxCarriers
}

// Stats returns a thread-safe snapshot of the carrier pool for the given transport.
func (c *Client) Stats(transport string) PoolStats {
	c.carrierMu.RLock()
	defer c.carrierMu.RUnlock()

	if transport == "h2" {
		total := len(c.h2Clients)
		base := c.baseH2Carriers
		if base > total {
			base = total
		}
		stats := PoolStats{
			Transport:       "h2",
			TotalCarriers:   total,
			BaseCarriers:    base,
			DynamicCarriers: total - base,
			ActiveStreams:   make([]int64, total),
		}
		if total == 0 {
			return stats
		}
		var minStreams, maxStreams, sumStreams int64
		minStreams = c.h2Clients[0].activeStreams.Load()
		maxStreams = minStreams
		for i, cli := range c.h2Clients {
			act := cli.activeStreams.Load()
			stats.ActiveStreams[i] = act
			sumStreams += act
			if act < minStreams {
				minStreams = act
			}
			if act > maxStreams {
				maxStreams = act
			}
		}
		stats.MinActiveStreams = minStreams
		stats.MaxActiveStreams = maxStreams
		stats.TotalActiveStreams = sumStreams
		return stats
	} else if transport == "h3" {
		total := len(c.h3Managers)
		base := c.baseH3Carriers
		if base > total {
			base = total
		}
		stats := PoolStats{
			Transport:       "h3",
			TotalCarriers:   total,
			BaseCarriers:    base,
			DynamicCarriers: total - base,
			ActiveStreams:   make([]int64, total),
		}
		if total == 0 {
			return stats
		}
		var minStreams, maxStreams, sumStreams int64
		minStreams = c.h3Managers[0].activeStreams.Load()
		maxStreams = minStreams
		for i, mgr := range c.h3Managers {
			act := mgr.activeStreams.Load()
			stats.ActiveStreams[i] = act
			sumStreams += act
			if act < minStreams {
				minStreams = act
			}
			if act > maxStreams {
				maxStreams = act
			}
		}
		stats.MinActiveStreams = minStreams
		stats.MaxActiveStreams = maxStreams
		stats.TotalActiveStreams = sumStreams
		return stats
	}
	return PoolStats{Transport: transport}
}

// AddCarrier dynamically creates, handshakes, and registers a new carrier into the pool.
// It verifies context deadlines and probes physical connectivity before accepting the carrier.
func (c *Client) AddCarrier(ctx context.Context, transport string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("client closed")
	}
	c.mu.Unlock()

	now := time.Now()

	if transport == "h2" {
		c.carrierMu.RLock()
		if len(c.h2Clients) >= c.maxCarriers {
			c.carrierMu.RUnlock()
			return ErrPoolAtCapacity
		}
		c.carrierMu.RUnlock()

		h2Cli, err := newH2TransportClient(c.cfg.Server, c.cfg.ServerName, c.rootURL, c.requestURL, c.cfg.Path, c.cfg.PSK, c.cfg.InsecureSkipVerify, c.cfg.DialContext)
		if err != nil {
			return fmt.Errorf("create h2 carrier: %w", err)
		}

		// Verify physical connectivity and context cancellation
		probeCtx, cancelProbe := context.WithTimeout(ctx, 3*time.Second)
		err = h2Cli.prewarm(probeCtx)
		cancelProbe()
		if err != nil {
			h2Cli.close()
			return fmt.Errorf("probe h2 carrier failed: %w", err)
		}

		h2Cli.isDynamic = true
		h2Cli.idleSince = now

		// Close also acquires c.mu before carrierMu. Hold both locks while
		// registering so Close cannot drain the pool between the check and append.
		c.mu.Lock()
		c.carrierMu.Lock()
		closed := c.closed
		ctxErr := ctx.Err()
		atCapacity := len(c.h2Clients) >= c.maxCarriers
		if !closed && ctxErr == nil && !atCapacity {
			c.h2Clients = append(c.h2Clients, h2Cli)
		}
		c.carrierMu.Unlock()
		c.mu.Unlock()
		if closed || ctxErr != nil || atCapacity {
			h2Cli.close()
			if closed {
				return errors.New("client closed")
			}
			if ctxErr != nil {
				return ctxErr
			}
			return ErrPoolAtCapacity
		}
		return nil
	} else if transport == "h3" {
		c.carrierMu.RLock()
		if len(c.h3Managers) >= c.maxCarriers {
			c.carrierMu.RUnlock()
			return ErrPoolAtCapacity
		}
		c.carrierMu.RUnlock()

		mgr := newH3TransportManager(
			c.cfg.Server, c.cfg.ServerName, c.rootURL, c.requestURL, c.cfg.Path, c.cfg.PSK, c.sessionCache, c.cfg.QUICInitialPacketSize, c.cfg.InsecureSkipVerify, c.cfg.ListenPacket, c.cfg.ResolveUDP, c.cfg.DialPacket,
		)

		// Verify physical connectivity and context cancellation
		probeCtx, cancelProbe := context.WithTimeout(ctx, 3*time.Second)
		err := mgr.prewarm(probeCtx)
		cancelProbe()
		if err != nil {
			mgr.close()
			return fmt.Errorf("probe h3 carrier failed: %w", err)
		}

		mgr.isDynamic = true
		mgr.idleSince = now

		c.mu.Lock()
		c.carrierMu.Lock()
		closed := c.closed
		ctxErr := ctx.Err()
		atCapacity := len(c.h3Managers) >= c.maxCarriers
		if !closed && ctxErr == nil && !atCapacity {
			c.h3Managers = append(c.h3Managers, mgr)
		}
		c.carrierMu.Unlock()
		c.mu.Unlock()
		if closed || ctxErr != nil || atCapacity {
			mgr.close()
			if closed {
				return errors.New("client closed")
			}
			if ctxErr != nil {
				return ctxErr
			}
			return ErrPoolAtCapacity
		}
		return nil
	}
	return ErrUnsupportedTransport
}

// RemoveIdleCarrier inspects dynamically-spawned carriers and evicts one if it has been idle (0 active streams) for >= minIdle.
func (c *Client) RemoveIdleCarrier(transport string, minIdle time.Duration) (bool, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return false, errors.New("client closed")
	}
	c.mu.Unlock()

	now := time.Now()

	if transport == "h2" {
		c.carrierMu.Lock()
		base := c.baseH2Carriers
		if len(c.h2Clients) <= base {
			c.carrierMu.Unlock()
			return false, nil
		}

		candidateIdx := -1
		for i := base; i < len(c.h2Clients); i++ {
			cli := c.h2Clients[i]
			if cli.activeStreams.Load() == 0 {
				if cli.idleSince.IsZero() {
					cli.idleSince = now
				}
				if minIdle == 0 || now.Sub(cli.idleSince) >= minIdle {
					candidateIdx = i
					break
				}
			} else {
				cli.idleSince = time.Time{}
			}
		}

		if candidateIdx == -1 {
			c.carrierMu.Unlock()
			return false, nil
		}

		evicted := c.h2Clients[candidateIdx]
		c.h2Clients = append(c.h2Clients[:candidateIdx], c.h2Clients[candidateIdx+1:]...)
		c.carrierMu.Unlock()

		evicted.close()
		return true, nil
	} else if transport == "h3" {
		c.carrierMu.Lock()
		base := c.baseH3Carriers
		if len(c.h3Managers) <= base {
			c.carrierMu.Unlock()
			return false, nil
		}

		candidateIdx := -1
		for i := base; i < len(c.h3Managers); i++ {
			mgr := c.h3Managers[i]
			if mgr.activeStreams.Load() == 0 {
				if mgr.idleSince.IsZero() {
					mgr.idleSince = now
				}
				if minIdle == 0 || now.Sub(mgr.idleSince) >= minIdle {
					candidateIdx = i
					break
				}
			} else {
				mgr.idleSince = time.Time{}
			}
		}

		if candidateIdx == -1 {
			c.carrierMu.Unlock()
			return false, nil
		}

		evicted := c.h3Managers[candidateIdx]
		c.h3Managers = append(c.h3Managers[:candidateIdx], c.h3Managers[candidateIdx+1:]...)
		c.carrierMu.Unlock()

		evicted.close()
		return true, nil
	}
	return false, ErrUnsupportedTransport
}
