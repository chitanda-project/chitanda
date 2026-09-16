package chitanda

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/violetaini/chitanda/pkg/server"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
)

const maxUDPRoutes = 64
const udpRouteIdle = time.Minute

type udpRouteKey struct {
	session uint64
	target  string
}
type udpRoute struct {
	conn   *packetLinkConn
	cancel context.CancelFunc
	last   atomic.Int64
}
type udpRoutes struct {
	ctx        context.Context
	cancel     context.CancelFunc
	dispatcher routing.Dispatcher
	codec      *server.PlainUDPCodec
	outer      net.Conn
	mu         sync.Mutex
	writes     sync.Mutex
	closed     bool
	entries    map[udpRouteKey]*udpRoute
	wg         sync.WaitGroup
}

func newUDPRoutes(ctx context.Context, d routing.Dispatcher, codec *server.PlainUDPCodec, outer net.Conn) *udpRoutes {
	ctx, cancel := context.WithCancel(ctx)
	r := &udpRoutes{ctx: ctx, cancel: cancel, dispatcher: d, codec: codec, outer: outer, entries: make(map[udpRouteKey]*udpRoute)}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				r.expire(now)
			}
		}
	}()
	return r
}

func (r *udpRoutes) expire(now time.Time) {
	r.mu.Lock()
	var expired []*udpRoute
	for key, entry := range r.entries {
		if now.Sub(time.Unix(0, entry.last.Load())) >= udpRouteIdle {
			delete(r.entries, key)
			expired = append(expired, entry)
		}
	}
	r.mu.Unlock()
	for _, entry := range expired {
		entry.cancel()
		_ = entry.conn.Close()
	}
}

func (r *udpRoutes) Write(ctx context.Context, sid uint64, dest xnet.Destination, payload []byte) error {
	key := udpRouteKey{sid, dest.NetAddr()}
	r.mu.Lock()
	if r.closed || r.ctx.Err() != nil {
		r.mu.Unlock()
		return net.ErrClosed
	}
	entry := r.entries[key]
	if entry == nil {
		if len(r.entries) >= maxUDPRoutes {
			r.mu.Unlock()
			return fmt.Errorf("chitanda: UDP target limit reached")
		}
		// Preserve packet policy, but bind its lifetime to the association and
		// give this session/target its own mutable routing and sniffing state.
		flowCtx, cancel := context.WithCancel(inboundValueContext{Context: r.ctx, values: ctx})
		link, err := r.dispatcher.Dispatch(requestContext(flowCtx), dest)
		if err != nil {
			cancel()
			r.mu.Unlock()
			return err
		}
		entry = &udpRoute{conn: newPacketLinkConn(link.Reader, link.Writer, packetAddress(dest.NetAddr())), cancel: cancel}
		r.entries[key] = entry
		entry.last.Store(time.Now().UnixNano())
		r.wg.Add(1)
		go r.receive(key, entry)
	}
	entry.last.Store(time.Now().UnixNano())
	r.mu.Unlock()
	_, err := entry.conn.Write(payload)
	if err != nil {
		r.remove(key, entry)
	}
	return err
}

func (r *udpRoutes) remove(key udpRouteKey, entry *udpRoute) {
	r.mu.Lock()
	if r.entries[key] == entry {
		delete(r.entries, key)
	}
	r.mu.Unlock()
	entry.cancel()
	_ = entry.conn.Close()
}
func (r *udpRoutes) receive(key udpRouteKey, entry *udpRoute) {
	defer r.wg.Done()
	defer r.remove(key, entry)
	buffer := make([]byte, 65535)
	for {
		n, from, err := entry.conn.ReadFrom(buffer)
		if err != nil {
			return
		}
		entry.last.Store(time.Now().UnixNano())
		encoded, err := r.codec.EncodeServerPacket(key.session, from.String(), buffer[:n], time.Now())
		if err != nil {
			continue
		}
		r.writes.Lock()
		_, err = r.outer.Write(encoded)
		r.writes.Unlock()
		if err != nil {
			return
		}
	}
}
func (r *udpRoutes) Close() {
	r.cancel()
	r.mu.Lock()
	r.closed = true
	entries := r.entries
	r.entries = make(map[udpRouteKey]*udpRoute)
	r.mu.Unlock()
	// Process owns the outer association. Wake any response blocked on write
	// before joining readers; Close is also safe after EOF/caller cancellation.
	_ = r.outer.Close()
	for _, entry := range entries {
		entry.cancel()
		_ = entry.conn.Close()
	}
	r.wg.Wait()
}
