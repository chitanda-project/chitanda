package chitanda

import (
	"context"
	"fmt"
	"net"
	"strings"
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
	userIndex int
	session   uint64
	target    string
}
type udpRoute struct {
	conn   *packetLinkConn
	cancel context.CancelFunc
	last   atomic.Int64
}
type icmpRoute struct {
	pconn  net.PacketConn
	target net.IP
	cancel context.CancelFunc
	last   atomic.Int64
}
type udpRoutes struct {
	ctx         context.Context
	cancel      context.CancelFunc
	dispatcher  routing.Dispatcher
	codecs      []*server.PlainUDPCodec
	outer       net.Conn
	mu          sync.Mutex
	writes      sync.Mutex
	closed      bool
	entries     map[udpRouteKey]*udpRoute
	icmpEntries map[udpRouteKey]*icmpRoute
	dialICMP    func(ctx context.Context, address string) (net.PacketConn, error)
	wg          sync.WaitGroup
}

// A UDP association owns the route lifetime, while each authenticated packet
// supplies the user identity. Prefer packet-scoped values over the physical
// connection's inbound metadata so Xray does not lose the authenticated user.
type udpRouteValueContext struct {
	context.Context
	packet context.Context
}

func (c udpRouteValueContext) Value(key any) any {
	if value := c.packet.Value(key); value != nil {
		return value
	}
	return c.Context.Value(key)
}

func newUDPRoutes(ctx context.Context, d routing.Dispatcher, codecs []*server.PlainUDPCodec, outer net.Conn, dialICMP ...func(ctx context.Context, address string) (net.PacketConn, error)) *udpRoutes {
	ctx, cancel := context.WithCancel(ctx)
	var dialICMPFn func(ctx context.Context, address string) (net.PacketConn, error)
	if len(dialICMP) > 0 {
		dialICMPFn = dialICMP[0]
	}
	r := &udpRoutes{
		ctx:         ctx,
		cancel:      cancel,
		dispatcher:  d,
		codecs:      codecs,
		outer:       outer,
		entries:     make(map[udpRouteKey]*udpRoute),
		icmpEntries: make(map[udpRouteKey]*icmpRoute),
		dialICMP:    dialICMPFn,
	}
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
	var expiredICMP []*icmpRoute
	for key, entry := range r.icmpEntries {
		if now.Sub(time.Unix(0, entry.last.Load())) >= udpRouteIdle {
			delete(r.icmpEntries, key)
			expiredICMP = append(expiredICMP, entry)
		}
	}
	r.mu.Unlock()
	for _, entry := range expired {
		entry.cancel()
		_ = entry.conn.Close()
	}
	for _, entry := range expiredICMP {
		entry.cancel()
		_ = entry.pconn.Close()
	}
}

func (r *udpRoutes) Write(ctx context.Context, userIndex int, sid uint64, dest xnet.Destination, payload []byte) error {
	key := udpRouteKey{userIndex, sid, dest.NetAddr()}
	r.mu.Lock()
	if r.closed || r.ctx.Err() != nil {
		r.mu.Unlock()
		return net.ErrClosed
	}
	entry := r.entries[key]
	if entry == nil {
		if len(r.entries)+len(r.icmpEntries) >= maxUDPRoutes {
			r.mu.Unlock()
			return fmt.Errorf("chitanda: UDP target limit reached")
		}
		// Preserve packet policy, but bind its lifetime to the association and
		// give this session/target its own mutable routing and sniffing state.
		flowCtx, cancel := context.WithCancel(udpRouteValueContext{Context: r.ctx, packet: ctx})
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

func (r *udpRoutes) WriteICMP(ctx context.Context, userIndex int, sid uint64, targetAddr string, payload []byte) error {
	key := udpRouteKey{userIndex, sid, targetAddr}
	r.mu.Lock()
	if r.closed || r.ctx.Err() != nil {
		r.mu.Unlock()
		return net.ErrClosed
	}
	entry := r.icmpEntries[key]
	if entry == nil {
		if len(r.entries)+len(r.icmpEntries) >= maxUDPRoutes {
			r.mu.Unlock()
			return fmt.Errorf("chitanda: UDP target limit reached")
		}
		targetIPStr := strings.TrimPrefix(targetAddr, "icmp:")
		targetIP := net.ParseIP(targetIPStr)
		if targetIP == nil {
			r.mu.Unlock()
			return fmt.Errorf("chitanda: invalid icmp target %q", targetAddr)
		}
		var pconn net.PacketConn
		var err error
		if r.dialICMP != nil {
			pconn, err = r.dialICMP(ctx, targetIPStr)
		} else {
			network := "ip4:icmp"
			listenAddr := "0.0.0.0"
			if targetIP.To4() == nil {
				network = "ip6:ipv6-icmp"
				listenAddr = "::"
			}
			pconn, err = net.ListenPacket(network, listenAddr)
		}
		if err != nil {
			r.mu.Unlock()
			return err
		}
		_, cancel := context.WithCancel(r.ctx)
		entry = &icmpRoute{pconn: pconn, target: targetIP, cancel: cancel}
		r.icmpEntries[key] = entry
		entry.last.Store(time.Now().UnixNano())
		r.wg.Add(1)
		go r.receiveICMP(key, entry)
	}
	entry.last.Store(time.Now().UnixNano())
	r.mu.Unlock()

	_, err := entry.pconn.WriteTo(payload, &net.IPAddr{IP: entry.target})
	if err != nil {
		r.removeICMP(key, entry)
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

func (r *udpRoutes) removeICMP(key udpRouteKey, entry *icmpRoute) {
	r.mu.Lock()
	if r.icmpEntries[key] == entry {
		delete(r.icmpEntries, key)
	}
	r.mu.Unlock()
	entry.cancel()
	_ = entry.pconn.Close()
}

func (r *udpRoutes) receive(key udpRouteKey, entry *udpRoute) {
	defer r.wg.Done()
	defer r.remove(key, entry)
	buffer := make([]byte, 65535)
	var codec *server.PlainUDPCodec
	if key.userIndex >= 0 && key.userIndex < len(r.codecs) {
		codec = r.codecs[key.userIndex]
	}
	if codec == nil {
		return
	}
	for {
		n, from, err := entry.conn.ReadFrom(buffer)
		if err != nil {
			return
		}
		entry.last.Store(time.Now().UnixNano())
		encoded, err := codec.EncodeServerPacket(key.session, from.String(), buffer[:n], time.Now())
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

func (r *udpRoutes) receiveICMP(key udpRouteKey, entry *icmpRoute) {
	defer r.wg.Done()
	defer r.removeICMP(key, entry)
	buffer := make([]byte, 2048)
	var codec *server.PlainUDPCodec
	if key.userIndex >= 0 && key.userIndex < len(r.codecs) {
		codec = r.codecs[key.userIndex]
	}
	if codec == nil {
		return
	}
	for {
		_ = entry.pconn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, from, err := entry.pconn.ReadFrom(buffer)
		if err != nil {
			return
		}
		fromIP := from.String()
		if fip, _, err := net.SplitHostPort(fromIP); err == nil {
			fromIP = fip
		}
		if fromIP != entry.target.String() {
			continue
		}
		entry.last.Store(time.Now().UnixNano())
		encoded, err := codec.EncodeServerPacket(key.session, "icmp:"+fromIP, buffer[:n], time.Now())
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
	icmpEntries := r.icmpEntries
	r.icmpEntries = make(map[udpRouteKey]*icmpRoute)
	r.mu.Unlock()
	// Process owns the outer association. Wake any response blocked on write
	// before joining readers; Close is also safe after EOF/caller cancellation.
	_ = r.outer.Close()
	for _, entry := range entries {
		entry.cancel()
		_ = entry.conn.Close()
	}
	for _, entry := range icmpEntries {
		entry.cancel()
		_ = entry.pconn.Close()
	}
	r.wg.Wait()
}
