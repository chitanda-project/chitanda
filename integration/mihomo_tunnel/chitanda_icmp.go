package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// OpenChitandaICMP applies Mihomo's current UDP routing rules before choosing
// whether ICMP may use Chitanda. Unsupported proxy selections fail closed;
// they must not silently leak a packet through the machine's direct route.
func (t tunnel) OpenChitandaICMP(ctx context.Context, source, destination netip.Addr) (net.PacketConn, bool, error) {
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.TUN,
		SrcIP:   source.Unmap(),
		DstIP:   destination.Unmap(),
	}
	proxy, rule, err := resolveMetadata(metadata)
	if err != nil {
		return nil, false, err
	}
	if proxy == nil {
		return nil, false, fmt.Errorf("ICMP route has no outbound proxy")
	}
	pc, handled, err := openChitandaICMPPacket(ctx, proxy, metadata)
	if err != nil || !handled {
		return nil, handled, err
	}
	return statistic.NewUDPTracker(pc, statistic.DefaultManager, metadata, rule, 0, 0, true), true, nil
}

func openChitandaICMPPacket(ctx context.Context, proxy C.Proxy, metadata *C.Metadata) (C.PacketConn, bool, error) {
	selected := proxy
	var groups []C.Proxy
	for selected != nil {
		if selected.Type() == C.Chitanda {
			if !chitandaICMPSupported(selected) {
				return nil, false, fmt.Errorf("Chitanda ICMP is disabled")
			}
			// Dial the leaf that was checked. A proxy group may choose a different
			// member on its next ListenPacketContext call (e.g. round robin).
			pc, err := selected.ListenPacketContext(ctx, metadata)
			if err != nil {
				return nil, false, err
			}
			for i := len(groups) - 1; i >= 0; i-- {
				pc.AppendToChains(groups[i])
			}
			return pc, true, nil
		}
		if selected.Type() == C.Direct {
			return nil, false, nil
		}
		group := selected
		selected = group.Unwrap(metadata, true)
		if selected == group {
			return nil, false, fmt.Errorf("selected proxy %q unwraps to itself", group.Name())
		}
		groups = append(groups, group)
	}
	return nil, false, fmt.Errorf("selected proxy %q does not support ICMP", proxy.Name())
}

func chitandaICMPSupported(proxy C.Proxy) bool {
	// Mihomo wraps outbound adapters before exposing them through Adapter(),
	// so an optional method on the concrete Chitanda type is not visible
	// here. Chitanda's ICMP capability follows its UDP setting.
	return proxy.Type() == C.Chitanda && proxy.SupportUDP()
}
