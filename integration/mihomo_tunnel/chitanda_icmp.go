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
	selected := proxy
	for selected != nil {
		if selected.Type() == C.Chitanda {
			if capable, ok := selected.Adapter().(interface{ SupportICMP() bool }); !ok || !capable.SupportICMP() {
				return nil, false, fmt.Errorf("Chitanda ICMP is disabled")
			}
			pc, err := proxy.ListenPacketContext(ctx, metadata)
			if err != nil {
				return nil, false, err
			}
			return statistic.NewUDPTracker(pc, statistic.DefaultManager, metadata, rule, 0, 0, true), true, nil
		}
		if selected.Type() == C.Direct {
			return nil, false, nil
		}
		selected = selected.Unwrap(metadata, false)
	}
	return nil, false, fmt.Errorf("selected proxy %q does not support ICMP", proxy.Name())
}
