package tunnel

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// Mihomo's wrappers expose SupportUDP but not optional methods on the
// underlying Chitanda adapter. Embed the remainder of the proxy interface to
// simulate that wrapper without creating a test import cycle.
type wrappedChitandaProxy struct {
	C.Proxy
	udp bool
}

func (p wrappedChitandaProxy) Type() C.AdapterType     { return C.Chitanda }
func (p wrappedChitandaProxy) SupportUDP() bool        { return p.udp }
func (p wrappedChitandaProxy) Adapter() C.ProxyAdapter { return nil }

func TestChitandaICMPCapabilitySurvivesProxyWrapper(t *testing.T) {
	if !chitandaICMPSupported(wrappedChitandaProxy{udp: true}) {
		t.Fatal("wrapped Chitanda proxy lost ICMP capability")
	}
	if chitandaICMPSupported(wrappedChitandaProxy{udp: false}) {
		t.Fatal("ICMP was enabled despite UDP being disabled")
	}
}
