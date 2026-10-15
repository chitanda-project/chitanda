package outbound

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/violetaini/chitanda/pkg/client"
)

func TestChitandaClosedAdapterCannotReopen(t *testing.T) {
	for _, mode := range []string{"stream", "h1", "h2", "h3", "auto"} {
		for _, initialized := range []bool{false, true} {
			t.Run(mode+map[bool]string{false: "/before-init", true: "/after-init"}[initialized], func(t *testing.T) {
				n, err := NewChitanda(ChitandaOption{Name: "closed", Server: "127.0.0.1", Port: 443, PSK: strings.Repeat("x", 32), Transport: mode})
				if err != nil {
					t.Fatal(err)
				}
				defer n.Close()
				if initialized {
					if _, err := n.getClient(); err != nil {
						t.Fatal(err)
					}
				}
				if err := n.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := n.getClient(); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("getClient after Close=%v", err)
				}
				if _, err := n.DialContext(context.Background(), &C.Metadata{NetWork: C.TCP, Host: "must-not-resolve.invalid", DstPort: 80}); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("DialContext after Close=%v", err)
				}
				if _, err := n.ListenPacketContext(context.Background(), &C.Metadata{NetWork: C.UDP, Host: "must-not-resolve.invalid", DstPort: 53}); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("ListenPacketContext after Close=%v", err)
				}
				if n.client != nil {
					t.Fatal("closed adapter retained/recreated a client")
				}
			})
		}
	}
}

func TestChitandaClosedAdapterConcurrentInitialization(t *testing.T) {
	n, err := NewChitanda(ChitandaOption{Name: "race", Server: "127.0.0.1", Port: 443, PSK: strings.Repeat("x", 32), Transport: "auto"})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if i%2 == 0 {
				_ = n.Close()
			} else {
				_, _ = n.getClient()
			}
		}()
	}
	close(start)
	wg.Wait()
	if _, err := n.getClient(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("adapter revived after racing Close/init: %v", err)
	}
}

type validationPacketSocket struct {
	auditPacketSocket
	writes atomic.Int32
}

func (p *validationPacketSocket) WriteTo(b []byte, a net.Addr) (int, error) {
	p.writes.Add(1)
	return p.auditPacketSocket.WriteTo(b, a)
}

type validationBatchSocket struct {
	validationPacketSocket
	batches atomic.Int32
}

func (p *validationBatchSocket) WriteBatch(_ [][]byte, _ []net.Addr) error {
	p.batches.Add(1)
	return nil
}

type nilPacketAddress struct{}

func (*nilPacketAddress) Network() string { return "udp" }
func (a *nilPacketAddress) String() string {
	if a == nil {
		panic("typed nil must not be formatted")
	}
	return "example.invalid:53"
}

type domainPacketAddress string

func (domainPacketAddress) Network() string  { return "udp" }
func (a domainPacketAddress) String() string { return string(a) }

func TestChitandaPacketDestinationRejectsNilBeforeAnyWrite(t *testing.T) {
	var udp *net.UDPAddr
	var icmp *client.ICMPAddr
	var custom *nilPacketAddress
	good := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}
	for _, bad := range []net.Addr{nil, udp, icmp, custom, &client.ICMPAddr{}, &net.UDPAddr{Port: 0}} {
		for _, batchBackend := range []bool{false, true} {
			plain := &validationPacketSocket{}
			batch := &validationBatchSocket{}
			var backend net.PacketConn = plain
			if batchBackend {
				backend = batch
			}
			p := &chitandaICMPPacketConn{PacketConn: backend}
			if _, err := p.WriteTo([]byte("x"), bad); err == nil {
				t.Fatalf("single invalid %T accepted", bad)
			}
			if n, err := p.ChitandaBatchWrite([][]byte{[]byte("valid-prefix"), []byte("bad")}, []net.Addr{good, bad}); err == nil || n != 0 {
				t.Fatalf("invalid batch admitted prefix: n=%d err=%v", n, err)
			}
			if plain.writes.Load() != 0 || batch.writes.Load() != 0 || batch.batches.Load() != 0 {
				t.Fatal("invalid batch reached backend before all addresses were checked")
			}
		}
	}
}

func TestChitandaPacketDestinationValidAddressesAndICMPBatch(t *testing.T) {
	plain := &validationPacketSocket{}
	p := &chitandaICMPPacketConn{PacketConn: plain}
	for _, addr := range []net.Addr{&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}, &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 53}, domainPacketAddress("example.invalid:53")} {
		if _, err := p.WriteTo([]byte("ok"), addr); err != nil {
			t.Fatal(err)
		}
	}
	request := []byte{8, 0, 0xf7, 0xff, 0, 0, 0, 0}
	icmp := &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 0}
	good := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}
	before := plain.writes.Load()
	if n, err := p.ChitandaBatchWrite([][]byte{[]byte("valid-prefix"), []byte("not-icmp")}, []net.Addr{good, icmp}); err == nil || n != 0 {
		t.Fatalf("invalid ICMP admitted: %d %v", n, err)
	}
	if plain.writes.Load() != before {
		t.Fatal("invalid ICMP wrote a valid prefix")
	}
	if n, err := p.ChitandaBatchWrite([][]byte{request, []byte("dns")}, []net.Addr{icmp, good}); err != nil || n != len(request)+3 {
		t.Fatalf("valid mixed batch=%d %v", n, err)
	}
	batch := &validationBatchSocket{}
	bp := &chitandaICMPPacketConn{PacketConn: batch}
	if n, err := bp.ChitandaBatchWrite([][]byte{[]byte("one"), []byte("two")}, []net.Addr{good, good}); err != nil || n != 6 || batch.batches.Load() != 1 || batch.writes.Load() != 0 {
		t.Fatalf("valid UDP batch lost fast path: %d %v", n, err)
	}
}
