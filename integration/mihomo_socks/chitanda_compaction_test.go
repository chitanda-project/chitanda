package socks

import (
	"bytes"
	C "github.com/metacubex/mihomo/constant"
	"net"
	"testing"
)

type compactionConn struct {
	net.PacketConn
	data []byte
	addr net.Addr
}

func (c *compactionConn) WriteTo(p []byte, a net.Addr) (int, error) {
	c.data = append([]byte(nil), p...)
	c.addr = a
	return len(p), nil
}

func TestChitandaSOCKSCompactionPreservesPayloadAndWriteBack(t *testing.T) {
	backing := make([]byte, 16<<10)
	for i := range backing {
		backing[i] = 7
	}
	pc := &compactionConn{}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	released := 0
	p := &packet{pc: pc, rAddr: addr, payload: backing[:1200], put: func() { released++; clear(backing) }}
	adapter := C.NewPacketAdapter(p, &C.Metadata{})
	compact, ok := adapter.(interface{ CompactChitandaData() })
	if !ok {
		t.Fatal("ownership hook was lost at PacketAdapter boundary")
	}
	compact.CompactChitandaData()
	if released != 1 || cap(p.Data()) != 1200 || !bytes.Equal(p.Data(), bytes.Repeat([]byte{7}, 1200)) {
		t.Fatal("payload was not safely detached")
	}
	p.CompactChitandaData()
	if _, err := p.WriteBack([]byte("reply"), addr); err != nil {
		t.Fatal(err)
	}
	if pc.addr != addr || !bytes.HasSuffix(pc.data, []byte("reply")) {
		t.Fatal("WriteBack endpoint lost")
	}
	p.Drop()
	p.Drop()
	if released != 1 {
		t.Fatalf("pool release count = %d", released)
	}
}
