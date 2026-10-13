package client

import (
	"bytes"
	"net"
	"testing"
)

func TestH3BatchValidatesBeforeAdmission(t *testing.T) {
	c := &quicPacketConn{}
	for _, addrs := range [][]net.Addr{nil, {nil}, {(*net.UDPAddr)(nil)}, {(*ICMPAddr)(nil)}} {
		if err := c.WriteBatch([][]byte{[]byte("test")}, addrs); err == nil {
			t.Fatal("invalid batch accepted")
		}
		if c.sequence.Load() != 0 {
			t.Fatal("invalid batch consumed a sequence")
		}
	}
	if err := c.WriteBatch(nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestBufferedPipeLazyGrowthAndWrap(t *testing.T) {
	r, w := newBufferedPipe(1 << 20)
	if r.pipe.buf != nil {
		t.Fatal("idle pipe eagerly allocated")
	}
	first := bytes.Repeat([]byte{1}, 16000)
	if _, err := w.Write(first); err != nil {
		t.Fatal(err)
	}
	if len(r.pipe.buf) != 16*1024 {
		t.Fatalf("initial allocation = %d", len(r.pipe.buf))
	}
	read := make([]byte, 8000)
	if _, err := r.Read(read); err != nil {
		t.Fatal(err)
	}
	second := bytes.Repeat([]byte{2}, 24000)
	if _, err := w.Write(second); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 32000)
	if n, err := r.Read(got); err != nil || n != len(got) {
		t.Fatalf("read = %d, %v", n, err)
	}
	if !bytes.Equal(got, append(first[8000:], second...)) {
		t.Fatal("growth corrupted wrapped data")
	}
	_ = w.Close()
	_ = r.Close()
}
