package connio

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
)

func TestOwnedReaderPartialEOFAndCloseReturnsAllLeases(t *testing.T) {
	var acquired, released atomic.Int64
	stop := make(chan struct{})
	i := 0
	r := NewOwnedReader(func() ([]byte, net.Addr, func(), error) {
		i++
		if i > 3 {
			<-stop
			return nil, nil, nil, net.ErrClosed
		}
		acquired.Add(1)
		b := []byte("abcdefgh")
		var once atomic.Bool
		return b, nil, func() {
			if once.Swap(true) {
				t.Error("double release")
			}
			for j := range b {
				b[j] = 0
			}
			released.Add(1)
		}, nil
	}, func() error { close(stop); return nil })
	b := make([]byte, 1)
	if n, err := r.Read(b); n != 1 || err != nil || b[0] != 'a' {
		t.Fatal("first read")
	}
	if released.Load() != 0 {
		t.Fatal("partial buffer released early")
	}
	b = make([]byte, 7)
	if _, err := io.ReadFull(r, b); err != nil || string(b) != "bcdefgh" {
		t.Fatal("partial buffer overwritten")
	}
	_ = r.Close()
	_ = r.Close()
	if acquired.Load() != released.Load() {
		t.Fatalf("lease leak: %d %d", acquired.Load(), released.Load())
	}
}

func TestOwnedReaderReturnsLeaseOnShortPacketAndEOF(t *testing.T) {
	var releases atomic.Int64
	r := NewOwnedReader(func() ([]byte, net.Addr, func(), error) {
		return []byte("abc"), nil, func() { releases.Add(1) }, io.EOF
	}, nil)
	if _, _, err := r.ReadPacket(make([]byte, 1)); err != io.ErrShortBuffer {
		t.Fatal(err)
	}
	if releases.Load() != 1 {
		t.Fatal("discarded packet lease retained")
	}
	_ = r.Close()
}
