package h1session

import (
	"bytes"
	"io"
	"testing"
)

func TestAuthenticatedEOF(t *testing.T) {
	key := [32]byte{1}
	var wire bytes.Buffer
	enc, _ := NewAEADStream(key, DirClientToServer)
	w := NewFramedWriter(&wire, enc)
	w.Write([]byte("hello"))
	dataLen := wire.Len()
	if err := w.WriteEOF(); err != nil {
		t.Fatal(err)
	}
	valid := bytes.Clone(wire.Bytes())
	dec, _ := NewAEADStream(key, DirClientToServer)
	r := NewFramedReader(bytes.NewReader(valid), dec)
	p, err := io.ReadAll(r)
	if err != nil || string(p) != "hello" {
		t.Fatalf("roundtrip: %q %v", p, err)
	}
	for _, wire := range [][]byte{nil, {0, 0}, valid[:dataLen], valid[:len(valid)-1]} {
		dec, _ := NewAEADStream(key, DirClientToServer)
		if _, err := io.ReadAll(NewFramedReader(bytes.NewReader(wire), dec)); err == nil {
			t.Fatal("unauthenticated EOF accepted")
		}
	}
}
