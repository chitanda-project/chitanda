package rawstream

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestAuthenticatedEOFAndTruncation(t *testing.T) {
	key := [16]byte{1}
	enc, _ := NewAEADStream(key)
	var wire bytes.Buffer
	w := NewFramedWriter(&wire, enc)
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	dataLen := wire.Len()
	if err := w.WriteEOF(); err != nil {
		t.Fatal(err)
	}
	if wire.Len()-dataLen != 18 {
		t.Fatal("EOF must include an AEAD tag")
	}
	valid := bytes.Clone(wire.Bytes())
	for _, tc := range []struct {
		name    string
		wire    []byte
		wantEOF bool
	}{
		{"valid", valid, true},
		{"bare-zero", []byte{0, 0}, false},
		{"truncated-after-data", valid[:dataLen], false},
		{"truncated-tag", valid[:len(valid)-1], false},
		{"transport-eof", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dec, _ := NewAEADStream(key)
			r := NewFramedReader(bytes.NewReader(tc.wire), dec)
			_, err := io.ReadAll(r)
			if tc.wantEOF && err != nil {
				t.Fatal(err)
			}
			if !tc.wantEOF && err == nil {
				t.Fatal("unauthenticated end accepted")
			}
			_, again := r.Read(make([]byte, 1))
			if tc.wantEOF && again != io.EOF {
				t.Fatalf("EOF not sticky: %v", again)
			}
			if !tc.wantEOF && !errors.Is(again, err) {
				t.Fatalf("fatal error not sticky: %v then %v", err, again)
			}
		})
	}
	valid[len(valid)-1] ^= 1
	dec, _ := NewAEADStream(key)
	if _, err := io.ReadAll(NewFramedReader(bytes.NewReader(valid), dec)); err == nil {
		t.Fatal("forged EOF tag accepted")
	}
}
