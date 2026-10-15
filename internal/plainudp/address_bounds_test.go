package plainudp

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestAddressLengthsIndependentOfPayload(t *testing.T) {
	codec, err := NewCodec(bytes.Repeat([]byte{'x'}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"a:53", "ab:53", "abc:53", strings.Repeat("a", 255) + ":53", "192.0.2.1:53", "[2001:db8::1]:53", "icmp:a", "icmp:2001:db8::1"} {
		for size := range 4 {
			t.Run(fmt.Sprintf("%s/payload=%d", target, size), func(t *testing.T) {
				now, payload := time.Now(), bytes.Repeat([]byte{'p'}, size)
				for _, dir := range []Direction{DirClientToServer, DirServerToClient} {
					wire, err := codec.EncodePacket(nil, dir, 123, target, payload, now)
					if err != nil {
						t.Fatal(err)
					}
					sid, gotTarget, got, _, _, err := codec.DecodePacket(wire, dir, now)
					if err != nil || sid != 123 || gotTarget != target || !bytes.Equal(got, payload) {
						t.Fatalf("roundtrip sid=%d target=%q payload=%x err=%v", sid, gotTarget, got, err)
					}
					wire[len(wire)-1] ^= 1
					if _, _, _, _, _, err := codec.DecodePacket(wire, dir, now); !errors.Is(err, ErrDecryptionFailed) {
						t.Fatalf("tampered short packet: %v", err)
					}
				}
			})
		}
	}
}

func TestAddressParserRejectsTruncationAndEmptyDomain(t *testing.T) {
	for _, target := range []string{"a:53", "ab:53", strings.Repeat("a", 255) + ":53", "192.0.2.1:53", "[2001:db8::1]:53"} {
		encoded, err := appendTargetAddress(nil, target)
		if err != nil {
			t.Fatal(err)
		}
		for cut := range len(encoded) {
			if _, _, err := decodeTargetAddress(encoded[:cut]); err == nil {
				t.Fatalf("accepted truncated address target=%s cut=%d", target, cut)
			}
		}
	}
	for _, data := range [][]byte{nil, {0xff}, {3, 0, 0, 53}, {3, 0, 0, 53, 1, 2, 3}} {
		if _, _, err := decodeTargetAddress(data); err == nil {
			t.Fatalf("malformed address accepted: %x", data)
		}
	}
}
