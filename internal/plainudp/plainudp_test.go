package plainudp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/chitanda/internal/frame"
)

func BenchmarkDecodePacketMultiMiss(b *testing.B) {
	for _, count := range []int{1, 30, 128} {
		b.Run(fmt.Sprintf("users_%d", count), func(b *testing.B) {
			codecs := make([]*Codec, count)
			for i := range codecs {
				key := []byte(fmt.Sprintf("plainudp-benchmark-user-%03d-secret-key", i))
				var err error
				codecs[i], err = NewCodec(key)
				if err != nil {
					b.Fatal(err)
				}
			}
			packet := make([]byte, 1200)
			packet[0] = 0xc0 // QUIC-like long header, not valid plain UDP.
			now := time.Now()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, _, _, _, _, err := DecodePacketMulti(codecs, packet, DirClientToServer, now); err != ErrDecryptionFailed {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestPlainUDPRoundTripAndReplay(t *testing.T) {
	psk := []byte(strings.Repeat("u", 32))
	codec, err := NewCodec(psk)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	now := time.Now()
	var replay frame.ReplayWindow
	sessionID := uint64(0x1122334455667788)

	testCases := []struct {
		target  string
		payload string
	}{
		{"1.1.1.1:53", "DNS query data payload"},
		{"8.8.8.8:853", "DoT query"},
		{"[2606:4700:4700::1111]:53", "IPv6 DNS packet"},
		{"dns.google:53", "Domain target DNS"},
	}

	for _, tc := range testCases {
		packet, err := codec.EncodePacket(nil, DirClientToServer, sessionID, tc.target, []byte(tc.payload), now)
		if err != nil {
			t.Fatalf("EncodePacket(%q): %v", tc.target, err)
		}

		decodedSessionID, decodedTarget, decodedPayload, ts, seq, err := codec.DecodePacket(packet, DirClientToServer, now)
		if err != nil {
			t.Fatalf("DecodePacket(%q): %v", tc.target, err)
		}

		if decodedSessionID != sessionID {
			t.Fatalf("sessionID %x != expected %x", decodedSessionID, sessionID)
		}
		if decodedTarget != tc.target {
			t.Fatalf("target %q != expected %q", decodedTarget, tc.target)
		}
		if !bytes.Equal(decodedPayload, []byte(tc.payload)) {
			t.Fatalf("payload %q != expected %q", string(decodedPayload), tc.payload)
		}
		if ts != uint64(now.Unix()) {
			t.Fatalf("timestamp %d != expected %d", ts, uint64(now.Unix()))
		}
		if seq == 0 {
			t.Fatalf("expected non-zero sequence")
		}

		// First arrival: replay window accepts
		if !replay.Accept(seq) {
			t.Fatalf("expected replay window to accept first-time sequence %d", seq)
		}

		// Replay arrival: replay window rejects!
		if replay.Accept(seq) {
			t.Fatalf("expected replay window to reject duplicate sequence %d", seq)
		}
	}
}

func TestPlainUDPReflectionProtection(t *testing.T) {
	psk := []byte(strings.Repeat("u", 32))
	codec, err := NewCodec(psk)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	now := time.Now()

	// Client sends a request to server (DirClientToServer)
	reqPacket, err := codec.EncodePacket(nil, DirClientToServer, 0x55aa, "1.1.1.1:53", []byte("dns request"), now)
	if err != nil {
		t.Fatalf("EncodePacket: %v", err)
	}

	// Attacker/Echo server reflects the EXACT SAME packet back to client.
	// Client expects DirServerToClient.
	// This MUST fail decryption with ErrDecryptionFailed!
	_, _, _, _, _, err = codec.DecodePacket(reqPacket, DirServerToClient, now)
	if err != ErrDecryptionFailed {
		t.Fatalf("expected ErrDecryptionFailed on reflected packet, got: %v", err)
	}
}

func TestUnauthenticatedPacketCannotPoisonReplayWindow(t *testing.T) {
	psk := []byte(strings.Repeat("u", 32))
	codec, err := NewCodec(psk)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	now := time.Now()
	var replay frame.ReplayWindow

	// Attacker crafts unauthenticated packet with high sequence number
	fakePacket := make([]byte, 100)
	nowSec := uint64(now.Unix())
	binary.BigEndian.PutUint64(fakePacket[0:8], nowSec)
	binary.BigEndian.PutUint64(fakePacket[8:16], math.MaxUint64)

	// Decode must fail immediately due to AEAD decryption failure
	_, _, _, _, _, err = codec.DecodePacket(fakePacket, DirClientToServer, now)
	if err != ErrDecryptionFailed {
		t.Fatalf("expected ErrDecryptionFailed, got %v", err)
	}

	// Replay window state must remain completely unaffected
	// Legitimate client with seq=1 must still be accepted!
	if !replay.Accept(1) {
		t.Fatal("replay window was poisoned by unauthenticated packet!")
	}
}

func TestPlainUDPTamperAndExpire(t *testing.T) {
	psk := []byte(strings.Repeat("u", 32))
	codec, err := NewCodec(psk)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	now := time.Now()

	packet, err := codec.EncodePacket(nil, DirClientToServer, 0x1234, "1.1.1.1:53", []byte("hello"), now)
	if err != nil {
		t.Fatalf("EncodePacket: %v", err)
	}

	// Tampered payload
	tampered := make([]byte, len(packet))
	copy(tampered, packet)
	tampered[len(tampered)-1] ^= 0xff
	if _, _, _, _, _, err := codec.DecodePacket(tampered, DirClientToServer, now); err == nil {
		t.Fatal("expected decryption error on tampered packet")
	}

	// Expired packet (>30s)
	future := now.Add(45 * time.Second)
	if _, _, _, _, _, err := codec.DecodePacket(packet, DirClientToServer, future); err != ErrTimestampExpired {
		t.Fatalf("expected ErrTimestampExpired on out-of-window packet, got %v", err)
	}
}

func TestPlainUDPZeroFingerprintAndEntropy(t *testing.T) {
	psk := []byte(strings.Repeat("u", 32))
	codec, err := NewCodec(psk)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	now := time.Now()
	sessionID := uint64(0xAABBCCDDEEFF0011)

	var allBytes []byte
	var prevPkt []byte

	for i := 0; i < 50; i++ {
		pkt, err := codec.EncodePacket(nil, DirClientToServer, sessionID, "1.1.1.1:53", bytes.Repeat([]byte("test"), 250), now)
		if err != nil {
			t.Fatalf("EncodePacket: %v", err)
		}

		// 1. Verify NO sequence duplication: packet[8:16] == packet[24:32] was the old fingerprint
		if bytes.Equal(pkt[8:16], pkt[24:32]) {
			t.Fatalf("sequence duplication detected on packet wire: pkt[8:16] == pkt[24:32]")
		}

		// 2. Verify sessionID is NOT visible in plaintext anywhere on the wire
		var sBuf [8]byte
		binary.BigEndian.PutUint64(sBuf[:], sessionID)
		if bytes.Contains(pkt, sBuf[:]) {
			t.Fatalf("static sessionID found in plaintext on wire!")
		}

		// 3. Verify wire changes across every single packet
		if prevPkt != nil && bytes.Equal(pkt[:24], prevPkt[:24]) {
			t.Fatalf("nonce repeated across packets!")
		}
		prevPkt = pkt
		allBytes = append(allBytes, pkt...)
	}

	// Calculate Shannon Entropy across all wire packets
	freq := make(map[byte]int)
	for _, b := range allBytes {
		freq[b]++
	}
	total := float64(len(allBytes))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / total
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	t.Logf("PlainUDP wire Shannon entropy: %.4f bits/byte", entropy)
	if entropy < 7.95 {
		t.Fatalf("entropy %.4f < 7.95: traffic is not indistinguishable from random noise", entropy)
	}
}
