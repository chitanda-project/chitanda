package rawstream

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"math"
	"testing"
	"time"
)

func TestMatchPolymorphicClientHelloMultiUser(t *testing.T) {
	now := time.Now()
	serverID := "srv-main-01"

	// Create 5 different user PSKs
	keys := make([][]byte, 5)
	for i := range keys {
		keys[i] = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, keys[i]); err != nil {
			t.Fatalf("rand failed: %v", err)
		}
	}

	// Test handshake for each user
	for userIdx, psk := range keys {
		cHello, clientNonce, ts, err := CreatePolymorphicClientHello(psk, serverID, now)
		if err != nil {
			t.Fatalf("user %d CreatePolymorphicClientHello failed: %v", userIdx, err)
		}

		// 1. Test header-only match
		matchedIdx, padLen, matchedNonce, matchedTs, err := MatchPolymorphicClientHelloHeader(cHello[:49], keys, serverID, now)
		if err != nil {
			t.Fatalf("user %d MatchPolymorphicClientHelloHeader failed: %v", userIdx, err)
		}
		if matchedIdx != userIdx {
			t.Fatalf("expected matchedIdx %d, got %d", userIdx, matchedIdx)
		}
		if matchedNonce != clientNonce || matchedTs != ts {
			t.Fatalf("user %d nonce or ts mismatch", userIdx)
		}
		if len(cHello) != 49+padLen {
			t.Fatalf("user %d len mismatch: %d != 49 + %d", userIdx, len(cHello), padLen)
		}

		// 2. Test full stream match
		streamMatchedIdx, streamNonce, streamTs, err := ReadAndMatchPolymorphicClientHello(bytes.NewReader(cHello), keys, serverID, now)
		if err != nil {
			t.Fatalf("user %d ReadAndMatchPolymorphicClientHello failed: %v", userIdx, err)
		}
		if streamMatchedIdx != userIdx {
			t.Fatalf("expected streamMatchedIdx %d, got %d", userIdx, streamMatchedIdx)
		}
		if streamNonce != clientNonce || streamTs != ts {
			t.Fatalf("user %d stream nonce or ts mismatch", userIdx)
		}
	}

	// Test unknown user PSK
	unknownKey := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, unknownKey)
	unknownHello, _, _, _ := CreatePolymorphicClientHello(unknownKey, serverID, now)
	if _, _, _, _, err := MatchPolymorphicClientHelloHeader(unknownHello[:49], keys, serverID, now); err != ErrInvalidClientAuth {
		t.Fatalf("expected ErrInvalidClientAuth for unknown user, got: %v", err)
	}
}

func BenchmarkMatchPolymorphicClientHello(b *testing.B) {
	now := time.Now()
	serverID := "srv-benchmark"
	const numUsers = 30

	keys := make([][]byte, numUsers)
	for i := range keys {
		keys[i] = make([]byte, 32)
		_, _ = io.ReadFull(rand.Reader, keys[i])
	}

	// Create ClientHello for the last user (worst-case trial iteration)
	targetUserIdx := numUsers - 1
	cHello, _, _, err := CreatePolymorphicClientHello(keys[targetUserIdx], serverID, now)
	if err != nil {
		b.Fatalf("CreatePolymorphicClientHello failed: %v", err)
	}
	header := cHello[:49]
	matcher, err := NewPreparedClientHelloMatcher(keys, serverID)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matchedIdx, _, _, _, err := matcher.MatchHeader(header, now)
		if err != nil || matchedIdx != targetUserIdx {
			b.Fatalf("unexpected match result: idx=%d, err=%v", matchedIdx, err)
		}
	}
}

func TestPreparedClientHelloMatcherMatchesLegacy(t *testing.T) {
	now := time.Now()
	keys := [][]byte{
		[]byte("alice-key-at-least-32-bytes-long!"),
		[]byte("bob---key-at-least-32-bytes-long!"),
	}
	matcher, err := NewPreparedClientHelloMatcher(keys, "prepared-test")
	if err != nil {
		t.Fatal(err)
	}
	for i, key := range keys {
		record, _, _, err := CreatePolymorphicClientHello(key, "prepared-test", now)
		if err != nil {
			t.Fatal(err)
		}
		wantIdx, wantPad, wantNonce, wantTS, wantErr := MatchPolymorphicClientHelloHeader(record[:49], keys, "prepared-test", now)
		gotIdx, gotPad, gotNonce, gotTS, gotErr := matcher.MatchHeader(record[:49], now)
		if gotErr != wantErr || gotIdx != wantIdx || gotIdx != i || gotPad != wantPad || gotNonce != wantNonce || gotTS != wantTS {
			t.Fatalf("user %d: prepared=(%d,%d,%v,%d,%v), legacy=(%d,%d,%v,%d,%v)", i, gotIdx, gotPad, gotNonce, gotTS, gotErr, wantIdx, wantPad, wantNonce, wantTS, wantErr)
		}
		readIdx, readNonce, readTS, err := matcher.ReadAndMatch(bytes.NewReader(record), now)
		if err != nil || readIdx != i || readNonce != wantNonce || readTS != wantTS {
			t.Fatalf("user %d full read: index=%d err=%v", i, readIdx, err)
		}
	}
	bad, _, _, err := CreatePolymorphicClientHello([]byte("unknown-key-at-least-32-bytes-long!"), "prepared-test", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := matcher.MatchHeader(bad[:49], now); err != ErrInvalidClientAuth {
		t.Fatalf("unknown key accepted: %v", err)
	}
}

func TestClientHelloEntropy(t *testing.T) {
	// Falsifiable test: sample N=1000 ClientHellos and assert empirical Shannon entropy >= 7.95
	psk := []byte("01234567890123456789012345678901")
	serverID := "test-entropy"
	now := time.Now()

	var byteCounts [256]int
	totalBytes := 0
	samples := 1000

	for i := 0; i < samples; i++ {
		hello, _, _, err := CreatePolymorphicClientHello(psk, serverID, now)
		if err != nil {
			t.Fatalf("CreatePolymorphicClientHello: %v", err)
		}
		for _, b := range hello {
			byteCounts[b]++
			totalBytes++
		}
	}

	// Calculate Shannon entropy: H = - sum(p * log2(p))
	var entropy float64
	for _, count := range byteCounts {
		if count > 0 {
			p := float64(count) / float64(totalBytes)
			entropy -= p * math.Log2(p)
		}
	}

	fmt.Printf("[Verification] Empirical Shannon entropy over %d bytes (%d ClientHellos): %.4f bits/byte\n",
		totalBytes, samples, entropy)

	if entropy < 7.95 {
		t.Fatalf("empirical entropy %.4f is below required 7.95 bits/byte", entropy)
	}
}
