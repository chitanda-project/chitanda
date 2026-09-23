package h1session

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestH1SessionHandshakeAndMutualAuth(t *testing.T) {
	psk := []byte(strings.Repeat("k", 32))
	now := time.Now()

	// 1. Client creates ClientHello
	clientHello, clientNonce, ts, err := CreateClientHello(psk, now)
	if err != nil {
		t.Fatalf("CreateClientHello: %v", err)
	}
	if len(clientHello) != ClientHelloSize {
		t.Fatalf("unexpected ClientHello size: %d", len(clientHello))
	}

	// 2. Server verifies ClientHello
	verifiedNonce, verifiedTs, err := VerifyClientHello(psk, clientHello, now)
	if err != nil {
		t.Fatalf("VerifyClientHello: %v", err)
	}
	if verifiedNonce != clientNonce || verifiedTs != ts {
		t.Fatalf("nonce or timestamp mismatch")
	}

	// 3. Server creates ServerHello and derives session keys
	serverHello, serverClientKey, serverServerKey, err := CreateServerHello(psk, verifiedNonce)
	if err != nil {
		t.Fatalf("CreateServerHello: %v", err)
	}
	if len(serverHello) != ServerHelloSize {
		t.Fatalf("unexpected ServerHello size: %d", len(serverHello))
	}

	// 4. Client verifies ServerHello and derives identical session keys
	clientClientKey, clientServerKey, err := VerifyServerHello(psk, clientNonce, serverHello)
	if err != nil {
		t.Fatalf("VerifyServerHello: %v", err)
	}

	if clientClientKey != serverClientKey {
		t.Fatalf("client->server key mismatch between client and server")
	}
	if clientServerKey != serverServerKey {
		t.Fatalf("server->client key mismatch between client and server")
	}

	// 5. Test AEAD Stream round-trip in both directions
	c2sEnc, _ := NewAEADStream(clientClientKey, DirClientToServer)
	c2sDec, _ := NewAEADStream(serverClientKey, DirClientToServer)

	plaintext := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	encryptedChunk, err := c2sEnc.EncryptChunk(nil, plaintext)
	if err != nil {
		t.Fatalf("EncryptChunk: %v", err)
	}

	wireLen := int(encryptedChunk[0])<<8 | int(encryptedChunk[1])
	if wireLen != len(encryptedChunk)-2 {
		t.Fatalf("wireLen header %d != actual %d", wireLen, len(encryptedChunk)-2)
	}

	decrypted, err := c2sDec.DecryptChunk(nil, encryptedChunk[2:])
	if err != nil {
		t.Fatalf("DecryptChunk: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted %q != plaintext %q", string(decrypted), string(plaintext))
	}
}

func Test0RTTKeyAndChunk(t *testing.T) {
	psk := []byte(strings.Repeat("k", 32))
	now := time.Now()

	clientHello, clientNonce, ts, err := CreateClientHello(psk, now)
	if err != nil {
		t.Fatalf("CreateClientHello: %v", err)
	}

	// Client derives 0-RTT key
	k0Client, err := Derive0RTTKey(psk, ts, clientNonce)
	if err != nil {
		t.Fatalf("Derive0RTTKey: %v", err)
	}

	openPayload, err := EncodeOpenFrame("1.1.1.1:443", []byte("early TLS hello data"))
	if err != nil {
		t.Fatalf("EncodeOpenFrame: %v", err)
	}

	encrypted0RTT, err := Encrypt0RTTChunk(k0Client, openPayload)
	if err != nil {
		t.Fatalf("Encrypt0RTTChunk: %v", err)
	}

	// Server verifies ClientHello and derives matching 0-RTT key
	serverNonce, serverTs, err := VerifyClientHello(psk, clientHello, now)
	if err != nil {
		t.Fatalf("VerifyClientHello: %v", err)
	}
	k0Server, err := Derive0RTTKey(psk, serverTs, serverNonce)
	if err != nil {
		t.Fatalf("Derive0RTTKey server: %v", err)
	}

	if k0Client != k0Server {
		t.Fatalf("0-RTT key mismatch between client and server")
	}

	decryptedOpen, err := Decrypt0RTTChunk(k0Server, encrypted0RTT[2:])
	if err != nil {
		t.Fatalf("Decrypt0RTTChunk: %v", err)
	}

	target, payload, err := DecodeOpenFrame(decryptedOpen)
	if err != nil {
		t.Fatalf("DecodeOpenFrame: %v", err)
	}
	if target != "1.1.1.1:443" {
		t.Fatalf("target %q != expected", target)
	}
	if string(payload) != "early TLS hello data" {
		t.Fatalf("payload %q != expected", string(payload))
	}
}

func TestH1SessionReplayAndTamper(t *testing.T) {
	psk := []byte(strings.Repeat("k", 32))
	now := time.Now()

	clientHello, clientNonce, _, err := CreateClientHello(psk, now)
	if err != nil {
		t.Fatalf("CreateClientHello: %v", err)
	}

	tampered := make([]byte, len(clientHello))
	copy(tampered, clientHello)
	tampered[15] ^= 0xff
	if _, _, err := VerifyClientHello(psk, tampered, now); err == nil {
		t.Fatal("expected error on tampered ClientHello")
	}

	expiredTime := now.Add(100 * time.Second)
	if _, _, err := VerifyClientHello(psk, clientHello, expiredTime); err == nil {
		t.Fatal("expected error on expired ClientHello")
	}

	serverHello, _, _, _ := CreateServerHello(psk, clientNonce)
	tamperedServerHello := make([]byte, len(serverHello))
	copy(tamperedServerHello, serverHello)
	tamperedServerHello[30] ^= 0x01
	if _, _, err := VerifyServerHello(psk, clientNonce, tamperedServerHello); err == nil {
		t.Fatal("expected error on tampered ServerHello")
	}
}

func TestOpenFrameRoundTrip(t *testing.T) {
	testCases := []struct {
		target  string
		payload string
	}{
		{"1.1.1.1:443", "early data payload"},
		{"www.google.com:443", "GET / HTTP/1.1\r\n\r\n"},
		{"[2606:4700:4700::1111]:853", ""},
	}

	for _, tc := range testCases {
		encoded, err := EncodeOpenFrame(tc.target, []byte(tc.payload))
		if err != nil {
			t.Fatalf("EncodeOpenFrame(%q): %v", tc.target, err)
		}

		decodedTarget, decodedPayload, err := DecodeOpenFrame(encoded)
		if err != nil {
			t.Fatalf("DecodeOpenFrame: %v", err)
		}

		if decodedTarget != tc.target {
			t.Fatalf("decoded target %q != expected %q", decodedTarget, tc.target)
		}
		if string(decodedPayload) != tc.payload {
			t.Fatalf("decoded payload %q != expected %q", string(decodedPayload), tc.payload)
		}
	}
}

func TestMatchClientHelloMultiUser(t *testing.T) {
	now := time.Now()
	key1 := []byte("user1-secret-key-at-least-32-bytes-long!")
	key2 := []byte("user2-secret-key-at-least-32-bytes-long!")
	key3 := []byte("user3-secret-key-at-least-32-bytes-long!")
	keys := [][]byte{key1, key2, key3}

	// 1. Client creates ClientHello with key2
	hello2, nonce2, ts2, err := CreateClientHello(key2, now)
	if err != nil {
		t.Fatalf("CreateClientHello: %v", err)
	}

	// 2. Server matches across keys
	matchedIdx, matchedNonce, matchedTs, err := MatchClientHello(keys, hello2, now)
	if err != nil {
		t.Fatalf("MatchClientHello: %v", err)
	}
	if matchedIdx != 1 {
		t.Fatalf("expected matchedIdx 1, got %d", matchedIdx)
	}
	if matchedNonce != nonce2 || matchedTs != ts2 {
		t.Fatalf("nonce or ts mismatch")
	}

	// 3. Unknown key should fail
	unknownKey := []byte("unknown-user-key-at-least-32-bytes-long!")
	helloUnknown, _, _, _ := CreateClientHello(unknownKey, now)
	if _, _, _, err := MatchClientHello(keys, helloUnknown, now); err != ErrInvalidClientAuth {
		t.Fatalf("expected ErrInvalidClientAuth, got %v", err)
	}
}

