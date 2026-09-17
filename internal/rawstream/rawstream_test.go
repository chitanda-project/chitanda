package rawstream

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"testing"
	"time"
)

func TestClientServerHandshake(t *testing.T) {
	psk := []byte("01234567890123456789012345678901") // 32 bytes
	serverID := "node-alpha"
	now := time.Now()

	// 0. PSK < 32 bytes must be rejected
	if _, _, _, err := CreateClientHello([]byte("short-psk"), serverID, now); err == nil {
		t.Fatalf("expected error for PSK < 32 bytes, got nil")
	}

	// 1. Client creates ClientHello
	cHello, clientNonce, ts, err := CreateClientHello(psk, serverID, now)
	if err != nil {
		t.Fatalf("CreateClientHello failed: %v", err)
	}
	if len(cHello) != ClientHelloSize {
		t.Fatalf("expected client hello size %d, got %d", ClientHelloSize, len(cHello))
	}

	// 2. Server verifies ClientHello with matching serverID
	verifiedNonce, verifiedTs, err := VerifyClientHello(psk, serverID, cHello, now)
	if err != nil {
		t.Fatalf("VerifyClientHello failed: %v", err)
	}
	if verifiedNonce != clientNonce || verifiedTs != ts {
		t.Fatalf("nonce or timestamp mismatch")
	}

	// 2b. Server with mismatched serverID must reject ClientHello (cross-node replay defense)
	if _, _, err := VerifyClientHello(psk, "node-beta", cHello, now); err == nil {
		t.Fatalf("expected VerifyClientHello to reject mismatched serverID, but it passed!")
	}

	// 3. Keys derivation
	k0RTTClient, err := Derive0RTTKey(psk, serverID, ts, clientNonce)
	if err != nil {
		t.Fatalf("Derive0RTTKey client failed: %v", err)
	}
	k0RTTServer, err := Derive0RTTKey(psk, serverID, verifiedTs, verifiedNonce)
	if err != nil {
		t.Fatalf("Derive0RTTKey server failed: %v", err)
	}
	if k0RTTClient != k0RTTServer {
		t.Fatalf("0-RTT key mismatch")
	}

	// 4. Server creates ServerHello
	sHello, serverNonce, err := CreateServerHello(psk, serverID, verifiedTs, verifiedNonce)
	if err != nil {
		t.Fatalf("CreateServerHello failed: %v", err)
	}
	if len(sHello) != ServerHelloSize {
		t.Fatalf("expected server hello size %d, got %d", ServerHelloSize, len(sHello))
	}

	// 5. Client verifies ServerHello
	verifiedServerNonce, err := VerifyServerHello(psk, serverID, ts, clientNonce, sHello)
	if err != nil {
		t.Fatalf("VerifyServerHello failed: %v", err)
	}
	if verifiedServerNonce != serverNonce {
		t.Fatalf("server nonce mismatch")
	}

	// 6. Session keys match
	c2sClient, s2cClient, err := DeriveSessionKeys(psk, serverID, ts, clientNonce, serverNonce)
	if err != nil {
		t.Fatalf("DeriveSessionKeys client: %v", err)
	}
	c2sServer, s2cServer, err := DeriveSessionKeys(psk, serverID, verifiedTs, verifiedNonce, verifiedServerNonce)
	if err != nil {
		t.Fatalf("DeriveSessionKeys server: %v", err)
	}

	if c2sClient != c2sServer || s2cClient != s2cServer {
		t.Fatalf("session keys mismatch between client and server")
	}
}

func TestPolymorphicHandshake(t *testing.T) {
	psk := []byte("01234567890123456789012345678901") // 32 bytes
	serverID := "node-poly-1"
	now := time.Now()

	// 0. PSK < 32 bytes must be rejected
	if _, _, _, err := CreatePolymorphicClientHello([]byte("short-psk"), serverID, now); err == nil {
		t.Fatalf("expected error for PSK < 32 bytes, got nil")
	}

	clientLengths := make(map[int]bool)
	serverLengths := make(map[int]bool)

	for i := 0; i < 100; i++ {
		// 1. Client creates Polymorphic ClientHello
		cHello, clientNonce, ts, err := CreatePolymorphicClientHello(psk, serverID, now)
		if err != nil {
			t.Fatalf("iteration %d: CreatePolymorphicClientHello failed: %v", i, err)
		}
		if len(cHello) < 49 || len(cHello) > 1+MaxPolymorphicPadding+ClientHelloSize {
			t.Fatalf("iteration %d: unexpected client hello length %d", i, len(cHello))
		}
		clientLengths[len(cHello)] = true

		// 2. Server verifies via slice
		vNonce, vTs, err := VerifyPolymorphicClientHello(psk, serverID, cHello, now)
		if err != nil {
			t.Fatalf("iteration %d: VerifyPolymorphicClientHello failed: %v", i, err)
		}
		if vNonce != clientNonce || vTs != ts {
			t.Fatalf("iteration %d: nonce or timestamp mismatch", i)
		}

		// 3. Server verifies via io.Reader (stream simulation)
		vNonceStream, vTsStream, err := ReadAndVerifyPolymorphicClientHello(bytes.NewReader(cHello), psk, serverID, now)
		if err != nil {
			t.Fatalf("iteration %d: ReadAndVerifyPolymorphicClientHello failed: %v", i, err)
		}
		if vNonceStream != clientNonce || vTsStream != ts {
			t.Fatalf("iteration %d: stream reader nonce or timestamp mismatch", i)
		}

		// 4. Server creates Polymorphic ServerHello
		sHello, serverNonce, err := CreatePolymorphicServerHello(psk, serverID, vTs, vNonce)
		if err != nil {
			t.Fatalf("iteration %d: CreatePolymorphicServerHello failed: %v", i, err)
		}
		if len(sHello) < 41 || len(sHello) > 1+MaxPolymorphicPadding+ServerHelloSize {
			t.Fatalf("iteration %d: unexpected server hello length %d", i, len(sHello))
		}
		serverLengths[len(sHello)] = true

		// 5. Client verifies via slice
		vServerNonce, err := VerifyPolymorphicServerHello(psk, serverID, ts, clientNonce, sHello)
		if err != nil {
			t.Fatalf("iteration %d: VerifyPolymorphicServerHello failed: %v", i, err)
		}
		if vServerNonce != serverNonce {
			t.Fatalf("iteration %d: server nonce mismatch", i)
		}

		// 6. Client verifies via io.Reader
		vServerNonceStream, err := ReadAndVerifyPolymorphicServerHello(bytes.NewReader(sHello), psk, serverID, ts, clientNonce)
		if err != nil {
			t.Fatalf("iteration %d: ReadAndVerifyPolymorphicServerHello failed: %v", i, err)
		}
		if vServerNonceStream != serverNonce {
			t.Fatalf("iteration %d: stream reader server nonce mismatch", i)
		}

		// 7. Derive session keys
		c2sClient, s2cClient, err := DeriveSessionKeys(psk, serverID, ts, clientNonce, serverNonce)
		if err != nil {
			t.Fatalf("DeriveSessionKeys client: %v", err)
		}
		c2sServer, s2cServer, err := DeriveSessionKeys(psk, serverID, vTs, vNonce, vServerNonce)
		if err != nil {
			t.Fatalf("DeriveSessionKeys server: %v", err)
		}
		if c2sClient != c2sServer || s2cClient != s2cServer {
			t.Fatalf("iteration %d: session keys mismatch", i)
		}
	}

	// Verify polymorphic distribution: at least 15 distinct lengths across 100 samples
	if len(clientLengths) < 15 {
		t.Fatalf("expected high client length entropy, got only %d distinct lengths", len(clientLengths))
	}
	if len(serverLengths) < 15 {
		t.Fatalf("expected high server length entropy, got only %d distinct lengths", len(serverLengths))
	}
}

func TestPolymorphicHandshakeAttacks(t *testing.T) {
	psk := []byte("01234567890123456789012345678901") // 32 bytes
	serverID := "node-poly-secure"
	now := time.Now()

	// Attack 1: Plain HTTP probe (GET / HTTP/1.1)
	httpProbe := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if _, _, err := ReadAndVerifyPolymorphicClientHello(bytes.NewReader(httpProbe), psk, serverID, now); err == nil {
		t.Fatalf("expected HTTP probe to be rejected immediately, but it passed!")
	}

	// Attack 2: Mismatched serverID
	cHello, _, _, err := CreatePolymorphicClientHello(psk, serverID, now)
	if err != nil {
		t.Fatalf("CreatePolymorphicClientHello failed: %v", err)
	}
	if _, _, err := ReadAndVerifyPolymorphicClientHello(bytes.NewReader(cHello), psk, "other-node", now); err == nil {
		t.Fatalf("expected mismatched serverID to be rejected")
	}

	// Attack 3: Tampered padding length / header byte
	tampered := make([]byte, len(cHello))
	copy(tampered, cHello)
	tampered[0] ^= 0x01 // flip bit in masked padLen
	if _, _, err := ReadAndVerifyPolymorphicClientHello(bytes.NewReader(tampered), psk, serverID, now); err == nil {
		t.Fatalf("expected tampered padLen to fail HMAC verification")
	}

	// Attack 4: Tampered core HMAC tag (at offset 48)
	tamperedTag := make([]byte, len(cHello))
	copy(tamperedTag, cHello)
	tamperedTag[48] ^= 0x01 // flip bit in 16B HMAC tag (offset 33..49)
	if _, _, err := ReadAndVerifyPolymorphicClientHello(bytes.NewReader(tamperedTag), psk, serverID, now); err == nil {
		t.Fatalf("expected tampered HMAC tag to be rejected")
	}

	// Attack 5: Expired timestamp
	oldTime := now.Add(-5 * time.Minute)
	oldHello, _, _, err := CreatePolymorphicClientHello(psk, serverID, oldTime)
	if err != nil {
		t.Fatalf("CreatePolymorphicClientHello failed: %v", err)
	}
	if _, _, err := ReadAndVerifyPolymorphicClientHello(bytes.NewReader(oldHello), psk, serverID, now); !errors.Is(err, ErrTimestampExpired) {
		t.Fatalf("expected ErrTimestampExpired, got: %v", err)
	}
}

func TestDynamicPaddingVariance(t *testing.T) {
	target := "1.1.1.1:53"
	payload := []byte("ping payload data")

	lengths := make(map[int]bool)
	for i := 0; i < 20; i++ {
		frame, err := Encode0RTTOpenFrame(target, payload, 32, 256)
		if err != nil {
			t.Fatalf("Encode0RTTOpenFrame failed: %v", err)
		}
		lengths[len(frame)] = true

		decodedTarget, decodedPayload, err := Decode0RTTOpenFrame(frame)
		if err != nil {
			t.Fatalf("Decode0RTTOpenFrame failed: %v", err)
		}
		if decodedTarget != target {
			t.Fatalf("expected target %s, got %s", target, decodedTarget)
		}
		if !bytes.Equal(decodedPayload, payload) {
			t.Fatalf("payload mismatch")
		}
	}

	// Dynamic padding must yield multiple different wire lengths
	if len(lengths) < 5 {
		t.Fatalf("expected at least 5 different wire lengths across 20 samples, got %d", len(lengths))
	}
}

func TestAntiProbeResistance(t *testing.T) {
	psk := []byte("01234567890123456789012345678901")
	now := time.Now()

	// 1. Scanner sends HTTP GET request
	httpScan := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
	_, _, err := VerifyClientHello(psk, "", httpScan, now)
	if err == nil {
		t.Fatalf("expected VerifyClientHello to reject HTTP scan request, but it passed!")
	}

	// 2. Scanner sends random bytes of exact 48 length
	junk48 := make([]byte, ClientHelloSize)
	for i := range junk48 {
		junk48[i] = 0xAA
	}
	_, _, err = VerifyClientHello(psk, "", junk48, now)
	if err == nil {
		t.Fatalf("expected VerifyClientHello to reject random junk, but it passed!")
	}
}

func TestStreamConnBidirectional(t *testing.T) {
	keyC2S := [16]byte{1, 2, 3}
	keyS2C := [16]byte{4, 5, 6}

	cStreamOut, _ := NewAEADStream(keyC2S)
	cStreamIn, _ := NewAEADStream(keyS2C)
	sStreamIn, _ := NewAEADStream(keyC2S)
	sStreamOut, _ := NewAEADStream(keyS2C)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	clientConn := NewStreamConn(c1, cStreamIn, cStreamOut)
	serverConn := NewStreamConn(c2, sStreamIn, sStreamOut)

	testData := bytes.Repeat([]byte("abcdef123456"), 5000) // 60KB

	errCh := make(chan error, 2)

	// Server echoes back
	go func() {
		buf := make([]byte, len(testData))
		if _, err := io.ReadFull(serverConn, buf); err != nil {
			errCh <- err
			return
		}
		if _, err := serverConn.Write(buf); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	// Client sends and receives
	go func() {
		if _, err := clientConn.Write(testData); err != nil {
			errCh <- err
			return
		}
		buf := make([]byte, len(testData))
		if _, err := io.ReadFull(clientConn, buf); err != nil {
			errCh <- err
			return
		}
		if !bytes.Equal(buf, testData) {
			t.Errorf("echoed data mismatch")
		}
		errCh <- nil
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("concurrent stream error: %v", err)
		}
	}
}

func BenchmarkStreamConn_Throughput(b *testing.B) {
	keyC2S := [16]byte{1, 2, 3}
	keyS2C := [16]byte{4, 5, 6}

	cStreamOut, _ := NewAEADStream(keyC2S)
	cStreamIn, _ := NewAEADStream(keyS2C)
	sStreamIn, _ := NewAEADStream(keyC2S)
	sStreamOut, _ := NewAEADStream(keyS2C)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	clientConn := NewStreamConn(c1, cStreamIn, cStreamOut)
	serverConn := NewStreamConn(c2, sStreamIn, sStreamOut)

	chunk := make([]byte, 32*1024) // 32KB payload
	b.SetBytes(int64(len(chunk)))
	b.ResetTimer()

	go func() {
		buf := make([]byte, len(chunk))
		for {
			_, err := io.ReadFull(serverConn, buf)
			if err != nil {
				return
			}
		}
	}()

	for i := 0; i < b.N; i++ {
		if _, err := clientConn.Write(chunk); err != nil {
			b.Fatalf("write failed: %v", err)
		}
	}
}

func BenchmarkAEADStream_Direct(b *testing.B) {
	key := [16]byte{1, 2, 3, 4}
	streamEnc, _ := NewAEADStream(key)
	streamDec, _ := NewAEADStream(key)

	plaintext := make([]byte, 16384) // 16KB
	b.SetBytes(int64(len(plaintext)))
	encBuf := make([]byte, 0, MaxChunkWireLen+2)
	decBuf := make([]byte, 0, MaxChunkPayloadLen)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc, _ := streamEnc.EncryptChunk(encBuf[:0], plaintext)
		wireLen := binary.BigEndian.Uint16(enc[:2])
		_, _ = streamDec.DecryptChunk(decBuf[:0], enc[2:], wireLen)
	}
}

func BenchmarkAES128GCM_Direct(b *testing.B) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	plaintext := make([]byte, 16384)
	b.SetBytes(int64(len(plaintext)))
	nonce := make([]byte, 12)
	encBuf := make([]byte, 0, 16384+16)
	decBuf := make([]byte, 0, 16384)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc := gcm.Seal(encBuf[:0], nonce, plaintext, nil)
		_, _ = gcm.Open(decBuf[:0], nonce, enc, nil)
	}
}

func TestAEADStream_SequenceExhaustion(t *testing.T) {
	key := [16]byte{1, 2, 3, 4}
	streamEnc, err := NewAEADStream(key)
	if err != nil {
		t.Fatalf("NewAEADStream: %v", err)
	}
	streamEnc.sequence = math.MaxUint64

	_, err = streamEnc.EncryptChunk(nil, []byte("data"))
	if !errors.Is(err, ErrSequenceExhausted) {
		t.Fatalf("expected ErrSequenceExhausted on EncryptChunk, got %v", err)
	}

	streamDec, err := NewAEADStream(key)
	if err != nil {
		t.Fatalf("NewAEADStream: %v", err)
	}
	streamDec.sequence = math.MaxUint64

	_, err = streamDec.DecryptChunk(nil, make([]byte, 32), 32)
	if !errors.Is(err, ErrSequenceExhausted) {
		t.Fatalf("expected ErrSequenceExhausted on DecryptChunk, got %v", err)
	}
}

func TestFramedWriter_LargeWrite_Batching(t *testing.T) {
	key := [16]byte{1, 2, 3, 4}
	encStream, _ := NewAEADStream(key)
	decStream, _ := NewAEADStream(key)

	r, w := io.Pipe()
	fw := NewFramedWriter(w, encStream)
	fr := NewFramedReader(r, decStream)

	largeData := bytes.Repeat([]byte("1234567890abcdef"), 64*1024) // 1 MiB

	errCh := make(chan error, 1)
	go func() {
		defer w.Close()
		_, err := fw.Write(largeData)
		errCh <- err
	}()

	readBuf := make([]byte, len(largeData))
	if _, err := io.ReadFull(fr, readBuf); err != nil {
		t.Fatalf("ReadFull failed: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("fw.Write failed: %v", err)
	}

	if !bytes.Equal(readBuf, largeData) {
		t.Fatalf("large write data corrupted")
	}
}

func TestFramedReader_EOFRepeat(t *testing.T) {
	key := [16]byte{1, 2, 3, 4}
	encStream, _ := NewAEADStream(key)
	decStream, _ := NewAEADStream(key)

	r, w := io.Pipe()
	fw := NewFramedWriter(w, encStream)
	fr := NewFramedReader(r, decStream)

	msg := []byte("hello world payload")
	go func() {
		_, _ = fw.Write(msg)
		_ = fw.WriteEOF()
		_ = w.Close()
	}()

	buf := make([]byte, 64)
	n, err := fr.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("unexpected read error: %v", err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Fatalf("expected %q, got %q", msg, buf[:n])
	}

	// Read again: must return (0, io.EOF)
	n2, err2 := fr.Read(buf)
	if n2 != 0 || !errors.Is(err2, io.EOF) {
		t.Fatalf("expected (0, io.EOF) on subsequent read, got (%d, %v)", n2, err2)
	}

	// Third read: still must return (0, io.EOF), NEVER stale data!
	n3, err3 := fr.Read(buf)
	if n3 != 0 || !errors.Is(err3, io.EOF) {
		t.Fatalf("expected (0, io.EOF) on 3rd read, got (%d, %v)", n3, err3)
	}
}

type errWriter struct {
	failAfter int
	written   int
}

func (ew *errWriter) Write(p []byte) (int, error) {
	if ew.written >= ew.failAfter {
		return 0, errors.New("underlying network write failed")
	}
	ew.written += len(p)
	return len(p), nil
}

func TestFramedWriter_ShortWriteError(t *testing.T) {
	key := [16]byte{1, 2, 3, 4}
	encStream, _ := NewAEADStream(key)

	ew := &errWriter{failAfter: 0}
	fw := NewFramedWriter(ew, encStream)

	data := []byte("some test data")
	n, err := fw.Write(data)
	if err == nil {
		t.Fatal("expected error from faulty writer")
	}
	if n != 0 {
		t.Fatalf("expected 0 written plaintext on early failure, got %d", n)
	}
}

type chunkRecordingWriter struct {
	chunks []int
	rawBuf []byte
}

func (crw *chunkRecordingWriter) Write(p []byte) (int, error) {
	crw.rawBuf = append(crw.rawBuf, p...)
	for len(crw.rawBuf) >= 2 {
		wireLen := int(binary.BigEndian.Uint16(crw.rawBuf[:2]))
		if len(crw.rawBuf) < 2+wireLen {
			break
		}
		payloadLen := wireLen - 16
		crw.chunks = append(crw.chunks, payloadLen)
		crw.rawBuf = crw.rawBuf[2+wireLen:]
	}
	return len(p), nil
}

func TestFramedWriter_DynamicRecordSizing_Phases(t *testing.T) {
	key := [16]byte{0xaa, 0xbb, 0xcc, 0xdd}
	encStream, _ := NewAEADStream(key)

	rec := &chunkRecordingWriter{}
	fw := NewFramedWriter(rec, encStream)

	// Phase 1: write 64 KiB (< Phase1Threshold = 128 KiB)
	p1Data := make([]byte, 64*1024)
	n, err := fw.Write(p1Data)
	if err != nil || n != len(p1Data) {
		t.Fatalf("Phase 1 write failed: n=%d, err=%v", n, err)
	}
	if len(rec.chunks) == 0 {
		t.Fatal("expected chunks recorded in Phase 1")
	}
	for i, sz := range rec.chunks {
		if sz > MinRecordPayloadLen {
			t.Fatalf("Phase 1 chunk [%d] size %d exceeds MinRecordPayloadLen %d", i, sz, MinRecordPayloadLen)
		}
	}

	// Phase 2: write 256 KiB (cumulative ~320 KiB, between 128 KiB and 1 MiB)
	p1Count := len(rec.chunks)
	p2Data := make([]byte, 256*1024)
	n, err = fw.Write(p2Data)
	if err != nil || n != len(p2Data) {
		t.Fatalf("Phase 2 write failed: n=%d, err=%v", n, err)
	}
	p2Chunks := rec.chunks[p1Count:]
	hasMidChunk := false
	for i, sz := range p2Chunks {
		if sz > MidRecordPayloadLen {
			t.Fatalf("Phase 2 chunk [%d] size %d exceeds MidRecordPayloadLen %d", i, sz, MidRecordPayloadLen)
		}
		if sz > MinRecordPayloadLen {
			hasMidChunk = true
		}
	}
	if !hasMidChunk {
		t.Fatal("expected at least one Phase 2 chunk larger than MinRecordPayloadLen")
	}

	// Phase 3: write 1.5 MiB (cumulative > Phase2Threshold = 1 MiB)
	p2TotalCount := len(rec.chunks)
	p3Data := make([]byte, 1536*1024)
	n, err = fw.Write(p3Data)
	if err != nil || n != len(p3Data) {
		t.Fatalf("Phase 3 write failed: n=%d, err=%v", n, err)
	}
	p3Chunks := rec.chunks[p2TotalCount:]
	hasMaxChunk := false
	for _, sz := range p3Chunks {
		if sz == MaxChunkPayloadLen {
			hasMaxChunk = true
		}
	}
	if !hasMaxChunk {
		t.Fatalf("expected Phase 3 to scale up to MaxChunkPayloadLen %d", MaxChunkPayloadLen)
	}
}

func TestFramedWriter_DynamicRecordSizing_IdleReset(t *testing.T) {
	key := [16]byte{0x11, 0x22, 0x33, 0x44}
	encStream, _ := NewAEADStream(key)

	rec := &chunkRecordingWriter{}
	fw := NewFramedWriter(rec, encStream)

	// Ramp up past 1 MiB into Phase 3
	bigData := make([]byte, 1200*1024)
	if _, err := fw.Write(bigData); err != nil {
		t.Fatalf("ramp-up write failed: %v", err)
	}

	// Wait beyond IdleResetThreshold (1s + 100ms margin)
	time.Sleep(1100 * time.Millisecond)

	recCountBefore := len(rec.chunks)
	subsequentData := make([]byte, 10*1024)
	if _, err := fw.Write(subsequentData); err != nil {
		t.Fatalf("post-idle write failed: %v", err)
	}

	postIdleChunks := rec.chunks[recCountBefore:]
	if len(postIdleChunks) == 0 {
		t.Fatal("expected chunks recorded after idle write")
	}

	// The first chunk after idle reset must be back in Phase 1 (<= MinRecordPayloadLen)
	if postIdleChunks[0] > MinRecordPayloadLen {
		t.Fatalf("expected post-idle chunk to reset to <= %d, got %d", MinRecordPayloadLen, postIdleChunks[0])
	}
}

func TestFramedWriter_DynamicRecordSizing_EndToEndIntegrity(t *testing.T) {
	key := [16]byte{0xde, 0xad, 0xbe, 0xef}
	encStream, _ := NewAEADStream(key)
	decStream, _ := NewAEADStream(key)

	pr, pw := io.Pipe()
	fw := NewFramedWriter(pw, encStream)
	fr := NewFramedReader(pr, decStream)

	// Transfer across all 3 phases: 1.5 MiB of random data
	src := make([]byte, 1536*1024)
	for i := range src {
		src[i] = byte((i * 31) ^ (i >> 3))
	}

	errChan := make(chan error, 1)
	dst := make([]byte, len(src))

	go func() {
		_, err := io.ReadFull(fr, dst)
		errChan <- err
	}()

	// Write in irregular chunks (100B, 50KB, 500KB, rest)
	sizes := []int{100, 50 * 1024, 500 * 1024, len(src) - (100 + 50*1024 + 500*1024)}
	offset := 0
	for _, sz := range sizes {
		if _, err := fw.Write(src[offset : offset+sz]); err != nil {
			t.Fatalf("write error at offset %d: %v", offset, err)
		}
		offset += sz
	}
	_ = pw.Close()

	if err := <-errChan; err != nil {
		t.Fatalf("read error: %v", err)
	}

	if !bytes.Equal(src, dst) {
		t.Fatal("decrypted payload does not match original source across dynamic record scaling")
	}
}

func BenchmarkFramedWriter_DynamicSizing_Bulk(b *testing.B) {
	key := [16]byte{0x01, 0x02, 0x03, 0x04}
	encStream, _ := NewAEADStream(key)
	fw := NewFramedWriter(io.Discard, encStream)

	payload := make([]byte, 64*1024)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := fw.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func TestPolymorphicClientHelloNoPlaintextZeroes(t *testing.T) {
	psk := bytes.Repeat([]byte("01234567"), 4)
	serverID := "edge-node-1"
	fourZeroes := []byte{0x00, 0x00, 0x00, 0x00}

	for i := 0; i < 50; i++ {
		now := time.Now().Add(time.Duration(i) * time.Second)
		cHello, _, _, err := CreatePolymorphicClientHello(psk, serverID, now)
		if err != nil {
			t.Fatalf("CreatePolymorphicClientHello failed: %v", err)
		}
		// The first 49 bytes contain padLen, maskedTs, nonce, tag.
		// Plaintext 4-zero timestamp leak at offset 1..9 must be eliminated.
		if bytes.Equal(cHello[1:5], fourZeroes) {
			t.Fatalf("found plaintext four zeroes at offset 1..5: leak detected!")
		}
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type faultReader struct {
	data     []byte
	timeout  bool
	readOnce bool
}

func (fr *faultReader) Read(p []byte) (int, error) {
	if fr.timeout && !fr.readOnce {
		fr.readOnce = true
		return 0, timeoutError{}
	}
	if len(fr.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, fr.data)
	fr.data = fr.data[n:]
	return n, nil
}

func TestFramedReader_TruncationAndTimeout(t *testing.T) {
	key := [16]byte{0x10, 0x20, 0x30, 0x40}
	encStream, _ := NewAEADStream(key)
	decStream, _ := NewAEADStream(key)

	// 1. Truncated body: write 2-byte header with wireLen = 50, but body is only 20 bytes
	var truncatedBuf bytes.Buffer
	binary.Write(&truncatedBuf, binary.BigEndian, uint16(50))
	truncatedBuf.Write(make([]byte, 20))

	reader := NewFramedReader(&truncatedBuf, decStream)
	buf := make([]byte, 1024)
	_, err := reader.Read(buf)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected ErrUnexpectedEOF on truncated frame, got: %v", err)
	}

	// 2. Timeout at frame boundary: should not permanently convert to EOF
	encChunk, err := encStream.EncryptChunk(nil, []byte("hello-timeout-recovery"))
	if err != nil {
		t.Fatalf("EncryptChunk: %v", err)
	}
	var fullFrame bytes.Buffer
	fullFrame.Write(encChunk)

	faulty := &faultReader{
		data:    fullFrame.Bytes(),
		timeout: true,
	}

	decStream2, _ := NewAEADStream(key)
	reader2 := NewFramedReader(faulty, decStream2)

	// First read triggers timeout error
	_, err = reader2.Read(buf)
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected timeout error on first read, got: %v", err)
	}

	// Second read must recover and read the frame successfully, NOT return false EOF
	n, err := reader2.Read(buf)
	if err != nil {
		t.Fatalf("expected successful recovery after timeout, got: %v", err)
	}
	if string(buf[:n]) != "hello-timeout-recovery" {
		t.Fatalf("got %q, want 'hello-timeout-recovery'", string(buf[:n]))
	}
}

func TestFramedReader_PartialChunkDoesNotBlockRead(t *testing.T) {
	key := [16]byte{1, 2, 3, 4}
	encStream, _ := NewAEADStream(key)
	decStream, _ := NewAEADStream(key)

	// Encrypt chunk 1
	msg1 := []byte("first chunk data 1234567890")
	chunk1, err := encStream.EncryptChunk(nil, msg1)
	if err != nil {
		t.Fatalf("EncryptChunk: %v", err)
	}

	// Prepare chunk 2 header (2 bytes wire length = 1000) WITHOUT body
	var chunk2Hdr [2]byte
	binary.BigEndian.PutUint16(chunk2Hdr[:], 1000)

	// Combine chunk 1 and chunk 2 header together (mimicking a single TCP segment from IEPL relay)
	combined := append(chunk1, chunk2Hdr[:]...)

	r, w := io.Pipe()
	fr := NewFramedReader(r, decStream)

	// Write the combined packet into the pipe
	go func() {
		_, _ = w.Write(combined)
		// Body of chunk 2 is NOT written! We simulate a pause or waiting for response.
	}()

	buf := make([]byte, 4096)
	readDone := make(chan struct{})
	var n int
	var readErr error
	go func() {
		n, readErr = fr.Read(buf)
		close(readDone)
	}()

	select {
	case <-readDone:
		if readErr != nil {
			t.Fatalf("unexpected read error: %v", readErr)
		}
		if !bytes.Equal(buf[:n], msg1) {
			t.Fatalf("expected %q, got %q", msg1, buf[:n])
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("STALL DETECTED: FramedReader.Read blocked waiting for next chunk body instead of returning chunk 1!")
	}
}

func TestFramedReader_LeftoverDecBufReturnsImmediatelyWithoutBlocking(t *testing.T) {
	key := [16]byte{1, 2, 3, 4}
	encStream, _ := NewAEADStream(key)
	decStream, _ := NewAEADStream(key)

	// Encrypt chunk 1 (100 bytes)
	msg1 := bytes.Repeat([]byte("A"), 100)
	chunk1, _ := encStream.EncryptChunk(nil, msg1)

	// Chunk 2 header only (incomplete chunk)
	var chunk2Hdr [2]byte
	binary.BigEndian.PutUint16(chunk2Hdr[:], 500)

	combined := append(chunk1, chunk2Hdr[:]...)

	r, w := io.Pipe()
	fr := NewFramedReader(r, decStream)

	go func() {
		_, _ = w.Write(combined)
	}()

	// First read: reads only 40 bytes out of 100 bytes
	smallBuf := make([]byte, 40)
	n1, err := fr.Read(smallBuf)
	if err != nil || n1 != 40 {
		t.Fatalf("first read failed: n=%d, err=%v", n1, err)
	}

	// Now 60 bytes remain in fr.decBuf!
	// Second read: requests 4096 bytes. MUST return remaining 60 bytes immediately without touching pipe!
	bigBuf := make([]byte, 4096)
	readDone := make(chan struct{})
	var n2 int
	var err2 error
	go func() {
		n2, err2 = fr.Read(bigBuf)
		close(readDone)
	}()

	select {
	case <-readDone:
		if err2 != nil {
			t.Fatalf("second read error: %v", err2)
		}
		if n2 != 60 {
			t.Fatalf("expected 60 leftover bytes, got %d", n2)
		}
		if !bytes.Equal(bigBuf[:n2], msg1[40:]) {
			t.Fatalf("leftover data mismatch")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("STALL DETECTED: FramedReader.Read blocked waiting for network instead of returning leftover decBuf!")
	}
}

type countingWriter struct {
	writes [][]byte
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.writes = append(w.writes, bytes.Clone(p))
	return len(p), nil
}

func TestFramedWriter_WriteBatch_IntegrityAndFlushCount(t *testing.T) {
	var key [16]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	streamEnc, _ := NewAEADStream(key)
	streamDec, _ := NewAEADStream(key)

	cw := &countingWriter{}
	fw := NewFramedWriter(cw, streamEnc)
	// Fast forward to Phase 3 (> 1 MiB burst)
	fw.burstBytes = Phase2Threshold + 100

	// 16 slices of 8 KiB (128 KiB total), matching Xray MultiBuffer
	var slices [][]byte
	var fullPlaintext []byte
	for i := 0; i < 16; i++ {
		chunk := bytes.Repeat([]byte{byte(i + 65)}, 8192)
		slices = append(slices, chunk)
		fullPlaintext = append(fullPlaintext, chunk...)
	}

	n, err := fw.WriteBatch(slices)
	if err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	if n != len(fullPlaintext) {
		t.Fatalf("WriteBatch returned %d, want %d", n, len(fullPlaintext))
	}

	// In Phase 3, flushThreshold is 128 KiB. All 16 slices should be flushed in AT MOST 2 underlying writes (typically 1 or 2 due to 128K threshold + framing overhead)
	// Compare with 16 writes if done sequentially!
	if len(cw.writes) > 2 {
		t.Fatalf("WriteBatch produced %d writes, want <= 2", len(cw.writes))
	}

	if err := fw.WriteEOF(); err != nil {
		t.Fatalf("WriteEOF: %v", err)
	}

	// Verify reader can decrypt everything back identically
	var combinedEnc []byte
	for _, w := range cw.writes {
		combinedEnc = append(combinedEnc, w...)
	}

	fr := NewFramedReader(bytes.NewReader(combinedEnc), streamDec)
	got, err := io.ReadAll(fr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, fullPlaintext) {
		t.Fatalf("decrypted payload mismatch: got %d bytes, want %d bytes", len(got), len(fullPlaintext))
	}
}

