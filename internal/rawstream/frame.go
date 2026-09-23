package rawstream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"strconv"
	"time"
)

const (
	ClientHelloSize    = 48 // 8B Timestamp + 24B ClientNonce + 16B AuthTag
	ServerHelloSize    = 40 // 24B ServerNonce + 16B ServerAuthTag
	MaxChunkPayloadLen = 32768
	MaxChunkWireLen    = MaxChunkPayloadLen + 16 // 16B AES-GCM tag
	MaxTimestampSkew   = 90 * time.Second

	DefaultMinPadding = 32
	DefaultMaxPadding = 256

	MaxPolymorphicPadding = 64
	DomainPolymorphicMask = "CHITANDA-RAWSTREAM-POLY-V1"

	DomainClientHello = "CHITANDA-RAWSTREAM-CLIENT-V1"
	DomainServerHello = "CHITANDA-RAWSTREAM-SERVER-V1"
	Domain0RTTKey     = "CHITANDA-RAWSTREAM-0RTT-V1"
	DomainSessionKey  = "CHITANDA-RAWSTREAM-SESSION-V1"
)

var (
	ErrInvalidRecordLen          = errors.New("rawstream: invalid handshake record length")
	ErrTimestampExpired          = errors.New("rawstream: timestamp out of acceptable window")
	ErrInvalidClientAuth         = errors.New("rawstream: invalid client authentication tag")
	ErrInvalidServerAuth         = errors.New("rawstream: invalid server authentication tag")
	ErrInvalidPolymorphicPadding = errors.New("rawstream: invalid polymorphic padding length")
	ErrDecryptionFailed          = errors.New("rawstream: AEAD chunk decryption failed")
	ErrChunkTooLarge             = errors.New("rawstream: AEAD chunk length exceeds maximum allowed size")
	ErrInvalidOpenFrame          = errors.New("rawstream: invalid OPEN frame structure")
	ErrInvalidAddress            = errors.New("rawstream: unsupported address type in OPEN frame")
	ErrSequenceExhausted         = errors.New("rawstream: AEAD sequence number exhausted")
)

// CreateClientHello generates a 48-byte ClientHello record.
func CreateClientHello(psk []byte, serverID string, now time.Time) (record []byte, clientNonce [24]byte, timestamp uint64, err error) {
	if len(psk) < 32 {
		return nil, clientNonce, 0, errors.New("rawstream: PSK must be at least 32 bytes")
	}
	timestamp = uint64(now.Unix())
	if _, err := io.ReadFull(rand.Reader, clientNonce[:]); err != nil {
		return nil, clientNonce, 0, fmt.Errorf("rawstream: random generator failed: %w", err)
	}

	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(DomainClientHello))
	if len(serverID) > 0 {
		mac.Write([]byte(serverID))
	}
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], timestamp)
	mac.Write(tsBuf[:])
	mac.Write(clientNonce[:])
	fullTag := mac.Sum(nil)

	record = make([]byte, ClientHelloSize)
	copy(record[0:8], tsBuf[:])
	copy(record[8:32], clientNonce[:])
	copy(record[32:48], fullTag[:16])

	return record, clientNonce, timestamp, nil
}

// VerifyClientHello verifies an incoming 48-byte ClientHello record.
func VerifyClientHello(psk []byte, serverID string, record []byte, now time.Time) (clientNonce [24]byte, timestamp uint64, err error) {
	if len(psk) < 32 {
		return clientNonce, 0, errors.New("rawstream: PSK must be at least 32 bytes")
	}
	if len(record) != ClientHelloSize {
		return clientNonce, 0, ErrInvalidRecordLen
	}

	timestamp = binary.BigEndian.Uint64(record[0:8])
	copy(clientNonce[:], record[8:32])
	clientTag := record[32:48]

	nowSec := uint64(now.Unix())
	diff := int64(nowSec) - int64(timestamp)
	if diff < -int64(MaxTimestampSkew/time.Second) || diff > int64(MaxTimestampSkew/time.Second) {
		return clientNonce, 0, ErrTimestampExpired
	}

	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(DomainClientHello))
	if len(serverID) > 0 {
		mac.Write([]byte(serverID))
	}
	mac.Write(record[0:8])
	mac.Write(clientNonce[:])
	expectedFullTag := mac.Sum(nil)

	if !hmac.Equal(clientTag, expectedFullTag[:16]) {
		return clientNonce, 0, ErrInvalidClientAuth
	}

	return clientNonce, timestamp, nil
}

// DerivePolymorphicMasks derives two 1-byte obfuscation masks for ClientHello and ServerHello padding lengths.
func DerivePolymorphicMasks(psk []byte, serverID string) (clientMask, serverMask byte) {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(DomainPolymorphicMask))
	if len(serverID) > 0 {
		mac.Write([]byte(serverID))
	}
	sum := mac.Sum(nil)
	return sum[0], sum[1]
}

func deriveTimestampMask(psk []byte, nonce [24]byte) [8]byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte("rawstream-ts-mask"))
	mac.Write(nonce[:])
	var mask [8]byte
	copy(mask[:], mac.Sum(nil)[:8])
	return mask
}

// CreatePolymorphicClientHello generates a variable-length (49-113 bytes) ClientHello record.
// Wire structure:
// [1B padLen ^ clientMask] [8B masked ts] [24B nonce] [16B tag] [padLen random padBytes]
// The 16B HMAC tag covers DomainClientHello, serverID, ts, clientNonce, and padLen.
func CreatePolymorphicClientHello(psk []byte, serverID string, now time.Time) (record []byte, clientNonce [24]byte, timestamp uint64, err error) {
	if len(psk) < 32 {
		return nil, clientNonce, 0, errors.New("rawstream: PSK must be at least 32 bytes")
	}
	clientMask, _ := DerivePolymorphicMasks(psk, serverID)

	var padLenBuf [1]byte
	if _, err := io.ReadFull(rand.Reader, padLenBuf[:]); err != nil {
		return nil, clientNonce, 0, fmt.Errorf("rawstream: rand padLen failed: %w", err)
	}
	padLen := int(padLenBuf[0] % (MaxPolymorphicPadding + 1)) // 0 to 64 bytes

	padBytes := make([]byte, padLen)
	if padLen > 0 {
		if _, err := io.ReadFull(rand.Reader, padBytes); err != nil {
			return nil, clientNonce, 0, fmt.Errorf("rawstream: rand padBytes failed: %w", err)
		}
	}

	timestamp = uint64(now.Unix())
	if _, err := io.ReadFull(rand.Reader, clientNonce[:]); err != nil {
		return nil, clientNonce, 0, fmt.Errorf("rawstream: random generator failed: %w", err)
	}

	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(DomainClientHello))
	if len(serverID) > 0 {
		mac.Write([]byte(serverID))
	}
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], timestamp)
	mac.Write(tsBuf[:])
	mac.Write(clientNonce[:])
	mac.Write([]byte{byte(padLen)})
	fullTag := mac.Sum(nil)

	// Obfuscate timestamp with nonce-derived keystream
	tsMask := deriveTimestampMask(psk, clientNonce)
	var maskedTs [8]byte
	for i := 0; i < 8; i++ {
		maskedTs[i] = tsBuf[i] ^ tsMask[i]
	}

	record = make([]byte, 1+ClientHelloSize+padLen)
	record[0] = byte(padLen) ^ clientMask
	copy(record[1:9], maskedTs[:])
	copy(record[9:33], clientNonce[:])
	copy(record[33:49], fullTag[:16])
	if padLen > 0 {
		copy(record[49:49+padLen], padBytes)
	}

	return record, clientNonce, timestamp, nil
}

// VerifyPolymorphicClientHello verifies an incoming variable-length ClientHello record from a byte buffer.
func VerifyPolymorphicClientHello(psk []byte, serverID string, record []byte, now time.Time) (clientNonce [24]byte, timestamp uint64, err error) {
	if len(psk) < 32 {
		return clientNonce, 0, errors.New("rawstream: PSK must be at least 32 bytes")
	}
	if len(record) < 1+ClientHelloSize {
		return clientNonce, 0, ErrInvalidRecordLen
	}
	clientMask, _ := DerivePolymorphicMasks(psk, serverID)
	padLen := int(record[0] ^ clientMask)
	if padLen > MaxPolymorphicPadding {
		return clientNonce, 0, ErrInvalidPolymorphicPadding
	}
	if len(record) != 1+ClientHelloSize+padLen {
		return clientNonce, 0, ErrInvalidRecordLen
	}

	copy(clientNonce[:], record[9:33])
	tsMask := deriveTimestampMask(psk, clientNonce)
	var tsBuf [8]byte
	for i := 0; i < 8; i++ {
		tsBuf[i] = record[1+i] ^ tsMask[i]
	}
	timestamp = binary.BigEndian.Uint64(tsBuf[:])

	nowSec := uint64(now.Unix())
	diff := int64(nowSec) - int64(timestamp)
	if diff < -int64(MaxTimestampSkew/time.Second) || diff > int64(MaxTimestampSkew/time.Second) {
		return clientNonce, 0, ErrTimestampExpired
	}

	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(DomainClientHello))
	if len(serverID) > 0 {
		mac.Write([]byte(serverID))
	}
	mac.Write(tsBuf[:])
	mac.Write(clientNonce[:])
	mac.Write([]byte{byte(padLen)})
	expectedFullTag := mac.Sum(nil)

	if !hmac.Equal(record[33:49], expectedFullTag[:16]) {
		return clientNonce, 0, ErrInvalidClientAuth
	}

	return clientNonce, timestamp, nil
}

// MatchPolymorphicClientHelloHeader matches the fixed 49-byte authenticated header against multiple PSKs in memory.
// It does not perform network I/O; header must be at least 49 bytes.
// If matched, returns the index of the key in keys, padLen, clientNonce, timestamp, nil.
// If no key matches, returns -1, 0, clientNonce, 0, ErrInvalidClientAuth.
func MatchPolymorphicClientHelloHeader(header []byte, keys [][]byte, serverID string, now time.Time) (matchedIndex int, padLen int, clientNonce [24]byte, timestamp uint64, err error) {
	if len(header) < 1+ClientHelloSize {
		return -1, 0, clientNonce, 0, ErrInvalidRecordLen
	}

	copy(clientNonce[:], header[9:33])
	clientTag := header[33:49]
	nowSec := uint64(now.Unix())

	if len(keys) == 1 {
		psk := keys[0]
		if len(psk) < 32 {
			return -1, 0, clientNonce, 0, errors.New("rawstream: PSK must be at least 32 bytes")
		}
		clientMask, _ := DerivePolymorphicMasks(psk, serverID)
		pLen := int(header[0] ^ clientMask)
		if pLen > MaxPolymorphicPadding {
			return -1, 0, clientNonce, 0, ErrInvalidPolymorphicPadding
		}

		tsMask := deriveTimestampMask(psk, clientNonce)
		var tsBuf [8]byte
		for j := 0; j < 8; j++ {
			tsBuf[j] = header[1+j] ^ tsMask[j]
		}
		ts := binary.BigEndian.Uint64(tsBuf[:])

		diff := int64(nowSec) - int64(ts)
		if diff < -int64(MaxTimestampSkew/time.Second) || diff > int64(MaxTimestampSkew/time.Second) {
			return -1, 0, clientNonce, 0, ErrTimestampExpired
		}

		mac := hmac.New(sha256.New, psk)
		mac.Write([]byte(DomainClientHello))
		if len(serverID) > 0 {
			mac.Write([]byte(serverID))
		}
		mac.Write(tsBuf[:])
		mac.Write(clientNonce[:])
		mac.Write([]byte{byte(pLen)})
		expectedFullTag := mac.Sum(nil)

		if !hmac.Equal(clientTag, expectedFullTag[:16]) {
			return -1, 0, clientNonce, 0, ErrInvalidClientAuth
		}

		return 0, pLen, clientNonce, ts, nil
	}

	expiredFound := false
	for i, psk := range keys {
		if len(psk) < 32 {
			continue
		}
		clientMask, _ := DerivePolymorphicMasks(psk, serverID)
		pLen := int(header[0] ^ clientMask)
		if pLen > MaxPolymorphicPadding {
			continue
		}

		tsMask := deriveTimestampMask(psk, clientNonce)
		var tsBuf [8]byte
		for j := 0; j < 8; j++ {
			tsBuf[j] = header[1+j] ^ tsMask[j]
		}
		ts := binary.BigEndian.Uint64(tsBuf[:])

		mac := hmac.New(sha256.New, psk)
		mac.Write([]byte(DomainClientHello))
		if len(serverID) > 0 {
			mac.Write([]byte(serverID))
		}
		mac.Write(tsBuf[:])
		mac.Write(clientNonce[:])
		mac.Write([]byte{byte(pLen)})
		expectedFullTag := mac.Sum(nil)

		if hmac.Equal(clientTag, expectedFullTag[:16]) {
			diff := int64(nowSec) - int64(ts)
			if diff < -int64(MaxTimestampSkew/time.Second) || diff > int64(MaxTimestampSkew/time.Second) {
				expiredFound = true
				continue
			}
			return i, pLen, clientNonce, ts, nil
		}
	}

	if expiredFound {
		return -1, 0, clientNonce, 0, ErrTimestampExpired
	}
	return -1, 0, clientNonce, 0, ErrInvalidClientAuth
}


// ReadAndMatchPolymorphicClientHello reads the fixed 49-byte header from r, matches against multiple keys,
// and if matched, reads the trailing padBytes (if padLen > 0).
func ReadAndMatchPolymorphicClientHello(r io.Reader, keys [][]byte, serverID string, now time.Time) (matchedIndex int, clientNonce [24]byte, timestamp uint64, err error) {
	var header [1 + ClientHelloSize]byte // 49 bytes
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return -1, clientNonce, 0, err
	}

	matchedIdx, padLen, cNonce, ts, err := MatchPolymorphicClientHelloHeader(header[:], keys, serverID, now)
	if err != nil {
		return -1, clientNonce, 0, err
	}

	if padLen > 0 {
		padBytes := make([]byte, padLen)
		if _, err := io.ReadFull(r, padBytes); err != nil {
			return -1, clientNonce, 0, err
		}
	}

	return matchedIdx, cNonce, ts, nil
}

// ReadAndVerifyPolymorphicClientHello reads the fixed 49-byte authenticated header first,
// verifies the HMAC and freshness in constant time, and only reads padBytes if authenticated.
func ReadAndVerifyPolymorphicClientHello(r io.Reader, psk []byte, serverID string, now time.Time) (clientNonce [24]byte, timestamp uint64, err error) {
	if len(psk) < 32 {
		return clientNonce, 0, errors.New("rawstream: PSK must be at least 32 bytes")
	}
	matched, cNonce, ts, err := ReadAndMatchPolymorphicClientHello(r, [][]byte{psk}, serverID, now)
	if err != nil || matched < 0 {
		return cNonce, ts, err
	}
	return cNonce, ts, nil
}


// Derive0RTTKey derives a 16-byte key for AES-128-GCM 0-RTT frame encryption.
func Derive0RTTKey(psk []byte, serverID string, timestamp uint64, clientNonce [24]byte) ([16]byte, error) {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(Domain0RTTKey))
	if len(serverID) > 0 {
		mac.Write([]byte(serverID))
	}
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], timestamp)
	mac.Write(tsBuf[:])
	mac.Write(clientNonce[:])
	sum := mac.Sum(nil)

	var key [16]byte
	copy(key[:], sum[:16])
	return key, nil
}

// DeriveSessionKeys derives bidirectional 16-byte keys for established AES-128-GCM sessions.
func DeriveSessionKeys(psk []byte, serverID string, timestamp uint64, clientNonce, serverNonce [24]byte) (clientKey, serverKey [16]byte, err error) {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(DomainSessionKey))
	if len(serverID) > 0 {
		mac.Write([]byte(serverID))
	}
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], timestamp)
	mac.Write(tsBuf[:])
	mac.Write(clientNonce[:])
	mac.Write(serverNonce[:])
	prk := mac.Sum(nil)

	// Client to Server key (AES-128: 16 bytes)
	h1 := hmac.New(sha256.New, prk)
	h1.Write([]byte("C2S"))
	copy(clientKey[:], h1.Sum(nil)[:16])

	// Server to Client key (AES-128: 16 bytes)
	h2 := hmac.New(sha256.New, prk)
	h2.Write([]byte("S2C"))
	copy(serverKey[:], h2.Sum(nil)[:16])

	return clientKey, serverKey, nil
}

// CreateServerHello generates a 40-byte ServerHello response record.
func CreateServerHello(psk []byte, serverID string, timestamp uint64, clientNonce [24]byte) (record []byte, serverNonce [24]byte, err error) {
	if _, err := io.ReadFull(rand.Reader, serverNonce[:]); err != nil {
		return nil, serverNonce, fmt.Errorf("rawstream: server random failed: %w", err)
	}

	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(DomainServerHello))
	if len(serverID) > 0 {
		mac.Write([]byte(serverID))
	}
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], timestamp)
	mac.Write(tsBuf[:])
	mac.Write(clientNonce[:])
	mac.Write(serverNonce[:])
	fullTag := mac.Sum(nil)

	record = make([]byte, ServerHelloSize)
	copy(record[0:24], serverNonce[:])
	copy(record[24:40], fullTag[:16])

	return record, serverNonce, nil
}

// VerifyServerHello verifies the incoming 40-byte ServerHello record.
func VerifyServerHello(psk []byte, serverID string, timestamp uint64, clientNonce [24]byte, record []byte) (serverNonce [24]byte, err error) {
	if len(record) != ServerHelloSize {
		return serverNonce, ErrInvalidRecordLen
	}
	copy(serverNonce[:], record[0:24])
	serverTag := record[24:40]

	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(DomainServerHello))
	if len(serverID) > 0 {
		mac.Write([]byte(serverID))
	}
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], timestamp)
	mac.Write(tsBuf[:])
	mac.Write(clientNonce[:])
	mac.Write(serverNonce[:])
	expectedFullTag := mac.Sum(nil)

	if !hmac.Equal(serverTag, expectedFullTag[:16]) {
		return serverNonce, ErrInvalidServerAuth
	}

	return serverNonce, nil
}

// CreatePolymorphicServerHello generates a variable-length (41-105 bytes) ServerHello response record.
// Wire structure:
// [1B padLen ^ serverMask] [24B serverNonce] [16B tag] [padLen random padBytes]
func CreatePolymorphicServerHello(psk []byte, serverID string, timestamp uint64, clientNonce [24]byte) (record []byte, serverNonce [24]byte, err error) {
	if len(psk) < 32 {
		return nil, serverNonce, errors.New("rawstream: PSK must be at least 32 bytes")
	}
	_, serverMask := DerivePolymorphicMasks(psk, serverID)

	var padLenBuf [1]byte
	if _, err := io.ReadFull(rand.Reader, padLenBuf[:]); err != nil {
		return nil, serverNonce, fmt.Errorf("rawstream: server rand padLen failed: %w", err)
	}
	padLen := int(padLenBuf[0] % (MaxPolymorphicPadding + 1)) // 0 to 64 bytes

	padBytes := make([]byte, padLen)
	if padLen > 0 {
		if _, err := io.ReadFull(rand.Reader, padBytes); err != nil {
			return nil, serverNonce, fmt.Errorf("rawstream: server rand padBytes failed: %w", err)
		}
	}

	if _, err := io.ReadFull(rand.Reader, serverNonce[:]); err != nil {
		return nil, serverNonce, fmt.Errorf("rawstream: server random failed: %w", err)
	}

	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(DomainServerHello))
	if len(serverID) > 0 {
		mac.Write([]byte(serverID))
	}
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], timestamp)
	mac.Write(tsBuf[:])
	mac.Write(clientNonce[:])
	mac.Write(serverNonce[:])
	mac.Write([]byte{byte(padLen)})
	fullTag := mac.Sum(nil)

	record = make([]byte, 1+ServerHelloSize+padLen)
	record[0] = byte(padLen) ^ serverMask
	copy(record[1:25], serverNonce[:])
	copy(record[25:41], fullTag[:16])
	if padLen > 0 {
		copy(record[41:41+padLen], padBytes)
	}

	return record, serverNonce, nil
}

// VerifyPolymorphicServerHello verifies the incoming variable-length ServerHello record from a byte buffer.
func VerifyPolymorphicServerHello(psk []byte, serverID string, timestamp uint64, clientNonce [24]byte, record []byte) (serverNonce [24]byte, err error) {
	if len(psk) < 32 {
		return serverNonce, errors.New("rawstream: PSK must be at least 32 bytes")
	}
	if len(record) < 1+ServerHelloSize {
		return serverNonce, ErrInvalidRecordLen
	}
	_, serverMask := DerivePolymorphicMasks(psk, serverID)
	padLen := int(record[0] ^ serverMask)
	if padLen > MaxPolymorphicPadding {
		return serverNonce, ErrInvalidPolymorphicPadding
	}
	if len(record) != 1+ServerHelloSize+padLen {
		return serverNonce, ErrInvalidRecordLen
	}

	copy(serverNonce[:], record[1:25])
	serverTag := record[25:41]

	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(DomainServerHello))
	if len(serverID) > 0 {
		mac.Write([]byte(serverID))
	}
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], timestamp)
	mac.Write(tsBuf[:])
	mac.Write(clientNonce[:])
	mac.Write(serverNonce[:])
	mac.Write([]byte{byte(padLen)})
	expectedFullTag := mac.Sum(nil)

	if !hmac.Equal(serverTag, expectedFullTag[:16]) {
		return serverNonce, ErrInvalidServerAuth
	}

	return serverNonce, nil
}

// ReadAndVerifyPolymorphicServerHello reads the fixed 41-byte authenticated header first,
// verifies the HMAC in constant time, and only reads padBytes if authenticated.
func ReadAndVerifyPolymorphicServerHello(r io.Reader, psk []byte, serverID string, timestamp uint64, clientNonce [24]byte) (serverNonce [24]byte, err error) {
	if len(psk) < 32 {
		return serverNonce, errors.New("rawstream: PSK must be at least 32 bytes")
	}
	var header [1 + ServerHelloSize]byte // 41 bytes
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return serverNonce, err
	}
	_, serverMask := DerivePolymorphicMasks(psk, serverID)
	padLen := int(header[0] ^ serverMask)
	if padLen > MaxPolymorphicPadding {
		return serverNonce, ErrInvalidPolymorphicPadding
	}

	copy(serverNonce[:], header[1:25])
	serverTag := header[25:41]

	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(DomainServerHello))
	if len(serverID) > 0 {
		mac.Write([]byte(serverID))
	}
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], timestamp)
	mac.Write(tsBuf[:])
	mac.Write(clientNonce[:])
	mac.Write(serverNonce[:])
	mac.Write([]byte{byte(padLen)})
	expectedFullTag := mac.Sum(nil)

	if !hmac.Equal(serverTag, expectedFullTag[:16]) {
		return serverNonce, ErrInvalidServerAuth
	}

	if padLen > 0 {
		padBytes := make([]byte, padLen)
		if _, err := io.ReadFull(r, padBytes); err != nil {
			return serverNonce, err
		}
	}

	return serverNonce, nil
}

// Encode0RTTOpenFrame encodes target address and initial payload with dynamic random padding.
// Plaintext structure:
// [2B PaddingLen] [PaddingBytes] [TargetAddr (SOCKS5)] [InitialPayload]
func Encode0RTTOpenFrame(target string, initialPayload []byte, minPad, maxPad int) ([]byte, error) {
	if minPad < 0 {
		minPad = DefaultMinPadding
	}
	if maxPad < minPad {
		maxPad = DefaultMaxPadding
	}

	padSpan := maxPad - minPad + 1
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(padSpan)))
	if err != nil {
		return nil, fmt.Errorf("rawstream: rand padding: %w", err)
	}
	paddingLen := minPad + int(nBig.Int64())

	padding := make([]byte, paddingLen)
	if _, err := io.ReadFull(rand.Reader, padding); err != nil {
		return nil, fmt.Errorf("rawstream: fill padding: %w", err)
	}

	targetBytes, err := encodeTargetAddress(target)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 2+paddingLen+len(targetBytes)+len(initialPayload))
	binary.BigEndian.PutUint16(buf[0:2], uint16(paddingLen))
	copy(buf[2:2+paddingLen], padding)
	offset := 2 + paddingLen
	copy(buf[offset:offset+len(targetBytes)], targetBytes)
	offset += len(targetBytes)
	copy(buf[offset:], initialPayload)

	return buf, nil
}

// Decode0RTTOpenFrame decodes target address and initial payload, stripping dynamic padding.
func Decode0RTTOpenFrame(plaintext []byte) (target string, initialPayload []byte, err error) {
	if len(plaintext) < 2 {
		return "", nil, ErrInvalidOpenFrame
	}
	paddingLen := int(binary.BigEndian.Uint16(plaintext[0:2]))
	if len(plaintext) < 2+paddingLen {
		return "", nil, ErrInvalidOpenFrame
	}

	rest := plaintext[2+paddingLen:]
	target, consumed, err := decodeTargetAddress(rest)
	if err != nil {
		return "", nil, err
	}

	initialPayload = rest[consumed:]
	return target, initialPayload, nil
}

func encodeTargetAddress(address string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", address, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid port %q", portText)
	}

	var buf []byte
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			buf = append(buf, 0x01) // IPv4
			buf = append(buf, ipv4...)
		} else {
			buf = append(buf, 0x04) // IPv6
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("invalid domain length %d", len(host))
		}
		buf = append(buf, 0x03) // Domain
		buf = append(buf, byte(len(host)))
		buf = append(buf, host...)
	}

	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port))
	buf = append(buf, portBuf[:]...)
	return buf, nil
}

func decodeTargetAddress(b []byte) (string, int, error) {
	if len(b) < 1+4+2 {
		return "", 0, ErrInvalidOpenFrame
	}
	atyp := b[0]
	switch atyp {
	case 0x01: // IPv4
		if len(b) < 1+net.IPv4len+2 {
			return "", 0, ErrInvalidOpenFrame
		}
		ip := net.IP(b[1 : 1+net.IPv4len])
		port := binary.BigEndian.Uint16(b[1+net.IPv4len : 1+net.IPv4len+2])
		return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), 1 + net.IPv4len + 2, nil

	case 0x04: // IPv6
		if len(b) < 1+net.IPv6len+2 {
			return "", 0, ErrInvalidOpenFrame
		}
		ip := net.IP(b[1 : 1+net.IPv6len])
		port := binary.BigEndian.Uint16(b[1+net.IPv6len : 1+net.IPv6len+2])
		return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), 1 + net.IPv6len + 2, nil

	case 0x03: // Domain
		domainLen := int(b[1])
		if domainLen == 0 || len(b) < 2+domainLen+2 {
			return "", 0, ErrInvalidOpenFrame
		}
		domain := string(b[2 : 2+domainLen])
		port := binary.BigEndian.Uint16(b[2+domainLen : 2+domainLen+2])
		return net.JoinHostPort(domain, strconv.Itoa(int(port))), 2 + domainLen + 2, nil

	default:
		return "", 0, ErrInvalidAddress
	}
}

// Encrypt0RTTChunk encrypts plaintext using AES-128-GCM with the 0-RTT key.
func Encrypt0RTTChunk(k0RTT [16]byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(k0RTT[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	var nonce [12]byte // 0-RTT uses single fixed zero nonce
	return aead.Seal(nil, nonce[:], plaintext, nil), nil
}

// Decrypt0RTTChunk decrypts ciphertext using AES-128-GCM with the 0-RTT key.
func Decrypt0RTTChunk(k0RTT [16]byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(k0RTT[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	return aead.Open(nil, nonce[:], ciphertext, nil)
}

// AEADStream manages sequential chunk encryption/decryption with monotonic nonces.
type AEADStream struct {
	aead     cipher.AEAD
	sequence uint64
	nonceBuf [12]byte
	lenBuf   [2]byte
}

// NewAEADStream creates an AEADStream with AES-128-GCM.
func NewAEADStream(key [16]byte) (*AEADStream, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &AEADStream{aead: aead}, nil
}

// EncryptChunk seals plaintext into dst (allocating if nil) prefixed with a 2-byte length.
func (s *AEADStream) EncryptChunk(dst, plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxChunkPayloadLen {
		return nil, ErrChunkTooLarge
	}
	if s.sequence == math.MaxUint64 {
		return nil, ErrSequenceExhausted
	}
	binary.BigEndian.PutUint64(s.nonceBuf[4:12], s.sequence)
	s.sequence++

	wirePayloadLen := len(plaintext) + s.aead.Overhead()
	if dst == nil {
		dst = make([]byte, 0, 2+wirePayloadLen)
	}
	binary.BigEndian.PutUint16(s.lenBuf[:], uint16(wirePayloadLen))
	dst = append(dst, s.lenBuf[:]...)
	dst = s.aead.Seal(dst, s.nonceBuf[:], plaintext, s.lenBuf[:])
	return dst, nil
}

// DecryptChunk opens ciphertext with associated 2-byte wire length data.
func (s *AEADStream) DecryptChunk(dst, ciphertext []byte, wireLen uint16) ([]byte, error) {
	if s.sequence == math.MaxUint64 {
		return nil, ErrSequenceExhausted
	}
	binary.BigEndian.PutUint64(s.nonceBuf[4:12], s.sequence)
	s.sequence++

	binary.BigEndian.PutUint16(s.lenBuf[:], wireLen)
	return s.aead.Open(dst, s.nonceBuf[:], ciphertext, s.lenBuf[:])
}
