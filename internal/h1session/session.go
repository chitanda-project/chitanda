package h1session

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ClientHelloSize    = 48 // 8B Timestamp + 24B ClientNonce + 16B AuthTag
	ServerHelloSize    = 40 // 24B ServerNonce + 16B ServerAuthTag
	MaxChunkPayloadLen = 16384
	MaxChunkWireLen    = MaxChunkPayloadLen + 16 // 16B Poly1305 tag
	MaxTimestampSkew   = 90 * time.Second

	DomainClientHello = "MYXRAY-H1-CLIENT-V1"
	DomainSessionInfo = "MYXRAY-H1-SESSION-V1"
	Domain0RTT        = "MYXRAY-H1-0RTT-V1"

	CmdConnectTCP byte = 0x01
)

var (
	ErrInvalidRecordLen   = errors.New("h1session: invalid handshake record length")
	ErrTimestampExpired   = errors.New("h1session: timestamp out of acceptable window")
	ErrInvalidClientAuth  = errors.New("h1session: invalid client authentication tag")
	ErrInvalidServerAuth  = errors.New("h1session: invalid server authentication tag")
	ErrDecryptionFailed   = errors.New("h1session: AEAD chunk decryption failed")
	ErrChunkTooLarge      = errors.New("h1session: AEAD chunk length exceeds maximum allowed size")
	ErrInvalidOpenFrame   = errors.New("h1session: invalid OPEN frame structure")
	ErrInvalidAddressType = errors.New("h1session: unsupported address type in OPEN frame")
)

// CreateClientHello generates a 48-byte ClientHello record.
func CreateClientHello(psk []byte, now time.Time) (record []byte, clientNonce [24]byte, timestamp uint64, err error) {
	if len(psk) < 32 {
		return nil, clientNonce, 0, errors.New("h1session: PSK must be at least 32 bytes")
	}
	timestamp = uint64(now.Unix())
	if _, err := io.ReadFull(rand.Reader, clientNonce[:]); err != nil {
		return nil, clientNonce, 0, fmt.Errorf("h1session: random generator failed: %w", err)
	}

	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(DomainClientHello))
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

// MatchClientHello verifies an incoming 48-byte ClientHello record against multiple PSKs.
// Returns the index of the matching key in keys, clientNonce, timestamp, or an error.
func MatchClientHello(keys [][]byte, record []byte, now time.Time) (matchedIndex int, clientNonce [24]byte, timestamp uint64, err error) {
	if len(record) != ClientHelloSize {
		return -1, clientNonce, 0, ErrInvalidRecordLen
	}

	timestamp = binary.BigEndian.Uint64(record[0:8])
	copy(clientNonce[:], record[8:32])
	clientTag := record[32:48]

	nowSec := uint64(now.Unix())
	diff := int64(nowSec) - int64(timestamp)
	if diff < -int64(MaxTimestampSkew/time.Second) || diff > int64(MaxTimestampSkew/time.Second) {
		return -1, clientNonce, 0, ErrTimestampExpired
	}

	for i, psk := range keys {
		if len(psk) < 32 {
			continue
		}
		mac := hmac.New(sha256.New, psk)
		mac.Write([]byte(DomainClientHello))
		mac.Write(record[0:8])
		mac.Write(clientNonce[:])
		expectedFullTag := mac.Sum(nil)

		if hmac.Equal(clientTag, expectedFullTag[:16]) {
			return i, clientNonce, timestamp, nil
		}
	}

	return -1, clientNonce, 0, ErrInvalidClientAuth
}

// VerifyClientHello verifies an incoming 48-byte ClientHello record.
func VerifyClientHello(psk []byte, record []byte, now time.Time) (clientNonce [24]byte, timestamp uint64, err error) {
	if len(psk) < 32 {
		return clientNonce, 0, errors.New("h1session: PSK must be at least 32 bytes")
	}
	matched, cNonce, ts, err := MatchClientHello([][]byte{psk}, record, now)
	if err != nil || matched < 0 {
		return cNonce, ts, err
	}
	return cNonce, ts, nil
}


// Derive0RTTKey derives a 32-byte 0-RTT ChaCha20-Poly1305 key for Flight 1 client payload.
func Derive0RTTKey(psk []byte, timestamp uint64, clientNonce [24]byte) ([32]byte, error) {
	var key [32]byte
	if len(psk) < 32 {
		return key, errors.New("h1session: PSK must be at least 32 bytes")
	}

	// Salt = clientNonce (24B)
	extractor := hmac.New(sha256.New, clientNonce[:])
	extractor.Write(psk)
	prk := extractor.Sum(nil) // 32B

	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], timestamp)

	expander := hmac.New(sha256.New, prk)
	expander.Write([]byte(Domain0RTT))
	expander.Write(tsBuf[:])
	expander.Write([]byte{0x01})
	t1 := expander.Sum(nil)

	copy(key[:], t1[0:32])
	return key, nil
}

// Encrypt0RTTChunk encrypts plaintext with the 0-RTT key and prepends a 2-byte wire length header.
func Encrypt0RTTChunk(key [32]byte, plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxChunkPayloadLen {
		return nil, ErrChunkTooLarge
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	copy(nonce[0:4], "0RTT")
	// nonce[4:12] is 0

	wireLen := len(plaintext) + aead.Overhead()
	dst := make([]byte, 0, 2+wireLen)
	dst = binary.BigEndian.AppendUint16(dst, uint16(wireLen))
	dst = aead.Seal(dst, nonce[:], plaintext, nil)
	return dst, nil
}

// Decrypt0RTTChunk decrypts a 0-RTT wire chunk (excluding the 2-byte length header).
func Decrypt0RTTChunk(key [32]byte, ciphertextWithTag []byte) ([]byte, error) {
	if len(ciphertextWithTag) > MaxChunkWireLen {
		return nil, ErrChunkTooLarge
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	copy(nonce[0:4], "0RTT")

	plaintext, err := aead.Open(nil, nonce[:], ciphertextWithTag, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

// CreateServerHello generates a 40-byte ServerHello record and derives 1-RTT session keys.
func CreateServerHello(psk []byte, clientNonce [24]byte) (serverHello []byte, clientKey, serverKey [32]byte, err error) {
	var serverNonce [24]byte
	if _, err := io.ReadFull(rand.Reader, serverNonce[:]); err != nil {
		return nil, clientKey, serverKey, fmt.Errorf("h1session: random generator failed: %w", err)
	}

	clientKey, serverKey, serverAuthTag, err := deriveKeys(psk, clientNonce, serverNonce)
	if err != nil {
		return nil, clientKey, serverKey, err
	}

	serverHello = make([]byte, ServerHelloSize)
	copy(serverHello[0:24], serverNonce[:])
	copy(serverHello[24:40], serverAuthTag[:])

	return serverHello, clientKey, serverKey, nil
}

// VerifyServerHello verifies an incoming 40-byte ServerHello record and derives 1-RTT session keys.
func VerifyServerHello(psk []byte, clientNonce [24]byte, serverHello []byte) (clientKey, serverKey [32]byte, err error) {
	if len(serverHello) != ServerHelloSize {
		return clientKey, serverKey, ErrInvalidRecordLen
	}

	var serverNonce [24]byte
	copy(serverNonce[:], serverHello[0:24])
	serverTag := serverHello[24:40]

	clientKey, serverKey, expectedServerAuthTag, err := deriveKeys(psk, clientNonce, serverNonce)
	if err != nil {
		return clientKey, serverKey, err
	}

	if !hmac.Equal(serverTag, expectedServerAuthTag[:]) {
		return clientKey, serverKey, ErrInvalidServerAuth
	}

	return clientKey, serverKey, nil
}

func deriveKeys(psk []byte, clientNonce, serverNonce [24]byte) (clientKey, serverKey [32]byte, serverAuthTag [16]byte, err error) {
	salt := make([]byte, 48)
	copy(salt[0:24], clientNonce[:])
	copy(salt[24:48], serverNonce[:])

	extractor := hmac.New(sha256.New, salt)
	extractor.Write(psk)
	prk := extractor.Sum(nil) // 32 bytes

	expander1 := hmac.New(sha256.New, prk)
	expander1.Write([]byte(DomainSessionInfo))
	expander1.Write([]byte{0x01})
	t1 := expander1.Sum(nil) // 32 bytes

	expander2 := hmac.New(sha256.New, prk)
	expander2.Write(t1)
	expander2.Write([]byte(DomainSessionInfo))
	expander2.Write([]byte{0x02})
	t2 := expander2.Sum(nil) // 32 bytes

	expander3 := hmac.New(sha256.New, prk)
	expander3.Write(t2)
	expander3.Write([]byte(DomainSessionInfo))
	expander3.Write([]byte{0x03})
	t3 := expander3.Sum(nil) // 32 bytes

	copy(clientKey[:], t1)
	copy(serverKey[:], t2)
	copy(serverAuthTag[:], t3[0:16])
	return clientKey, serverKey, serverAuthTag, nil
}

// EncodeOpenFrame builds an encrypted OPEN frame payload containing target address and early data.
func EncodeOpenFrame(targetAddress string, initialPayload []byte) ([]byte, error) {
	host, portText, err := net.SplitHostPort(targetAddress)
	if err != nil {
		return nil, fmt.Errorf("h1session: invalid target address %q: %w", targetAddress, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("h1session: invalid port %q", portText)
	}

	buf := make([]byte, 0, 1+1+16+2+len(initialPayload))
	buf = append(buf, CmdConnectTCP)

	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			buf = append(buf, 0x01)
			buf = append(buf, ipv4...)
		} else {
			buf = append(buf, 0x04)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("h1session: invalid domain host length: %d", len(host))
		}
		buf = append(buf, 0x03, byte(len(host)))
		buf = append(buf, host...)
	}

	buf = binary.BigEndian.AppendUint16(buf, uint16(port))
	if len(initialPayload) > 0 {
		buf = append(buf, initialPayload...)
	}
	return buf, nil
}

// DecodeOpenFrame parses an OPEN frame payload into target address and initial data.
func DecodeOpenFrame(data []byte) (targetAddress string, payload []byte, err error) {
	if len(data) < 7 {
		return "", nil, ErrInvalidOpenFrame
	}
	if data[0] != CmdConnectTCP {
		return "", nil, fmt.Errorf("h1session: unsupported command 0x%02x", data[0])
	}

	offset := 1
	var host string
	addrType := data[offset]
	offset++

	switch addrType {
	case 0x01: // IPv4
		if len(data) < offset+4+2 {
			return "", nil, ErrInvalidOpenFrame
		}
		host = net.IP(data[offset : offset+4]).String()
		offset += 4
	case 0x03: // Domain
		if len(data) < offset+1 {
			return "", nil, ErrInvalidOpenFrame
		}
		domainLen := int(data[offset])
		offset++
		if len(data) < offset+domainLen+2 {
			return "", nil, ErrInvalidOpenFrame
		}
		host = string(data[offset : offset+domainLen])
		offset += domainLen
	case 0x04: // IPv6
		if len(data) < offset+16+2 {
			return "", nil, ErrInvalidOpenFrame
		}
		host = net.IP(data[offset : offset+16]).String()
		offset += 16
	default:
		return "", nil, ErrInvalidAddressType
	}

	port := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	targetAddress = net.JoinHostPort(host, strconv.Itoa(int(port)))
	if len(data) > offset {
		payload = data[offset:]
	}
	return targetAddress, payload, nil
}

// Direction indicates data flow for AEAD nonce derivation.
type Direction string

const (
	DirClientToServer Direction = "C2S\x00"
	DirServerToClient Direction = "S2C\x00"
)

// AEADStream manages framed ChaCha20-Poly1305 encryption/decryption.
type AEADStream struct {
	aead      cipher.AEAD
	direction Direction
	seq       atomic.Uint64
}

// NewAEADStream creates an AEAD stream handler for a specific direction key.
func NewAEADStream(key [32]byte, dir Direction) (*AEADStream, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return &AEADStream{
		aead:      aead,
		direction: dir,
	}, nil
}

// EncryptChunk encrypts plaintext and prepends a 2-byte wire length header.
func (s *AEADStream) EncryptChunk(dst []byte, plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxChunkPayloadLen {
		return nil, ErrChunkTooLarge
	}
	seq := s.seq.Add(1) - 1
	var nonce [12]byte
	copy(nonce[0:4], string(s.direction))
	binary.BigEndian.PutUint64(nonce[4:12], seq)

	wireLen := len(plaintext) + s.aead.Overhead()
	dst = binary.BigEndian.AppendUint16(dst, uint16(wireLen))
	dst = s.aead.Seal(dst, nonce[:], plaintext, nil)
	return dst, nil
}

// DecryptChunk decrypts an incoming wire chunk (excluding the 2-byte length header).
func (s *AEADStream) DecryptChunk(dst []byte, ciphertextWithTag []byte) ([]byte, error) {
	if len(ciphertextWithTag) > MaxChunkWireLen {
		return nil, ErrChunkTooLarge
	}
	seq := s.seq.Add(1) - 1
	var nonce [12]byte
	copy(nonce[0:4], string(s.direction))
	binary.BigEndian.PutUint64(nonce[4:12], seq)

	plaintext, err := s.aead.Open(dst, nonce[:], ciphertextWithTag, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}
