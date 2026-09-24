package plainudp

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
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

type Direction byte

const (
	DirClientToServer Direction = 0x01
	DirServerToClient Direction = 0x02
)

const (
	// Header: Nonce (24B random)
	HeaderSize       = 24
	MaxPacketSize    = 64 << 10 // 64KB max datagram buffer
	MaxTimestampSkew = 30 * time.Second

	SaltUDP = "MYXRAY-PLAIN-UDP-SALT-V2"
	InfoUDP = "MYXRAY-PLAIN-UDP-KEY-V2"
)

var (
	ErrPacketTooShort     = errors.New("plainudp: packet too short")
	ErrTimestampExpired   = errors.New("plainudp: timestamp out of acceptable window")
	ErrReplayDetected     = errors.New("plainudp: duplicate or replayed datagram")
	ErrDecryptionFailed   = errors.New("plainudp: AEAD packet decryption failed")
	ErrInvalidAddressType = errors.New("plainudp: unsupported SOCKS5 address type")
	ErrInvalidAddress     = errors.New("plainudp: malformed address in packet")
	ErrInvalidDirection   = errors.New("plainudp: invalid or unexpected direction")
)

var packetPool = sync.Pool{
	New: func() any {
		b := make([]byte, MaxPacketSize)
		return &b
	},
}

// DeriveDirectionalKeys derives independent 32-byte keys for Client-to-Server and Server-to-Client.
func DeriveDirectionalKeys(psk []byte) (c2sKey, s2cKey [32]byte) {
	extractor := hmac.New(sha256.New, []byte(SaltUDP))
	extractor.Write(psk)
	prk := extractor.Sum(nil)

	h1 := hmac.New(sha256.New, prk)
	h1.Write([]byte(InfoUDP))
	h1.Write([]byte("C2S"))
	copy(c2sKey[:], h1.Sum(nil))

	h2 := hmac.New(sha256.New, prk)
	h2.Write([]byte(InfoUDP))
	h2.Write([]byte("S2C"))
	copy(s2cKey[:], h2.Sum(nil))

	return c2sKey, s2cKey
}

// Codec provides bidirectional XChaCha20-Poly1305 AEAD encryption and decryption.
type Codec struct {
	c2sAEAD   cipher.AEAD
	s2cAEAD   cipher.AEAD
	sequence  atomic.Uint64
}

// NewCodec creates a persistent Codec instance holding initialized C2S and S2C AEAD ciphers.
func NewCodec(psk []byte) (*Codec, error) {
	c2sKey, s2cKey := DeriveDirectionalKeys(psk)
	c2sAEAD, err := chacha20poly1305.NewX(c2sKey[:])
	if err != nil {
		return nil, err
	}
	s2cAEAD, err := chacha20poly1305.NewX(s2cKey[:])
	if err != nil {
		return nil, err
	}
	return &Codec{
		c2sAEAD:  c2sAEAD,
		s2cAEAD:  s2cAEAD,
	}, nil
}

// EncodePacket encrypts sessionID, target address and payload into a plain-udp datagram.
// Wire format: [24B Random Nonce] [AEAD Ciphertext + 16B Poly1305 Tag]
// Plaintext structure: [8B Timestamp] [8B Monotonic Sequence] [8B SessionID] [TargetAddress] [Payload]
func (c *Codec) EncodePacket(dst []byte, dir Direction, sessionID uint64, targetAddr string, payload []byte, now time.Time) ([]byte, error) {
	bufPtr := packetPool.Get().(*[]byte)
	defer packetPool.Put(bufPtr)

	seq := c.sequence.Add(1)
	ts := uint64(now.Unix())

	plaintext := (*bufPtr)[:0]
	var hdrBuf [24]byte
	binary.BigEndian.PutUint64(hdrBuf[0:8], ts)
	binary.BigEndian.PutUint64(hdrBuf[8:16], seq)
	binary.BigEndian.PutUint64(hdrBuf[16:24], sessionID)
	plaintext = append(plaintext, hdrBuf[:]...)

	var err error
	plaintext, err = appendTargetAddress(plaintext, targetAddr)
	if err != nil {
		return nil, err
	}
	plaintext = append(plaintext, payload...)

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("plainudp: random nonce failed: %w", err)
	}

	ad := [1]byte{byte(dir)}

	var aead cipher.AEAD
	if dir == DirClientToServer {
		aead = c.c2sAEAD
	} else if dir == DirServerToClient {
		aead = c.s2cAEAD
	} else {
		return nil, ErrInvalidDirection
	}

	if dst == nil {
		dst = make([]byte, 0, HeaderSize+len(plaintext)+aead.Overhead())
	}
	dst = append(dst, nonce[:]...)
	dst = aead.Seal(dst, nonce[:], plaintext, ad[:])

	return dst, nil
}

// DecodePacket decrypts a plain-udp datagram, authenticates via AEAD, and extracts sessionID, target address and payload.
func (c *Codec) DecodePacket(packet []byte, expectedDir Direction, now time.Time) (sessionID uint64, targetAddr string, payload []byte, timestamp uint64, seq uint64, err error) {
	// Minimum length: 24B Nonce + (24B hdr + 1B type + 4B ipv4 + 2B port + 16B tag) = 71 bytes
	if len(packet) < HeaderSize+24+1+4+2+16 {
		return 0, "", nil, 0, 0, ErrPacketTooShort
	}

	nonce := packet[:HeaderSize]
	ciphertextWithTag := packet[HeaderSize:]

	ad := [1]byte{byte(expectedDir)}

	var aead cipher.AEAD
	if expectedDir == DirClientToServer {
		aead = c.c2sAEAD
	} else if expectedDir == DirServerToClient {
		aead = c.s2cAEAD
	} else {
		return 0, "", nil, 0, 0, ErrInvalidDirection
	}

	bufPtr := packetPool.Get().(*[]byte)
	defer packetPool.Put(bufPtr)

	plaintext, err := aead.Open((*bufPtr)[:0], nonce, ciphertextWithTag, ad[:])
	if err != nil {
		return 0, "", nil, 0, 0, ErrDecryptionFailed
	}

	if len(plaintext) < 24 {
		return 0, "", nil, 0, 0, ErrPacketTooShort
	}

	timestamp = binary.BigEndian.Uint64(plaintext[0:8])
	nowSec := uint64(now.Unix())
	diff := int64(nowSec) - int64(timestamp)
	if diff < -int64(MaxTimestampSkew/time.Second) || diff > int64(MaxTimestampSkew/time.Second) {
		return 0, "", nil, timestamp, 0, ErrTimestampExpired
	}

	seq = binary.BigEndian.Uint64(plaintext[8:16])
	sessionID = binary.BigEndian.Uint64(plaintext[16:24])

	targetAddr, rawPayload, err := decodeTargetAddress(plaintext[24:])
	if err != nil {
		return sessionID, "", nil, timestamp, seq, err
	}

	// Make an owned copy of payload since bufPtr will be returned to pool
	payloadCopy := make([]byte, len(rawPayload))
	copy(payloadCopy, rawPayload)

	return sessionID, targetAddr, payloadCopy, timestamp, seq, nil
}

// DecodePacketMulti tries decrypting the packet across multiple Codecs.
// Returns the index of the codec in codecs that successfully decrypted the packet,
// along with the decoded packet fields.
func DecodePacketMulti(codecs []*Codec, packet []byte, expectedDir Direction, now time.Time) (matchedIndex int, sessionID uint64, targetAddr string, payload []byte, timestamp uint64, seq uint64, err error) {
	for i, codec := range codecs {
		if codec == nil {
			continue
		}
		sID, tAddr, pLoad, ts, sNum, err := codec.DecodePacket(packet, expectedDir, now)
		if err == nil {
			return i, sID, tAddr, pLoad, ts, sNum, nil
		}
	}
	return -1, 0, "", nil, 0, 0, ErrDecryptionFailed
}


func appendTargetAddress(buf []byte, address string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", address, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid port %q", portText)
	}

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
			return nil, fmt.Errorf("invalid domain host length: %d", len(host))
		}
		buf = append(buf, 0x03, byte(len(host)))
		buf = append(buf, host...)
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(port))
	return buf, nil
}

func decodeTargetAddress(data []byte) (targetAddress string, payload []byte, err error) {
	if len(data) < 7 {
		return "", nil, ErrInvalidAddress
	}

	offset := 0
	var host string
	addrType := data[offset]
	offset++

	switch addrType {
	case 0x01: // IPv4
		if len(data) < offset+4+2 {
			return "", nil, ErrInvalidAddress
		}
		host = net.IP(data[offset : offset+4]).String()
		offset += 4
	case 0x03: // Domain
		if len(data) < offset+1 {
			return "", nil, ErrInvalidAddress
		}
		domainLen := int(data[offset])
		offset++
		if len(data) < offset+domainLen+2 {
			return "", nil, ErrInvalidAddress
		}
		host = string(data[offset : offset+domainLen])
		offset += domainLen
	case 0x04: // IPv6
		if len(data) < offset+16+2 {
			return "", nil, ErrInvalidAddress
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
