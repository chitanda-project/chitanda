package icmpmsg

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

const (
	IPv4EchoRequest = 8
	IPv4EchoReply   = 0
	IPv6EchoRequest = 128
	IPv6EchoReply   = 129
)

type EchoMessage struct {
	Type     byte
	Code     byte
	Checksum uint16
	ID       uint16
	Seq      uint16
	Data     []byte
}

// BuildEchoRequest builds an ICMP Echo Request packet.
func BuildEchoRequest(id, seq uint16, data []byte, isIPv6 bool) []byte {
	msgType := byte(IPv4EchoRequest)
	if isIPv6 {
		msgType = byte(IPv6EchoRequest)
	}
	pkt := make([]byte, 8+len(data))
	pkt[0] = msgType
	pkt[1] = 0 // code
	binary.BigEndian.PutUint16(pkt[4:6], id)
	binary.BigEndian.PutUint16(pkt[6:8], seq)
	copy(pkt[8:], data)

	if !isIPv6 {
		cs := Checksum(pkt)
		binary.BigEndian.PutUint16(pkt[2:4], cs)
	}
	return pkt
}

// BuildEchoReply builds an ICMP Echo Reply packet.
func BuildEchoReply(id, seq uint16, data []byte, isIPv6 bool) []byte {
	msgType := byte(IPv4EchoReply)
	if isIPv6 {
		msgType = byte(IPv6EchoReply)
	}
	pkt := make([]byte, 8+len(data))
	pkt[0] = msgType
	pkt[1] = 0
	binary.BigEndian.PutUint16(pkt[4:6], id)
	binary.BigEndian.PutUint16(pkt[6:8], seq)
	copy(pkt[8:], data)
	if !isIPv6 {
		cs := Checksum(pkt)
		binary.BigEndian.PutUint16(pkt[2:4], cs)
	}
	return pkt
}

// ParseEcho parses an ICMP packet into an EchoMessage.
func ParseEcho(b []byte) (*EchoMessage, error) {
	if len(b) < 8 {
		return nil, errors.New("icmp packet too short")
	}
	return &EchoMessage{
		Type:     b[0],
		Code:     b[1],
		Checksum: binary.BigEndian.Uint16(b[2:4]),
		ID:       binary.BigEndian.Uint16(b[4:6]),
		Seq:      binary.BigEndian.Uint16(b[6:8]),
		Data:     b[8:],
	}, nil
}

// Checksum calculates the RFC 1071 16-bit one's complement checksum.
func Checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

var nextEchoToken atomic.Uint32

func init() {
	var seed [4]byte
	if _, err := rand.Read(seed[:]); err == nil {
		nextEchoToken.Store(binary.BigEndian.Uint32(seed[:]))
	}
}

type pendingEcho struct {
	original uint32
	created  time.Time
}

// EchoTracker maps requests on one association to replies received by a raw
// socket. Raw ICMP sockets can see replies to other associations, so each
// outstanding request gets a process-unique wire ID and sequence pair.
type EchoTracker struct {
	mu      sync.Mutex
	pending map[uint32]pendingEcho
}

func ValidateEchoRequest(packet []byte, ipv6 bool) error {
	if len(packet) < 8 {
		return errors.New("icmp echo request too short")
	}
	want := byte(IPv4EchoRequest)
	if ipv6 {
		want = IPv6EchoRequest
	}
	if packet[0] != want || packet[1] != 0 {
		return errors.New("only ICMP echo requests are allowed")
	}
	if !ipv6 && Checksum(packet) != 0 {
		return errors.New("invalid ICMPv4 checksum")
	}
	return nil
}

func adjustChecksum(checksum uint16, oldValue, newValue uint32) uint16 {
	sum := uint32(^checksum) + uint32(^(oldValue>>16)&0xffff) + uint32(^oldValue&0xffff)
	sum += newValue >> 16
	sum += newValue & 0xffff
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func rewriteToken(packet []byte, token uint32, ipv6 bool) []byte {
	result := append([]byte(nil), packet...)
	old := binary.BigEndian.Uint32(result[4:8])
	binary.BigEndian.PutUint32(result[4:8], token)
	if ipv6 {
		if checksum := binary.BigEndian.Uint16(result[2:4]); checksum != 0 {
			binary.BigEndian.PutUint16(result[2:4], adjustChecksum(checksum, old, token))
		}
	} else {
		binary.BigEndian.PutUint16(result[2:4], 0)
		binary.BigEndian.PutUint16(result[2:4], Checksum(result))
	}
	return result
}

func (t *EchoTracker) PrepareRequest(packet []byte, ipv6 bool) ([]byte, error) {
	if err := ValidateEchoRequest(packet, ipv6); err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pending == nil {
		t.pending = make(map[uint32]pendingEcho)
	}
	if len(t.pending) >= 2048 {
		for token, pending := range t.pending {
			if time.Since(pending.created) >= time.Minute {
				delete(t.pending, token)
			}
		}
		if len(t.pending) >= 2048 {
			return nil, errors.New("too many outstanding ICMP echo requests")
		}
	}
	token := nextEchoToken.Add(1)
	t.pending[token] = pendingEcho{original: binary.BigEndian.Uint32(packet[4:8]), created: time.Now()}
	return rewriteToken(packet, token, ipv6), nil
}

// StripIPHeader accepts the platform-specific raw socket formats: ICMPv4
// commonly includes its IPv4 header, while ICMPv6 commonly does not.
func StripIPHeader(packet []byte, ipv6 bool) ([]byte, error) {
	if len(packet) < 8 {
		return nil, errors.New("icmp reply too short")
	}
	if !ipv6 && packet[0]>>4 == 4 {
		if len(packet) < 28 {
			return nil, errors.New("short IPv4 ICMP reply")
		}
		ihl := int(packet[0]&0x0f) * 4
		if ihl < 20 || ihl+8 > len(packet) || packet[9] != 1 {
			return nil, errors.New("invalid IPv4 ICMP reply header")
		}
		return packet[ihl:], nil
	}
	if ipv6 && packet[0]>>4 == 6 {
		if len(packet) < 48 || packet[6] != 58 {
			return nil, errors.New("invalid IPv6 ICMP reply header")
		}
		return packet[40:], nil
	}
	return packet, nil
}

func (t *EchoTracker) RestoreReply(raw []byte, ipv6 bool) ([]byte, bool) {
	packet, err := StripIPHeader(raw, ipv6)
	if err != nil || len(packet) < 8 {
		return nil, false
	}
	want := byte(IPv4EchoReply)
	if ipv6 {
		want = IPv6EchoReply
	}
	if packet[0] != want || packet[1] != 0 {
		return nil, false
	}
	token := binary.BigEndian.Uint32(packet[4:8])
	t.mu.Lock()
	pending, ok := t.pending[token]
	if ok {
		delete(t.pending, token)
	}
	t.mu.Unlock()
	if !ok || time.Since(pending.created) >= time.Minute {
		return nil, false
	}
	return rewriteToken(packet, pending.original, ipv6), true
}
