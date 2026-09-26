package icmpmsg

import (
	"encoding/binary"
	"errors"
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
