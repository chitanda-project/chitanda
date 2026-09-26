package icmpmsg

import (
	"bytes"
	"net"
	"testing"
)

func TestBuildAndParseIPv4EchoRequest(t *testing.T) {
	id := uint16(0x1234)
	seq := uint16(0x0001)
	payload := []byte("hello icmp world")

	pkt := BuildEchoRequest(id, seq, payload, false)
	if len(pkt) != 8+len(payload) {
		t.Fatalf("expected packet length %d, got %d", 8+len(payload), len(pkt))
	}

	// Verify checksum of valid IPv4 packet is 0 when computed over entire packet
	if Checksum(pkt) != 0 {
		t.Fatalf("checksum failed: computed %04x, want 0000", Checksum(pkt))
	}

	msg, err := ParseEcho(pkt)
	if err != nil {
		t.Fatalf("ParseEcho failed: %v", err)
	}

	if msg.Type != IPv4EchoRequest {
		t.Errorf("expected type %d, got %d", IPv4EchoRequest, msg.Type)
	}
	if msg.Code != 0 {
		t.Errorf("expected code 0, got %d", msg.Code)
	}
	if msg.ID != id {
		t.Errorf("expected ID %04x, got %04x", id, msg.ID)
	}
	if msg.Seq != seq {
		t.Errorf("expected Seq %04x, got %04x", seq, msg.Seq)
	}
	if !bytes.Equal(msg.Data, payload) {
		t.Errorf("expected payload %q, got %q", payload, msg.Data)
	}
}

func TestBuildAndParseIPv4EchoReply(t *testing.T) {
	id := uint16(0xabcd)
	seq := uint16(0x0042)
	payload := []byte("ping reply payload")

	pkt := BuildEchoReply(id, seq, payload, false)
	if Checksum(pkt) != 0 {
		t.Fatalf("checksum failed: computed %04x, want 0000", Checksum(pkt))
	}

	msg, err := ParseEcho(pkt)
	if err != nil {
		t.Fatalf("ParseEcho failed: %v", err)
	}
	if msg.Type != IPv4EchoReply {
		t.Errorf("expected type %d, got %d", IPv4EchoReply, msg.Type)
	}
	if msg.ID != id || msg.Seq != seq {
		t.Errorf("ID/Seq mismatch: got %04x/%04x, want %04x/%04x", msg.ID, msg.Seq, id, seq)
	}
	if !bytes.Equal(msg.Data, payload) {
		t.Errorf("payload mismatch")
	}
}

func TestBuildAndParseIPv6Echo(t *testing.T) {
	id := uint16(0x5678)
	seq := uint16(0x0002)
	payload := []byte("ipv6 ping")

	req := BuildEchoRequest(id, seq, payload, true)
	msgReq, err := ParseEcho(req)
	if err != nil {
		t.Fatalf("ParseEcho ipv6 request failed: %v", err)
	}
	if msgReq.Type != IPv6EchoRequest {
		t.Errorf("expected type %d, got %d", IPv6EchoRequest, msgReq.Type)
	}

	rep := BuildEchoReply(id, seq, payload, true)
	msgRep, err := ParseEcho(rep)
	if err != nil {
		t.Fatalf("ParseEcho ipv6 reply failed: %v", err)
	}
	if msgRep.Type != IPv6EchoReply {
		t.Errorf("expected type %d, got %d", IPv6EchoReply, msgRep.Type)
	}
}

func TestParseEchoErrors(t *testing.T) {
	_, err := ParseEcho([]byte{1, 2, 3})
	if err == nil {
		t.Errorf("expected error for short packet, got nil")
	}
}

func TestChecksumOddBytes(t *testing.T) {
	data := []byte{1, 2, 3}
	cs := Checksum(data)
	if cs == 0 {
		t.Errorf("checksum of non-zero odd bytes should not be 0")
	}
}

func TestParseIPHelper(t *testing.T) {
	ip4 := net.ParseIP("1.1.1.1")
	if ip4.To4() == nil {
		t.Errorf("expected IPv4")
	}
	ip6 := net.ParseIP("2606:4700:4700::1111")
	if ip6.To4() != nil {
		t.Errorf("expected IPv6")
	}
}
