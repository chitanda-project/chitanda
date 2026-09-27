package icmpmsg

import (
	"bytes"
	"encoding/binary"
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

func TestEchoTrackerIsolatesAssociationsAndRestoresIDs(t *testing.T) {
	request := BuildEchoRequest(0x1234, 7, []byte("isolated"), false)
	var first, second EchoTracker
	wire1, err := first.PrepareRequest(request, false)
	if err != nil {
		t.Fatal(err)
	}
	wire2, err := second.PrepareRequest(request, false)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(wire1[4:8], wire2[4:8]) {
		t.Fatal("associations reused the same wire token")
	}
	if Checksum(wire1) != 0 {
		t.Fatal("rewritten IPv4 checksum is invalid")
	}
	wireToken := binary.BigEndian.Uint32(wire1[4:8])
	reply := BuildEchoReply(uint16(wireToken>>16), uint16(wireToken), []byte("isolated"), false)
	if _, ok := second.RestoreReply(reply, false); ok {
		t.Fatal("reply leaked to another association")
	}
	restored, ok := first.RestoreReply(reply, false)
	if !ok || !bytes.Equal(restored[4:8], request[4:8]) || Checksum(restored) != 0 {
		t.Fatal("original echo ID/sequence was not restored")
	}
	if _, ok := first.RestoreReply(reply, false); ok {
		t.Fatal("replayed reply was accepted")
	}
}

func TestEchoTrackerRejectsNonEchoAndStripsIPv4Header(t *testing.T) {
	var tracker EchoTracker
	if _, err := tracker.PrepareRequest(BuildEchoReply(1, 1, nil, false), false); err == nil {
		t.Fatal("non-Echo-Request was accepted")
	}
	request := BuildEchoRequest(1, 2, nil, false)
	wire, err := tracker.PrepareRequest(request, false)
	if err != nil {
		t.Fatal(err)
	}
	token := binary.BigEndian.Uint32(wire[4:8])
	reply := BuildEchoReply(uint16(token>>16), uint16(token), nil, false)
	ipv4 := make([]byte, 20+len(reply))
	ipv4[0] = 0x45
	ipv4[9] = 1
	copy(ipv4[20:], reply)
	if _, ok := tracker.RestoreReply(ipv4, false); !ok {
		t.Fatal("raw IPv4 reply header was not removed")
	}
}

func TestEchoTrackerPreservesIPv6Checksum(t *testing.T) {
	source := net.ParseIP("2001:4860::10").To16()
	target := net.ParseIP("2606:4700:4700::1111").To16()
	withChecksum := func(packet []byte, from, to net.IP) []byte {
		packet = append([]byte(nil), packet...)
		pseudo := make([]byte, 40+len(packet))
		copy(pseudo[:16], from)
		copy(pseudo[16:32], to)
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(packet)))
		pseudo[39] = 58
		copy(pseudo[40:], packet)
		binary.BigEndian.PutUint16(packet[2:4], Checksum(pseudo))
		return packet
	}
	valid := func(packet []byte, from, to net.IP) bool {
		pseudo := make([]byte, 40+len(packet))
		copy(pseudo[:16], from)
		copy(pseudo[16:32], to)
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(packet)))
		pseudo[39] = 58
		copy(pseudo[40:], packet)
		return Checksum(pseudo) == 0
	}
	var tracker EchoTracker
	request := withChecksum(BuildEchoRequest(0x1234, 0x5678, []byte("ipv6-checksum"), true), source, target)
	wire, err := tracker.PrepareRequest(request, true)
	if err != nil || !valid(wire, source, target) {
		t.Fatalf("wire request checksum invalid: %v", err)
	}
	token := binary.BigEndian.Uint32(wire[4:8])
	reply := withChecksum(BuildEchoReply(uint16(token>>16), uint16(token), []byte("ipv6-checksum"), true), target, source)
	restored, ok := tracker.RestoreReply(reply, true)
	if !ok || !valid(restored, target, source) || binary.BigEndian.Uint32(restored[4:8]) != 0x12345678 {
		t.Fatal("restored IPv6 reply checksum or ID/sequence invalid")
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
