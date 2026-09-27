package sing_tun

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/log"
	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
	"github.com/violetaini/chitanda/pkg/client"
)

type chitandaICMPOpener interface {
	OpenChitandaICMP(context.Context, netip.Addr, netip.Addr) (net.PacketConn, bool, error)
}

func (h *ListenerHandler) prepareChitandaICMP(source, destination netip.Addr, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, bool, error) {
	opener, ok := h.Tunnel.(chitandaICMPOpener)
	if !ok {
		return nil, false, nil
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, useProxy, err := opener.OpenChitandaICMP(ctx, source, destination)
	if err != nil {
		return nil, true, err
	}
	if !useProxy {
		return nil, false, nil
	}
	d := &chitandaICMPDestination{conn: conn, source: source, target: destination, routeContext: routeContext, timeout: timeout}
	go d.readReplies()
	log.Debugln("[ICMP] %s --> %s using Chitanda", source, destination)
	return d, true, nil
}

var _ tun.DirectRouteDestination = (*chitandaICMPDestination)(nil)

type chitandaICMPDestination struct {
	conn         net.PacketConn
	source       netip.Addr
	target       netip.Addr
	routeContext tun.DirectRouteContext
	timeout      time.Duration
	closed       atomic.Bool
}

func (d *chitandaICMPDestination) WritePacket(packet *buf.Buffer) error {
	if d.closed.Load() {
		return net.ErrClosed
	}
	data := packet.Bytes()
	var body []byte
	if d.target.Is4() {
		if len(data) < 28 || data[0]>>4 != 4 || data[9] != 1 {
			return errors.New("invalid IPv4 ICMP packet")
		}
		ihl := int(data[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(data[2:4]))
		if ihl < 20 || total < ihl+8 || total > len(data) {
			return errors.New("invalid IPv4 ICMP length")
		}
		if !net.IP(data[12:16]).Equal(d.source.AsSlice()) || !net.IP(data[16:20]).Equal(d.target.AsSlice()) {
			return errors.New("ICMP source or destination changed")
		}
		body = data[ihl:total]
	} else {
		if len(data) < 48 || data[0]>>4 != 6 || data[6] != 58 {
			return errors.New("invalid IPv6 ICMP packet")
		}
		total := 40 + int(binary.BigEndian.Uint16(data[4:6]))
		if total < 48 || total > len(data) || !net.IP(data[8:24]).Equal(d.source.AsSlice()) || !net.IP(data[24:40]).Equal(d.target.AsSlice()) {
			return errors.New("invalid IPv6 ICMP length or address")
		}
		body = data[40:total]
	}
	if err := client.ValidateICMPEchoRequest(body, d.target.Is6()); err != nil {
		return err
	}
	_, err := d.conn.WriteTo(body, &net.UDPAddr{IP: d.target.AsSlice(), Port: 0})
	return err
}

func (d *chitandaICMPDestination) readReplies() {
	defer d.Close()
	buffer := make([]byte, 64<<10)
	for !d.closed.Load() {
		deadline := d.timeout
		if deadline <= 0 {
			deadline = 10 * time.Second
		}
		_ = d.conn.SetReadDeadline(time.Now().Add(deadline))
		n, from, err := d.conn.ReadFrom(buffer)
		if err != nil {
			return
		}
		remote, ok := from.(*net.UDPAddr)
		if !ok || remote.Port != 0 || !remote.IP.Equal(d.target.AsSlice()) {
			continue
		}
		packet, err := d.buildReply(buffer[:n])
		if err != nil {
			continue
		}
		if err := d.routeContext.WritePacket(packet); err != nil {
			return
		}
	}
}

func (d *chitandaICMPDestination) buildReply(body []byte) ([]byte, error) {
	if len(body) < 8 {
		return nil, errors.New("short ICMP reply")
	}
	want := byte(0)
	if d.target.Is6() {
		want = 129
	}
	if body[0] != want || body[1] != 0 {
		return nil, errors.New("not an ICMP Echo Reply")
	}
	if d.target.Is4() {
		if len(body)+20 > 65535 {
			return nil, errors.New("ICMP reply too large")
		}
		packet := make([]byte, 20+len(body))
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		packet[8], packet[9] = 64, 1
		copy(packet[12:16], d.target.AsSlice())
		copy(packet[16:20], d.source.AsSlice())
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
		copy(packet[20:], body)
		return packet, nil
	}
	if len(body) > 65535 {
		return nil, errors.New("ICMPv6 reply too large")
	}
	packet := make([]byte, 40+len(body))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(body)))
	packet[6], packet[7] = 58, 64
	copy(packet[8:24], d.target.AsSlice())
	copy(packet[24:40], d.source.AsSlice())
	copy(packet[40:], body)
	packet[42], packet[43] = 0, 0
	pseudo := make([]byte, 40+len(body))
	copy(pseudo[0:16], d.target.AsSlice())
	copy(pseudo[16:32], d.source.AsSlice())
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(body)))
	pseudo[39] = 58
	copy(pseudo[40:], packet[40:])
	binary.BigEndian.PutUint16(packet[42:44], checksum(pseudo))
	return packet, nil
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (d *chitandaICMPDestination) Close() error {
	if d.closed.CompareAndSwap(false, true) {
		return d.conn.Close()
	}
	return nil
}

func (d *chitandaICMPDestination) IsClosed() bool { return d.closed.Load() }
