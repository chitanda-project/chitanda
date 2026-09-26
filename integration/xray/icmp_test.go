package chitanda

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/server"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestXrayOutbound_ICMPAddrDownlink(t *testing.T) {
	p := newReviewPC()
	defer p.Close()
	c := reviewClient(t, p)

	r, w := pipe.New()
	defer r.Interrupt()
	defer w.Close()

	writer := &reviewWriter{make(chan buf.MultiBuffer, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dest := xnet.UDPDestination(xnet.ParseAddress("8.8.8.8"), 0)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: dest}})

	h := &OutboundHandler{client: c}
	done := make(chan error, 1)
	go func() {
		done <- h.Process(ctx, &transport.Link{Reader: r, Writer: writer}, nil)
	}()

	// Send an initial uplink packet to establish session
	_ = w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("ping-request"))})
	wire := recvReview(t, p.out)

	codec, err := server.NewPlainUDPCodec(reviewKey)
	if err != nil {
		t.Fatal(err)
	}

	sid, _, _, _, _, err := codec.DecodeClientPacket(wire, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Send simulated ICMP echo reply from server with target "icmp:8.8.8.8"
	replyPayload := []byte("ping-reply-data")
	replyPacket, err := codec.EncodeServerPacket(sid, "icmp:8.8.8.8", replyPayload, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	p.in <- replyPacket

	mb := recvReview(t, writer.writes)
	if len(mb) != 1 {
		t.Fatalf("expected 1 buffer, got %d", len(mb))
	}
	defer buf.ReleaseMulti(mb)

	b := mb[0]
	if !bytes.Equal(b.Bytes(), replyPayload) {
		t.Errorf("payload mismatch: got %q, want %q", b.Bytes(), replyPayload)
	}
	if b.UDP == nil {
		t.Fatal("expected b.UDP to be populated for ICMP datagram")
	}
	if b.UDP.Address.IP().String() != "8.8.8.8" {
		t.Errorf("expected destination IP 8.8.8.8, got %s", b.UDP.Address.IP().String())
	}
	if b.UDP.Port.Value() != 0 {
		t.Errorf("expected destination Port 0 for ICMP, got %d", b.UDP.Port.Value())
	}

	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Error("Process did not exit after cancellation")
	}
}

func TestXrayInbound_DialICMPRegistration(t *testing.T) {
	config := &InboundConfig{
		Psk:       string(reviewKey),
		Transport: "stream",
	}
	ctx := newTestContextWithDispatcher(t, nil)
	h, err := NewInboundHandler(ctx, config)
	if err != nil {
		t.Fatalf("NewInboundHandler failed: %v", err)
	}
	defer h.Close()

	if h.server == nil {
		t.Fatal("expected h.server to be initialized")
	}
}
