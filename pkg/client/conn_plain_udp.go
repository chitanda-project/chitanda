package client

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/violetaini/chitanda/internal/frame"
	"github.com/violetaini/chitanda/internal/plainudp"
)

var udpReadPool = sync.Pool{
	New: func() any {
		b := make([]byte, 64<<10)
		return &b
	},
}

type plainUDPConn struct {
	sessionID  uint64
	conn       net.PacketConn
	serverAddr *net.UDPAddr
	codec      *plainudp.Codec
	closed     atomic.Bool
	replayMu   sync.Mutex
	replay     frame.ReplayWindow
}

func newPlainUDPConn(
	ctx context.Context,
	server string,
	psk []byte,
	listenPacket func(ctx context.Context, network, addr string) (net.PacketConn, error),
	resolveUDPFn func(ctx context.Context, network, addr string) (*net.UDPAddr, error),
	dialPackets ...func(context.Context, *net.UDPAddr) (net.PacketConn, error),
) (*plainUDPConn, error) {
	srvAddr, err := resolveUDP(ctx, server, resolveUDPFn)
	if err != nil {
		return nil, fmt.Errorf("resolve server udp addr %q: %w", server, err)
	}

	var conn net.PacketConn
	if len(dialPackets) > 0 && dialPackets[0] != nil {
		conn, err = dialPackets[0](ctx, srvAddr)
		if err != nil {
			return nil, err
		}
	} else if listenPacket != nil {
		pconn, err := listenPacket(ctx, "udp", ":0")
		if err != nil {
			return nil, fmt.Errorf("listen custom packet: %w", err)
		}
		conn = pconn
	} else {
		c, err := net.ListenUDP("udp", nil)
		if err != nil {
			return nil, fmt.Errorf("listen local udp: %w", err)
		}
		conn = c
	}
	if uc, ok := conn.(interface{ SetReadBuffer(int) error }); ok {
		_ = uc.SetReadBuffer(8 << 20)
	}
	if uc, ok := conn.(interface{ SetWriteBuffer(int) error }); ok {
		_ = uc.SetWriteBuffer(8 << 20)
	}

	codec, err := plainudp.NewCodec(psk)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	var sessionBytes [8]byte
	if _, err := io.ReadFull(rand.Reader, sessionBytes[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("generate session ID: %w", err)
	}
	sessionID := binary.BigEndian.Uint64(sessionBytes[:])

	return &plainUDPConn{
		sessionID:  sessionID,
		conn:       conn,
		serverAddr: srvAddr,
		codec:      codec,
	}, nil
}

func (c *plainUDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.closed.Load() {
		return 0, nil, errors.New("conn closed")
	}

	bufPtr := udpReadPool.Get().(*[]byte)
	defer udpReadPool.Put(bufPtr)

	for {
		readN, remoteAddr, err := c.conn.ReadFrom(*bufPtr)
		if err != nil {
			return 0, nil, err
		}

		// Strict origin check: drop any datagram not originating from configured proxy server
		if ua, ok := remoteAddr.(*net.UDPAddr); ok {
			if !ua.IP.Equal(c.serverAddr.IP) || ua.Port != c.serverAddr.Port {
				continue
			}
		}

		sessionID, targetAddrStr, payload, _, seq, err := c.codec.DecodePacket((*bufPtr)[:readN], plainudp.DirServerToClient, time.Now())
		if err != nil {
			continue // Drop corrupt, unauthenticated, replayed, reflected, or expired datagrams
		}
		if sessionID != c.sessionID {
			continue // Drop mismatched session datagrams
		}

		c.replayMu.Lock()
		accepted := c.replay.Accept(seq)
		c.replayMu.Unlock()
		if !accepted {
			continue // Drop replayed responses
		}

		rAddr := parseUDPAddr(targetAddrStr)
		copied := copy(p, payload)
		return copied, rAddr, nil
	}
}

func (c *plainUDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.closed.Load() {
		return 0, errors.New("conn closed")
	}

	address := formatDatagramAddress(addr)
	packet, err := c.codec.EncodePacket(nil, plainudp.DirClientToServer, c.sessionID, address, p, time.Now())
	if err != nil {
		return 0, err
	}

	if _, err := c.conn.WriteTo(packet, c.serverAddr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *plainUDPConn) Close() error {
	c.closed.Store(true)
	return c.conn.Close()
}

func (c *plainUDPConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *plainUDPConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *plainUDPConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *plainUDPConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
