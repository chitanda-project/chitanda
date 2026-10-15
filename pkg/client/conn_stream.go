package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/violetaini/chitanda/internal/rawstream"
)

func (c *Client) dialRawStream(ctx context.Context, target string) (net.Conn, error) {
	rawConn, err := c.dialRaw(ctx, "tcp", c.cfg.Server)
	if err != nil {
		return nil, fmt.Errorf("rawstream dial server %q: %w", c.cfg.Server, err)
	}
	if tc, ok := rawConn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(15 * time.Second)
	} else if kac, ok := rawConn.(interface {
		SetKeepAlive(bool) error
		SetKeepAlivePeriod(time.Duration) error
	}); ok {
		_ = kac.SetKeepAlive(true)
		_ = kac.SetKeepAlivePeriod(15 * time.Second)
	}

	// 1. Map context deadline to connection deadline to prevent indefinite hanging
	if deadline, ok := rawHandshakeDeadline(ctx); ok {
		_ = rawConn.SetDeadline(deadline)
	} else {
		_ = rawConn.SetDeadline(time.Now().Add(10 * time.Second))
	}

	// 2. Hook context cancellation to immediately close rawConn if caller aborts
	stopCancel := context.AfterFunc(ctx, func() {
		_ = rawConn.Close()
	})
	defer stopCancel()

	now := time.Now()
	clientHello, clientNonce, ts, err := rawstream.CreatePolymorphicClientHello(c.cfg.PSK, c.cfg.ServerID, now)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("create polymorphic client hello: %w", err)
	}

	// Derive 0-RTT key with serverID binding
	k0RTT, err := rawstream.Derive0RTTKey(c.cfg.PSK, c.cfg.ServerID, ts, clientNonce)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("derive 0-rtt key: %w", err)
	}

	// Encode open frame with dynamic padding (32 to 256 bytes)
	openFramePlaintext, err := rawstream.Encode0RTTOpenFrame(target, nil, rawstream.DefaultMinPadding, rawstream.DefaultMaxPadding)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("encode 0-rtt open frame: %w", err)
	}

	encrypted0RTT, err := rawstream.Encrypt0RTTChunk(k0RTT, openFramePlaintext)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("encrypt 0-rtt chunk: %w", err)
	}

	// Assemble Flight 1 single TCP write burst:
	// [Polymorphic ClientHello (49-113B)] [2B 0-RTT Wire Length] [Encrypted 0-RTT Chunk]
	wireLen := len(encrypted0RTT)
	flight1 := make([]byte, 0, len(clientHello)+2+wireLen)
	flight1 = append(flight1, clientHello...)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(wireLen))
	flight1 = append(flight1, lenBuf[:]...)
	flight1 = append(flight1, encrypted0RTT...)

	if _, err := rawConn.Write(flight1); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("write flight 1: %w", err)
	}

	// Read and verify polymorphic ServerHello (41-105 bytes)
	serverNonce, err := rawstream.ReadAndVerifyPolymorphicServerHello(rawConn, c.cfg.PSK, c.cfg.ServerID, ts, clientNonce)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("verify server hello: %w", err)
	}

	// Derive bidirectional session keys with serverID binding
	c2sKey, s2cKey, err := rawstream.DeriveSessionKeys(c.cfg.PSK, c.cfg.ServerID, ts, clientNonce, serverNonce)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("derive session keys: %w", err)
	}

	wStream, err := rawstream.NewAEADStream(c2sKey)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	rStream, err := rawstream.NewAEADStream(s2cKey)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	// Clear handshake deadline for established full-duplex session
	_ = rawConn.SetDeadline(time.Time{})

	return rawstream.NewStreamConn(rawConn, rStream, wStream), nil
}
