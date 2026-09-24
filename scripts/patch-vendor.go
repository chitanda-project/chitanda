package main

import (
	"fmt"
	"os"
	"strings"
)

type replacement struct {
	path string
	old  string
	new  string
}

func main() {
	replacements := []replacement{
		{
			path: "vendor/github.com/quic-go/quic-go/connection.go",
			old: `func (c *Conn) SendDatagram(p []byte) error {
	if !c.supportsDatagrams() {
		return errors.New("datagram support disabled")
	}

	f := &wire.DatagramFrame{DataLenPresent: true}
	// The payload size estimate is conservative.
	// Under many circumstances we could send a few more bytes.
	maxDataLen := min(
		f.MaxDataLen(c.peerParams.MaxDatagramFrameSize, c.version),
		protocol.ByteCount(c.maxPayloadSizeEstimate.Load()),
	)
	if protocol.ByteCount(len(p)) > maxDataLen {
		return &DatagramTooLargeError{MaxDatagramPayloadSize: int64(maxDataLen)}
	}
	f.Data = make([]byte, len(p))
	copy(f.Data, p)
	return c.datagramQueue.Add(f)
}`,
			new: `func (c *Conn) SendDatagram(p []byte) error {
	return c.sendDatagram(p, true)
}

// SendDatagramNoCopy transfers ownership of p to the connection. The caller
// must not access p after this method returns.
func (c *Conn) SendDatagramNoCopy(p []byte) error {
	return c.sendDatagram(p, false)
}

func (c *Conn) sendDatagram(p []byte, copyPayload bool) error {
	if !c.supportsDatagrams() {
		return errors.New("datagram support disabled")
	}

	f := &wire.DatagramFrame{DataLenPresent: true}
	// The payload size estimate is conservative.
	// Under many circumstances we could send a few more bytes.
	maxDataLen := min(
		f.MaxDataLen(c.peerParams.MaxDatagramFrameSize, c.version),
		protocol.ByteCount(c.maxPayloadSizeEstimate.Load()),
	)
	if protocol.ByteCount(len(p)) > maxDataLen {
		return &DatagramTooLargeError{MaxDatagramPayloadSize: int64(maxDataLen)}
	}
	if copyPayload {
		p = bytes.Clone(p)
	}
	f.Data = p
	return c.datagramQueue.Add(f)
}`,
		},
		{
			path: "vendor/github.com/quic-go/quic-go/http3/conn.go",
			old:  "return c.conn.SendDatagram(data)",
			new:  "return c.conn.SendDatagramNoCopy(data)",
		},
		{
			path: "vendor/github.com/quic-go/quic-go/internal/wire/datagram_frame.go",
			old:  "f.Data = make([]byte, length)\n\tcopy(f.Data, b)",
			new:  "// The connection copies the payload into its receive queue before the\n\t// packet buffer is released, so retaining this view here is safe.\n\tf.Data = b[:length]",
		},
		{
			path: "vendor/golang.org/x/net/http2/transport_common.go",
			old:  "\tCountError func(errType string)\n\n\t// Internal state, differs between wrapped and non-wrapped implementations.",
			new:  "\tCountError func(errType string)\n\n\t// MaxDataPadding, if positive, enables pseudo-random padding on HTTP/2 DATA frames (RFC 7540).\n\t// Bounded in range [0, 255].\n\tMaxDataPadding int\n\n\t// Internal state, differs between wrapped and non-wrapped implementations.",
		},
		{
			path: "vendor/golang.org/x/net/http2/transport.go",
			old: `			allowed, err = cs.awaitFlowControl(len(remain))
			if err != nil {
				return err
			}
			cc.wmu.Lock()
			data := remain[:allowed]
			remain = remain[allowed:]
			sentEnd = sawEOF && len(remain) == 0 && !hasTrailers
			err = cc.fr.WriteData(cs.ID, sentEnd, data)`,
			new: `			targetPad := 0
			if cc.t.MaxDataPadding > 0 {
				maxPad := cc.t.MaxDataPadding
				if maxPad > 255 {
					maxPad = 255
				}
				minPad := 8
				if minPad > maxPad {
					minPad = maxPad
				}
				targetPad = minPad + int(time.Now().UnixNano()%(int64(maxPad-minPad+1)))
			}
			reqBytes := len(remain)
			if targetPad > 0 {
				reqBytes += targetPad + 1
			}
			allowed, err = cs.awaitFlowControl(reqBytes)
			if err != nil {
				return err
			}
			cc.wmu.Lock()
			var data, pad []byte
			if targetPad > 0 && allowed > int32(len(remain)+1) {
				data = remain
				remain = nil
				actualPad := int(allowed) - len(data) - 1
				if actualPad > 255 {
					actualPad = 255
				}
				if actualPad > 0 {
					pad = make([]byte, actualPad)
				}
			} else {
				takeData := min(int(allowed), len(remain))
				data = remain[:takeData]
				remain = remain[takeData:]
			}
			sentEnd = sawEOF && len(remain) == 0 && !hasTrailers
			if len(pad) > 0 {
				err = cc.fr.WriteDataPadded(cs.ID, sentEnd, data, pad)
			} else {
				err = cc.fr.WriteData(cs.ID, sentEnd, data)
			}`,
		},
	}

	for _, replacement := range replacements {
		if len(os.Args) > 1 {
			switch os.Args[1] {
			case "--quic-only":
				if !strings.HasPrefix(replacement.path, "vendor/github.com/quic-go/quic-go/") {
					continue
				}
			case "--xnet-only":
				if !strings.HasPrefix(replacement.path, "vendor/golang.org/x/net/") {
					continue
				}
			default:
				fmt.Fprintln(os.Stderr, "usage: patch-vendor.go [--quic-only|--xnet-only]")
				os.Exit(2)
			}
		}
		if err := replaceExactlyOnce(replacement); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

func replaceExactlyOnce(replacement replacement) error {
	contents, err := os.ReadFile(replacement.path)
	if err != nil {
		return err
	}
	if strings.Count(string(contents), replacement.old) != 1 {
		return fmt.Errorf("vendor patch context changed in %s", replacement.path)
	}
	updated := strings.Replace(string(contents), replacement.old, replacement.new, 1)
	return os.WriteFile(replacement.path, []byte(updated), 0o644)
}
