package chitanda

import (
	"github.com/xtls/xray-core/common/buf"
	"io"
	"net"
	"sync"
)

// packetAddress keeps domain destinations intact; resolution belongs to Xray's
// configured router/outbound, not the host's default DNS resolver.
type packetAddress string

func (packetAddress) Network() string  { return "udp" }
func (a packetAddress) String() string { return string(a) }

func ownedDatagram(p []byte) *buf.Buffer {
	b := buf.NewWithSize(int32(max(1, len(p))))
	copy(b.Extend(int32(len(p))), p)
	return b
}

type fullPacketReader struct {
	r      io.Reader
	buffer [65535]byte
}

func newFullPacketReader(r io.Reader) buf.Reader {
	if reader, ok := r.(buf.Reader); ok {
		return reader
	}
	return &fullPacketReader{r: r}
}
func (r *fullPacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	n, err := r.r.Read(r.buffer[:])
	if err != nil && n == 0 {
		return nil, err
	}
	return buf.MultiBuffer{ownedDatagram(r.buffer[:n])}, err
}

// packetLinkConn preserves one Buffer per UDP packet (unlike BufferedReader and
// MergeBytes, which intentionally flatten/split TCP streams).
type packetLinkConn struct {
	*pipeConn
	packetReader buf.Reader
	readMu       sync.Mutex
	pending      buf.MultiBuffer
	readErr      error
	remote       net.Addr
}

func newPacketLinkConn(r buf.Reader, w buf.Writer, remote net.Addr) *packetLinkConn {
	return &packetLinkConn{pipeConn: newPipeConn(r, w), packetReader: r, remote: remote}
}

func (c *packetLinkConn) Read(p []byte) (int, error) {
	n, _, err := c.ReadFrom(p)
	return n, err
}

func (c *packetLinkConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for len(c.pending) == 0 {
		if c.readErr != nil {
			return 0, nil, c.readErr
		}
		c.pending, c.readErr = c.packetReader.ReadMultiBuffer()
	}
	b := c.pending[0]
	c.pending[0] = nil
	c.pending = c.pending[1:]
	defer b.Release()
	if len(p) < int(b.Len()) {
		return 0, nil, io.ErrShortBuffer
	}
	addr := c.remote
	if b.UDP != nil && b.UDP.IsValid() {
		addr = packetAddress(b.UDP.NetAddr())
	}
	return copy(p, b.Bytes()), addr, nil
}

func (c *packetLinkConn) Write(p []byte) (int, error) {
	if len(p) > 65535 {
		return 0, io.ErrShortBuffer
	}
	if err := c.writer.WriteMultiBuffer(buf.MultiBuffer{ownedDatagram(p)}); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *packetLinkConn) Close() error {
	err := c.pipeConn.Close()
	c.readMu.Lock()
	c.pending = buf.ReleaseMulti(c.pending)
	c.readErr = net.ErrClosed
	c.readMu.Unlock()
	return err
}

func (c *packetLinkConn) RemoteAddr() net.Addr { return c.remote }

// connectedPacketConn is only for the outer tunnel's single configured server.
type connectedPacketConn struct {
	net.Conn
	packets *packetLinkConn
	remote  net.Addr
}

func (c *connectedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.packets.Read(p)
	return n, c.remote, err
}
func (c *connectedPacketConn) Close() error {
	err := c.Conn.Close()
	_ = c.packets.Close()
	return err
}
func (c *connectedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr == nil || addr.String() != c.remote.String() {
		return 0, net.InvalidAddrError("unexpected UDP peer")
	}
	return c.Conn.Write(p)
}
