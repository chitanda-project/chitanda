// Apply after the performance/deadline vendor patches, before compiling.
package main

import (
	"fmt"
	"go/format"
	"os"
	"regexp"
	"strings"
)

func replaceReceive(source, old, next string, count int) string {
	if strings.Count(source, old) != count {
		panic(fmt.Sprintf("receive patch anchor changed: %q", old))
	}
	return strings.ReplaceAll(source, old, next)
}

func main() {
	root := "vendor/github.com/quic-go/quic-go/"
	for _, file := range []string{"internal/protocol/params.go", "connection.go", "http3/state_tracking_stream.go", "http3/stream.go"} {
		path := root + file
		data, err := os.ReadFile(path)
		if err != nil {
			panic(err)
		}
		s := strings.ReplaceAll(string(data), "\r\n", "\n")
		// Backfill the lifecycle guard when refreshing an earlier snapshot.
		if file == "connection.go" && strings.Contains(s, "func (c *Conn) ReceiveQueueStats()") && !strings.Contains(s, "receivedPacketQueueClosed") {
			s = replaceReceive(s, "receivedPacketDrops  uint64", "receivedPacketDrops  uint64\n\treceivedPacketQueueClosed bool", 1)
			s = replaceReceive(s, "// drain queued packets that will never be processed\n\t\tc.receivedPacketMx.Lock()", "// drain queued packets that will never be processed\n\t\tc.receivedPacketMx.Lock()\n\t\tc.receivedPacketQueueClosed = true", 1)
			s = replaceReceive(s, "if c.receivedPackets.Len() >= protocol.MaxConnUnprocessedPackets ||", "if c.receivedPacketQueueClosed || c.receivedPackets.Len() >= protocol.MaxConnUnprocessedPackets ||", 1)
			out, err := format.Source([]byte(s))
			if err != nil {
				panic(err)
			}
			if err := os.WriteFile(path, out, 0644); err != nil {
				panic(err)
			}
		}
		if (file == "internal/protocol/params.go" && strings.Contains(s, "const MaxConnUnprocessedPackets = 2048")) || (file == "connection.go" && strings.Contains(s, "func (c *Conn) ReceiveQueueStats()")) || (file == "http3/state_tracking_stream.go" && strings.Contains(s, "func (s *stateTrackingStream) DatagramReceiveStats()")) || (file == "http3/stream.go" && strings.Contains(s, "func (s *RequestStream) DatagramReceiveStats()")) {
			continue
		}
		switch file {
		case "internal/protocol/params.go":
			s = replaceReceive(s, "const MaxConnUnprocessedPackets = 256", "const MaxConnUnprocessedPackets = 2048", 1)
		case "http3/stream.go":
			s += `

// DatagramReceiveStats exposes tracked HTTP Datagram queue length and drops.
func (s *Stream) DatagramReceiveStats() (int, uint64) {
    if tracked, ok := s.datagramStream.(interface{ DatagramReceiveStats() (int, uint64) }); ok {
        return tracked.DatagramReceiveStats()
    }
    return 0, 0
}

func (s *RequestStream) DatagramReceiveStats() (int, uint64) {
    return s.str.DatagramReceiveStats()
}
`
		case "connection.go":
			s = replaceReceive(s, "receivedPackets      ringbuffer.RingBuffer[receivedPacket]", "receivedPackets      ringbuffer.RingBuffer[receivedPacket]\n\treceivedPacketBytes int64\n\treceivedPacketDrops uint64\n\treceivedPacketQueueClosed bool", 1)
			s = replaceReceive(s, "// drain queued packets that will never be processed\n\t\tc.receivedPacketMx.Lock()", "// drain queued packets that will never be processed\n\t\tc.receivedPacketMx.Lock()\n\t\tc.receivedPacketQueueClosed = true", 1)
			s = replaceReceive(s, "p := c.receivedPackets.PopFront()", "p := c.receivedPackets.PopFront()\n\t\tc.receivedPacketBytes -= p.queueCost()\n\t\tglobalReceiveQueueBytes.Add(-p.queueCost())", 2)
			s = replaceReceive(s, "if c.receivedPackets.Len() >= protocol.MaxConnUnprocessedPackets {", "cost := p.queueCost()\n\tif c.receivedPacketQueueClosed || c.receivedPackets.Len() >= protocol.MaxConnUnprocessedPackets || cost > (4<<20)-c.receivedPacketBytes || !reserveReceiveQueueBytes(cost) {\n\t\tc.receivedPacketDrops++", 1)
			s = replaceReceive(s, "c.receivedPacketMx.Unlock()\n\t\treturn\n\t}\n\tc.receivedPackets.PushBack(p)", "c.receivedPacketMx.Unlock()\n\t\tif p.buffer != nil { p.buffer.Decrement(); p.buffer.MaybeRelease() }\n\t\treturn\n\t}\n\tc.receivedPacketBytes += cost\n\tc.receivedPackets.PushBack(p)", 1)
			s += `

var globalReceiveQueueBytes atomic.Int64

func reserveReceiveQueueBytes(size int64) bool {
    for {
        used := globalReceiveQueueBytes.Load()
        if size <= 0 || size > (64<<20)-used { return false }
        if globalReceiveQueueBytes.CompareAndSwap(used, used+size) { return true }
    }
}

func (p receivedPacket) queueCost() int64 {
    if p.buffer != nil { return int64(p.buffer.Cap())+128 }
    return int64(cap(p.data))+128
}

// ReceiveQueueStats exposes actual queued allocations and cumulative drops.
func (c *Conn) ReceiveQueueStats() (packets int, bytes int64, drops uint64) {
    c.receivedPacketMx.Lock()
    defer c.receivedPacketMx.Unlock()
    return c.receivedPackets.Len(), c.receivedPacketBytes, c.receivedPacketDrops
}
`
		case "http3/state_tracking_stream.go":
			s = replaceReceive(s, "const streamDatagramQueueLen = 256", "const streamDatagramQueueLen = 2048", 1)
			field := regexp.MustCompile(`(?m)^\s*queueLen\s+int$`)
			if len(field.FindAllStringIndex(s, -1)) != 1 {
				panic("HTTP3 queue length field changed")
			}
			s = field.ReplaceAllString(s, "\tqueueLen int\n\tdroppedDatagrams uint64")
			s = replaceReceive(s, "!s.clearer.reserveDatagram(accountedSize) {\n\t\t\tcontinue", "!s.clearer.reserveDatagram(accountedSize) {\n\t\t\ts.droppedDatagrams++\n\t\t\tcontinue", 1)
			s += `

func (s *stateTrackingStream) DatagramReceiveStats() (int, uint64) {
    s.mx.Lock()
    defer s.mx.Unlock()
    return s.queueLen, s.droppedDatagrams
}
`
		}
		out, err := format.Source([]byte(s))
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(path, out, 0644); err != nil {
			panic(err)
		}
	}
}
