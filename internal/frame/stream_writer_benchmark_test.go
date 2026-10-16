package frame

import (
	"fmt"
	"io"
	"testing"
)

func BenchmarkStreamWriter(b *testing.B) {
	for _, size := range []int{64, 1200, 32 << 10, 256 << 10} {
		for _, parallel := range []bool{false, true} {
			b.Run(fmt.Sprintf("bytes=%d/parallel=%t", size, parallel), func(b *testing.B) {
				payload := make([]byte, size)
				b.ReportAllocs()
				b.SetBytes(int64(size))
				if parallel {
					b.RunParallel(func(pb *testing.PB) {
						w := NewStreamWriter(io.Discard)
						for pb.Next() {
							_, _ = w.Write(payload)
						}
					})
				} else {
					w := NewStreamWriter(io.Discard)
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_, _ = w.Write(payload)
					}
				}
			})
		}
	}
}
