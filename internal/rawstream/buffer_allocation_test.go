package rawstream

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"testing"
)

var rawBufferStartupSink struct {
	reader *FramedReader
	writer *FramedWriter
}

type rawBufferRecorder struct {
	bytes.Buffer
	writes []int
}

func (w *rawBufferRecorder) Write(p []byte) (int, error) {
	w.writes = append(w.writes, len(p))
	return w.Buffer.Write(p)
}

func TestRawBufferLazyWireAndOwnership(t *testing.T) {
	key := [16]byte{1}
	enc, _ := NewAEADStream(key)
	dec, _ := NewAEADStream(key)
	var wire rawBufferRecorder
	w := NewFramedWriter(&wire, enc)
	r := NewFramedReader(&wire, dec)
	if cap(w.buf) != 0 || cap(r.rawBuf) != 0 || cap(r.decBuf) != 0 {
		t.Fatal("unused record buffers were allocated before I/O")
	}
	small := bytes.Repeat([]byte{'a'}, 64)
	if _, err := w.Write(small); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(small))
	if _, err := io.ReadFull(r, got); err != nil || !bytes.Equal(got, small) {
		t.Fatal("small initial record mismatch", err)
	}
	if cap(w.buf) > 256 || cap(r.rawBuf) > 256 || cap(r.decBuf) > 256 {
		t.Fatal("small record retained a bulk-sized buffer")
	}
	// Two writers with the same key/input must produce identical ciphertext
	// and flush boundaries, whether initially lazy or eagerly provisioned.
	refEnc, _ := NewAEADStream(key)
	var reference rawBufferRecorder
	ref := NewFramedWriter(&reference, refEnc)
	ref.buf = make([]byte, 0, MaxBatchFlushLen+MaxChunkWireLen+2)
	_, _ = ref.Write(small)
	var expected bytes.Buffer
	for _, size := range []int{1, 1380, 8192, 32768, 256 << 10, 2 << 20, 17} {
		p := bytes.Repeat([]byte{byte(size)}, size)
		expected.Write(p)
		if _, err := w.Write(p); err != nil {
			t.Fatal(err)
		}
		if _, err := ref.Write(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.WriteEOF(); err != nil {
		t.Fatal(err)
	}
	if err := ref.WriteEOF(); err != nil {
		t.Fatal(err)
	}
	// The first short record was consumed from wire, not from reference.
	if !bytes.Equal(wire.Bytes(), reference.Bytes()[len(small)+18:]) || !slices.Equal(wire.writes, reference.writes) {
		t.Fatal("lazy buffers changed ciphertext or flush boundaries")
	}
	remaining, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(remaining, expected.Bytes()) {
		t.Fatal("small-to-bulk reader growth or authenticated EOF failed", err)
	}
}

func BenchmarkRawBufferStartup(b *testing.B) {
	for _, size := range []int{0, 64, 32 << 10, 1 << 20} {
		b.Run(fmt.Sprintf("payload-%d", size), func(b *testing.B) {
			p := make([]byte, size)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				enc, _ := NewAEADStream([16]byte{1})
				dec, _ := NewAEADStream([16]byte{1})
				w := NewFramedWriter(io.Discard, enc)
				if size > 0 {
					if _, err := w.Write(p); err != nil {
						b.Fatal(err)
					}
				}
				rawBufferStartupSink.reader = NewFramedReader(bytes.NewReader(nil), dec)
				rawBufferStartupSink.writer = w
			}
		})
	}
}

func BenchmarkRawBufferWarmWrite(b *testing.B) {
	for _, size := range []int{64, 32 << 10, 1 << 20} {
		for _, parallel := range []bool{false, true} {
			b.Run(fmt.Sprintf("payload-%d/parallel-%t", size, parallel), func(b *testing.B) {
				p := make([]byte, size)
				makeWriter := func() *FramedWriter {
					enc, _ := NewAEADStream([16]byte{1})
					w := NewFramedWriter(io.Discard, enc)
					if _, err := w.Write(make([]byte, 2*Phase2Threshold)); err != nil {
						b.Error(err)
						return nil
					}
					return w
				}
				b.SetBytes(int64(size))
				b.ReportAllocs()
				if parallel {
					b.RunParallel(func(pb *testing.PB) {
						w := makeWriter()
						if w == nil {
							return
						}
						for pb.Next() {
							if _, err := w.Write(p); err != nil {
								b.Error(err)
								return
							}
						}
					})
				} else {
					w := makeWriter()
					if w == nil {
						return
					}
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if _, err := w.Write(p); err != nil {
							b.Fatal(err)
						}
					}
				}
			})
		}
	}
}
