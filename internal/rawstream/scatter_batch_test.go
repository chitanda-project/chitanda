package rawstream

import (
	"bytes"
	"io"
	"testing"
)

func TestScatterBatchCoalescesWithoutChangingInput(t *testing.T) {
	key := [16]byte{1, 2, 3}
	enc, _ := NewAEADStream(key)
	dec, _ := NewAEADStream(key)
	var wire bytes.Buffer
	w := NewFramedWriter(&wire, enc)
	var input [][]byte
	var expected bytes.Buffer
	for i := 0; i < 1024; i++ {
		p := bytes.Repeat([]byte{byte(i)}, 2048)
		input = append(input, nil, p)
		expected.Write(p)
	}
	headerLengths := make([]int, len(input))
	for i := range input {
		headerLengths[i] = len(input[i])
	}
	if n, err := w.WriteBatch(input); err != nil || n != expected.Len() {
		t.Fatal(n, err)
	}
	if err := w.WriteEOF(); err != nil {
		t.Fatal(err)
	}
	for i := range input {
		if len(input[i]) != headerLengths[i] {
			t.Fatal("caller slice header mutated")
		}
	}
	got, err := io.ReadAll(NewFramedReader(&wire, dec))
	if err != nil || !bytes.Equal(got, expected.Bytes()) {
		t.Fatal("scatter payload/EOF mismatch", err)
	}
}

func BenchmarkScatterBatch(b *testing.B) {
	for _, pieces := range []int{1, 32} {
		name := "contiguous"
		if pieces > 1 {
			name = "32x2KiB"
		}
		b.Run(name, func(b *testing.B) {
			key := [16]byte{1, 2, 3}
			stream, _ := NewAEADStream(key)
			w := NewFramedWriter(io.Discard, stream)
			p := make([]byte, 64<<10)
			parts := make([][]byte, pieces)
			for i := range parts {
				parts[i] = p[i*len(p)/pieces : (i+1)*len(p)/pieces]
			}
			_, _ = w.WriteBatch(parts) // allocate an optional coalescing buffer once
			b.ReportAllocs()
			b.SetBytes(int64(len(p)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := w.WriteBatch(parts); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
