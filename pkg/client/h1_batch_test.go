package client

import (
	"bytes"
	"io"
	"testing"
)

type countingChunkSink struct {
	bytes.Buffer
	calls int
	short bool
}

func (s *countingChunkSink) Write(p []byte) (int, error) {
	s.calls++
	if s.short {
		return len(p) - 1, nil
	}
	return s.Buffer.Write(p)
}

func TestH1ChunkWriteIsOneCallAndDetectsShortWrite(t *testing.T) {
	s := &countingChunkSink{}
	w := newChunkedWriter(s)
	if n, err := w.Write([]byte("abc")); n != 3 || err != nil {
		t.Fatal(n, err)
	}
	if s.calls != 1 || s.String() != "3\r\nabc\r\n" {
		t.Fatal("invalid chunk or unbatched write")
	}
	s.short = true
	if _, err := w.Write([]byte("abc")); err != io.ErrShortWrite {
		t.Fatal("short write not rejected")
	}
}
