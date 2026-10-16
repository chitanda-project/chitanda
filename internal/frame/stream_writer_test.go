package frame

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
)

func TestStreamWriterPooledWireAndBoundaries(t *testing.T) {
	for _, size := range []int{0, 1, 256, 257, 4096, 4097, 32768, 32769, DataChunkSize, DataChunkSize + 1, 3*DataChunkSize + 17} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			payload := bytes.Repeat([]byte{byte(size), 31, 77}, (size+2)/3)[:size]
			var got, want bytes.Buffer
			w := NewStreamWriter(&got)
			if n, err := w.Write(payload); err != nil || n != size {
				t.Fatalf("write=%d %v", n, err)
			}
			for rest := payload; len(rest) != 0; {
				n := min(len(rest), DataChunkSize)
				if err := WriteFrame(&want, TypeData, 0, rest[:n]); err != nil {
					t.Fatal(err)
				}
				rest = rest[n:]
			}
			if err := w.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			_ = WriteFrame(&want, TypeHalfClose, 0, nil)
			if !bytes.Equal(got.Bytes(), want.Bytes()) {
				t.Fatal("pooled writer changed the wire format")
			}
			decoded, err := io.ReadAll(NewStreamReader(bytes.NewReader(got.Bytes())))
			if err != nil || !bytes.Equal(decoded, payload) {
				t.Fatal("round trip failed", err)
			}
			if err := w.CloseWrite(); err != nil {
				t.Fatal("half close is not idempotent", err)
			}
			if _, err := w.Write([]byte("after FIN")); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal("write accepted after half close", err)
			}
		})
	}
}

func TestStreamWriterPooledConcurrentIsolation(t *testing.T) {
	var workers sync.WaitGroup
	for id := byte(1); id <= 8; id++ {
		workers.Add(1)
		go func(id byte) {
			defer workers.Done()
			var wire bytes.Buffer
			w := NewStreamWriter(&wire)
			payload := bytes.Repeat([]byte{id}, 32<<10)
			for i := 0; i < 32; i++ {
				if _, err := w.Write(payload); err != nil {
					t.Error(err)
					return
				}
			}
			if err := w.CloseWrite(); err != nil {
				t.Error(err)
				return
			}
			got, err := io.ReadAll(NewStreamReader(&wire))
			if err != nil || !bytes.Equal(got, bytes.Repeat(payload, 32)) {
				t.Error("cross-writer buffer alias or corruption", err)
			}
		}(id)
	}
	workers.Wait()
}

type partialFrameFailure struct{ calls int }

func (w *partialFrameFailure) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == 1 {
		return min(3, len(p)), nil
	}
	return 0, io.ErrUnexpectedEOF
}

func TestStreamWriterPooledPartialFailureIsTerminal(t *testing.T) {
	transport := &partialFrameFailure{}
	w := NewStreamWriter(transport)
	if n, err := w.Write([]byte("payload")); n != 0 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("partial write = %d, %v", n, err)
	}
	calls := transport.calls
	if _, err := w.Write([]byte("retry")); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("failed writer accepted retry", err)
	}
	if err := w.CloseWrite(); !errors.Is(err, io.ErrUnexpectedEOF) || calls != transport.calls {
		t.Fatal("failed writer emitted an extra frame", err)
	}
}
