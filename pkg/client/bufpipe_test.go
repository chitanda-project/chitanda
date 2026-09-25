package client

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"testing"
)

func TestBufferedPipe_Basic(t *testing.T) {
	r, w := newBufferedPipe(1024)
	data := []byte("hello, chitanda buffered pipe")

	n, err := w.Write(data)
	if err != nil || n != len(data) {
		t.Fatalf("Write failed: n=%d, err=%v", n, err)
	}

	buf := make([]byte, 100)
	rn, rerr := r.Read(buf)
	if rerr != nil || rn != len(data) {
		t.Fatalf("Read failed: rn=%d, err=%v", rn, rerr)
	}
	if !bytes.Equal(buf[:rn], data) {
		t.Fatalf("Read data mismatch: got %q, want %q", buf[:rn], data)
	}

	// Close writer and verify EOF after drain
	_ = w.Close()
	_, rerr = r.Read(buf)
	if !errors.Is(rerr, io.EOF) {
		t.Fatalf("expected EOF after close, got %v", rerr)
	}
}

func TestBufferedPipe_WraparoundAndFill(t *testing.T) {
	cap := 64
	r, w := newBufferedPipe(cap)

	// Write 50 bytes, read 50 bytes
	d1 := bytes.Repeat([]byte{1}, 50)
	if _, err := w.Write(d1); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 50)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatal(err)
	}

	// Write 50 bytes again (this will wrap around ring buffer)
	d2 := bytes.Repeat([]byte{2}, 50)
	if _, err := w.Write(d2); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, d2) {
		t.Fatal("data mismatch on wrap")
	}
}

func TestBufferedPipe_ConcurrentStreaming(t *testing.T) {
	r, w := newBufferedPipe(4096)
	totalBytes := 1024 * 1024 // 1 MB
	src := make([]byte, totalBytes)
	for i := range src {
		src[i] = byte(i % 251)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer w.Close()
		chunkSize := 1024
		for i := 0; i < totalBytes; i += chunkSize {
			end := i + chunkSize
			if end > totalBytes {
				end = totalBytes
			}
			if _, err := w.Write(src[i:end]); err != nil {
				t.Errorf("writer error: %v", err)
				return
			}
		}
	}()

	dst := make([]byte, totalBytes)
	go func() {
		defer wg.Done()
		if _, err := io.ReadFull(r, dst); err != nil {
			t.Errorf("reader error: %v", err)
			return
		}
	}()

	wg.Wait()

	if !bytes.Equal(src, dst) {
		t.Fatal("concurrent streamed data mismatch")
	}
}

func TestBufferedPipe_CloseWithError(t *testing.T) {
	r, w := newBufferedPipe(1024)
	expectedErr := errors.New("custom stream error")
	_ = w.CloseWithError(expectedErr)

	buf := make([]byte, 10)
	_, err := r.Read(buf)
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected %v, got %v", expectedErr, err)
	}
}
