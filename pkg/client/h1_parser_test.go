package client

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

type h1BoundaryTimeout struct {
	data             []byte
	offset, boundary int
	failed           bool
}

func (r *h1BoundaryTimeout) Read(p []byte) (int, error) {
	if !r.failed && r.offset == r.boundary {
		r.failed = true
		return 0, os.ErrDeadlineExceeded
	}
	if r.offset == len(r.data) {
		return 0, io.EOF
	}
	n := len(r.data) - r.offset
	if !r.failed {
		n = min(n, r.boundary-r.offset)
	}
	n = min(n, len(p))
	copy(p, r.data[r.offset:r.offset+n])
	r.offset += n
	return n, nil
}

func TestH1ChunkTimeoutAtEveryBoundary(t *testing.T) {
	wire := []byte("10\r\nABCDEFGHIJKLMNOP\r\n1\r\nZ\r\n0\r\nTest-Trailer: ok\r\n\r\n")
	for boundary := 0; boundary < len(wire); boundary++ {
		t.Run(fmt.Sprint(boundary), func(t *testing.T) {
			r := newChunkedReader(bufio.NewReader(&h1BoundaryTimeout{data: wire, boundary: boundary}))
			var got bytes.Buffer
			var p [7]byte
			for reads := 0; reads < 100; reads++ {
				n, err := r.Read(p[:])
				got.Write(p[:n])
				if errors.Is(err, os.ErrDeadlineExceeded) {
					continue
				}
				if err == io.EOF {
					if got.String() != "ABCDEFGHIJKLMNOPZ" {
						t.Fatal(got.String())
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			t.Fatal("reader did not terminate")
		})
	}
}

func TestH1ResponseHeaderStrictnessAndBounds(t *testing.T) {
	valid := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
	if err := readH1ResponseHeaders(bufio.NewReader(strings.NewReader(valid))); err != nil {
		t.Fatal(err)
	}
	for _, wire := range []string{
		strings.Replace(valid, "200 OK", "2000 Nope", 1),
		strings.Replace(valid, "Transfer-Encoding: chunked", "Content-Length: 0", 1),
		strings.Replace(valid, "Transfer-Encoding: chunked", "Transfer-Encoding: gzip, chunked", 1),
		strings.Replace(valid, "Transfer-Encoding: chunked", "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked", 1),
		strings.ReplaceAll(valid, "\r\n", "\n"),
		"HTTP/1.1 200 OK\r\n" + strings.Repeat("X: abc\r\n", 100) + "\r\n",
		"HTTP/1.1 200 OK\r\n" + strings.Repeat("X: "+strings.Repeat("a", 1000)+"\r\n", 17) + "\r\n",
	} {
		if err := readH1ResponseHeaders(bufio.NewReader(strings.NewReader(wire))); err == nil {
			t.Fatalf("invalid response accepted (bytes=%d)", len(wire))
		}
	}
}

func TestH1MalformedChunkCannotResume(t *testing.T) {
	for _, wire := range []string{"1\r\nAx\n0\r\n\r\n", "1\nA\r\n0\r\n\r\n", "0\r\nBad Trailer\r\n\r\n", strings.Repeat("f", maxH1ChunkLine+1) + "\r\n", "10001\r\n"} {
		r := newChunkedReader(bufio.NewReader(strings.NewReader(wire)))
		_, err := io.ReadAll(r)
		if err == nil {
			t.Fatalf("invalid chunk accepted: len=%d", len(wire))
		}
		if _, again := r.Read(make([]byte, 1)); again == nil {
			t.Fatal("fatal parser error not sticky")
		}
	}
}
