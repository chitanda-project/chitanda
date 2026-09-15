package frame

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

// StreamReader exposes DATA frames as a byte stream. HALF_CLOSE is independent
// of the carrier lifetime, so an HTTP/2 response can end without losing upload.
// It bounds memory usage independently of the advertised frame length.
type StreamReader struct {
	mu         sync.Mutex
	r          io.Reader
	remaining  uint32
	terminal   error
	header     [HeaderSize]byte
	headerRead int
}

func NewStreamReader(r io.Reader) *StreamReader { return &StreamReader{r: r} }

func (r *StreamReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for r.terminal == nil {
		if r.remaining != 0 {
			if uint32(len(p)) > r.remaining {
				p = p[:r.remaining]
			}
			n, err := r.r.Read(p)
			r.remaining -= uint32(n)
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			if err != nil && !isReadTimeout(err) {
				r.terminal = err
			}
			return n, err
		}
		n, err := io.ReadFull(r.r, r.header[r.headerRead:])
		r.headerRead += n
		if err != nil {
			if isReadTimeout(err) {
				return 0, err
			}
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			r.terminal = err
			break
		}
		h := Header{Type: Type(r.header[1]), Flags: binary.BigEndian.Uint16(r.header[2:4]), Length: binary.BigEndian.Uint32(r.header[4:])}
		r.headerRead = 0
		if r.header[0] != Version || h.Length > MaxPayload {
			r.terminal = errors.New("invalid stream frame header")
			break
		}
		if h.Flags != 0 {
			r.terminal = errors.New("unsupported stream frame flags")
			break
		}
		switch h.Type {
		case TypeData:
			if h.Length == 0 {
				r.terminal = errors.New("empty DATA frame")
				break
			}
			r.remaining = h.Length
		case TypeHalfClose:
			if h.Length != 0 {
				r.terminal = errors.New("invalid HALF_CLOSE frame")
			} else {
				r.terminal = io.EOF
			}
		case TypeReset:
			r.terminal = errors.New("peer reset stream")
		default:
			r.terminal = errors.New("unexpected stream frame")
		}
	}
	return 0, r.terminal
}

func isReadTimeout(err error) bool {
	var e net.Error
	return errors.As(err, &e) && e.Timeout()
}
