package server

import (
	"context"
	"io"
	"net"
	"time"
)

const DefaultIdleTimeout = 300 * time.Second

type activityReader struct {
	r          io.Reader
	onActivity func()
}

func (a *activityReader) Read(p []byte) (int, error) {
	n, err := a.r.Read(p)
	if n > 0 && a.onActivity != nil {
		a.onActivity()
	}
	return n, err
}

type closeWriter interface{ CloseWrite() error }

func closeWriteConn(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

// waitRelay preserves a clean half-close. Only cancellation, an I/O failure or
// bidirectional inactivity aborts the other direction. Always join the workers
// before the handler releases its ResponseWriter or copy buffers.
func waitRelay(ctx context.Context, activity <-chan struct{}, upload, download <-chan error, abort func()) {
	timer := time.NewTimer(DefaultIdleTimeout)
	defer timer.Stop()
	join := func() {
		abort()
		if upload != nil {
			<-upload
		}
		if download != nil {
			<-download
		}
	}
	for upload != nil || download != nil {
		select {
		case <-ctx.Done():
			join()
			return
		case <-timer.C:
			join()
			return
		case <-activity:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(DefaultIdleTimeout)
		case err := <-upload:
			upload = nil
			if err != nil {
				join()
				return
			}
		case err := <-download:
			download = nil
			if err != nil {
				join()
				return
			}
		}
	}
}
