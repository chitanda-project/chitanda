package client

import (
	"io"
	"testing"
	"time"
)

func TestRegressionH2DeadlineRecovery(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	uploadReader, uploadWriter := io.Pipe()
	defer uploadReader.Close()
	defer uploadWriter.Close()
	c := newRawH2Conn("example.invalid:443", reader, uploadWriter, func() {}, nil)
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	_, err := c.Read(make([]byte, 1))
	if e, ok := err.(interface{ Timeout() bool }); !ok || !e.Timeout() {
		t.Errorf("read expiry is not a timeout error: %v", err)
	}
	c.SetReadDeadline(time.Time{})
	go writer.Write([]byte("x"))
	b := make([]byte, 1)
	if _, err = c.Read(b); err != nil {
		t.Errorf("cleared deadline still poisons stream: %v", err)
	}
}
