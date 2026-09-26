package outbound

import (
	"context"
	"testing"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestChitandaH3CancellableWritePatch(t *testing.T) {
	var _ interface {
		SendDatagramNoCopyContext(context.Context, []byte) error
	} = (*quic.Conn)(nil)
	var _ interface {
		SendDatagramContext(context.Context, []byte) error
		SendDatagramsContext(context.Context, [][]byte) error
	} = (*http3.RequestStream)(nil)
}
