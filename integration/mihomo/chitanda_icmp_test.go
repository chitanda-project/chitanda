package outbound

import (
	"context"
	"testing"
)

func TestMihomoSupportICMP(t *testing.T) {
	udpEnabled := true
	udpDisabled := false

	cDefault := &Chitanda{
		option: &ChitandaOption{},
	}
	if !cDefault.SupportICMP() {
		t.Fatal("expected SupportICMP() == true by default")
	}

	cEnabled := &Chitanda{
		option: &ChitandaOption{UDP: &udpEnabled},
	}
	if !cEnabled.SupportICMP() {
		t.Fatal("expected SupportICMP() == true when UDP enabled")
	}

	cDisabled := &Chitanda{
		option: &ChitandaOption{UDP: &udpDisabled},
	}
	if cDisabled.SupportICMP() {
		t.Fatal("expected SupportICMP() == false when UDP disabled")
	}

	// Verify ListenPacketContext rejects when UDP/ICMP is disabled
	_, err := cDisabled.ListenPacketContext(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error when UDP is disabled")
	}
}
