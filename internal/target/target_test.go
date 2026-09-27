package target

import (
	"context"
	"net"
	"testing"
)

func TestAllowed(t *testing.T) {
	tests := []struct {
		address string
		want    bool
	}{
		{"1.1.1.1", true},
		{"8.8.8.8", true},
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"192.168.1.1", false},
		{"100.64.0.1", false},
		{"192.0.2.1", false},
		{"198.18.0.1", false},
		{"203.0.113.1", false},
		{"169.254.1.1", false},
		{"224.0.0.1", false},
		{"::1", false},
		{"2001:db8::1", false},
		{"2001:4860:4860::8888", true},
	}
	for _, test := range tests {
		if got := allowed(net.ParseIP(test.address)); got != test.want {
			t.Errorf("allowed(%s) = %v, want %v", test.address, got, test.want)
		}
	}
}

func TestResolveICMPIPPolicy(t *testing.T) {
	if _, err := ResolveICMPIP(context.Background(), "127.0.0.1", false); err != ErrForbidden {
		t.Fatalf("loopback was not blocked: %v", err)
	}
	if _, err := ResolveICMPIP(context.Background(), "10.0.0.1", false); err != ErrForbidden {
		t.Fatalf("private IP was not blocked: %v", err)
	}
	if ip, err := ResolveICMPIP(context.Background(), "127.0.0.1", true); err != nil || !ip.IsLoopback() {
		t.Fatalf("explicit loopback override failed: %v %v", ip, err)
	}
	if _, err := ResolveICMPIP(context.Background(), "224.0.0.1", true); err != ErrForbidden {
		t.Fatalf("multicast was not blocked: %v", err)
	}
}
