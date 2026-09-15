package config

import "testing"

func TestReviewChitandaDialerValidation(t *testing.T) {
	for _, target := range []string{"self", "missing-proxy"} {
		t.Run(target, func(t *testing.T) {
			c := RawConfig{Proxy: []map[string]any{{"type": "chitanda", "name": "self", "server": "127.0.0.1", "port": 9999, "psk": "local-review-only-test-key-32-bytes", "transport": "stream", "dialer-proxy": target}}}
			_, _, e := parseProxies(&c)
			if e == nil {
				t.Errorf("invalid dialer-proxy %q bypassed validation", target)
			}
		})
	}
}
