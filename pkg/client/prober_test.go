package client

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestClassifyH2ProbeDefersBeforeEmbeddingDialerIsReady(t *testing.T) {
	for _, err := range []error{ErrCarrierNotReady, fmt.Errorf("wrapped: %w", ErrCarrierNotReady)} {
		skip, failed := classifyH2Probe(0, err)
		if !skip || failed {
			t.Fatalf("not-ready probe classified as failure: skip=%v failed=%v", skip, failed)
		}
	}
	for _, tc := range []struct {
		rtt    time.Duration
		err    error
		failed bool
	}{
		{100 * time.Millisecond, nil, false},
		{3 * time.Second, nil, true},
		{0, errors.New("network failure"), true},
	} {
		skip, failed := classifyH2Probe(tc.rtt, tc.err)
		if skip || failed != tc.failed {
			t.Fatalf("probe rtt=%s err=%v: skip=%v failed=%v, want failed=%v", tc.rtt, tc.err, skip, failed, tc.failed)
		}
	}
}
