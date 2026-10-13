package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/violetaini/chitanda/internal/plainudp"
	"github.com/violetaini/chitanda/pkg/auth"
)

// Persist one admission per authenticated session and 10-second timestamp
// bucket, never per packet. After restart an already admitted bucket fails
// closed; a new association works immediately, an existing one resumes in the
// next bucket. Admission is synced BEFORE any payload is forwarded.
const UDPReplayBucketSeconds = 10

func UDPReplayNamespace(psk []byte, serverID string) string {
	key := sha256.Sum256(append(append([]byte("plainudp\x00"+serverID+"\x00"), psk...), byte(0)))
	return hex.EncodeToString(key[:])
}

func udpReplayNamespaces(users []UserKey, serverID string) []string {
	result := make([]string, len(users))
	for i, u := range users {
		result[i] = UDPReplayNamespace(u.PSK, serverID)
	}
	return result
}

func NewPersistentUDPReplayWindow(cache *auth.ReplayCache, namespace string, sessionID uint64) *UDPReplayWindow {
	return &UDPReplayWindow{cache: cache, namespace: namespace, sessionID: sessionID}
}

func (w *UDPReplayWindow) AcceptAuthenticated(seq, timestamp uint64, now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	diff := now.Unix() - int64(timestamp)
	if diff < -int64(plainudp.MaxTimestampSkew/time.Second) || diff > int64(plainudp.MaxTimestampSkew/time.Second) {
		return false
	}
	if w.cache != nil {
		bucket := timestamp / UDPReplayBucketSeconds
		if w.buckets == nil {
			w.buckets = make(map[uint64]time.Time)
		}
		for b, expiry := range w.buckets {
			if !expiry.After(now) {
				delete(w.buckets, b)
			}
		}
		if _, ok := w.buckets[bucket]; !ok {
			key := fmt.Sprintf("udp-bucket/%s/%016x/%d", w.namespace, w.sessionID, bucket)
			accepted, err := w.cache.Accept(key, now)
			if err != nil || !accepted {
				return false
			}
			w.buckets[bucket] = now.Add(2 * auth.MaxClockSkew)
		}
	}
	return w.window.Accept(seq)
}
