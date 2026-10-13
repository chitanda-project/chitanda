package server

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/auth"
)

func TestPersistentUDPReplayRejectsAfterRestartAndAllowsFreshBucket(t *testing.T) {
	now := time.Unix(1700000000, 0)
	path := filepath.Join(t.TempDir(), "udp.cache")
	cache, err := auth.OpenReplayCache(path, now)
	if err != nil {
		t.Fatal(err)
	}
	w := NewPersistentUDPReplayWindow(cache, "userA", 123)
	if !w.AcceptAuthenticated(1, uint64(now.Unix()), now) {
		t.Fatal("first packet rejected")
	}
	if w.AcceptAuthenticated(1, uint64(now.Unix()), now) {
		t.Fatal("duplicate accepted")
	}
	if !w.AcceptAuthenticated(2, uint64(now.Unix()), now) {
		t.Fatal("fresh sequence rejected")
	}
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}
	cache, err = auth.OpenReplayCache(path, now)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	restarted := NewPersistentUDPReplayWindow(cache, "userA", 123)
	if restarted.AcceptAuthenticated(1, uint64(now.Unix()), now) {
		t.Fatal("restart reopened replay")
	}
	if restarted.AcceptAuthenticated(99, uint64(now.Unix()), now) {
		t.Fatal("recovered bucket reopened")
	}
	if !NewPersistentUDPReplayWindow(cache, "userA", 456).AcceptAuthenticated(1, uint64(now.Unix()), now) {
		t.Fatal("new association blocked")
	}
	if !NewPersistentUDPReplayWindow(cache, "userB", 123).AcceptAuthenticated(1, uint64(now.Unix()), now) {
		t.Fatal("different user blocked")
	}
	next := now.Add(10 * time.Second)
	if !restarted.AcceptAuthenticated(100, uint64(next.Unix()), next) {
		t.Fatal("fresh timestamp bucket blocked")
	}
	if restarted.AcceptAuthenticated(101, uint64(now.Unix()), next) {
		t.Fatal("old bucket reopened after fresh traffic")
	}
	if restarted.AcceptAuthenticated(102, uint64(now.Add(-31*time.Second).Unix()), now) {
		t.Fatal("expired timestamp accepted")
	}
}

func TestPlainUDPServerIdentityDomainSeparation(t *testing.T) {
	psk := []byte("01234567890123456789012345678901")
	a, _ := NewPlainUDPCodec(psk, "nodeA")
	b, _ := NewPlainUDPCodec(psk, "nodeB")
	legacy, _ := NewPlainUDPCodec(psk)
	now := time.Now()
	p, err := a.EncodeClientPacket(1, "192.0.2.1:53", []byte("test"), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []*PlainUDPCodec{b, legacy} {
		if _, _, _, _, _, err := wrong.DecodeClientPacket(p, now); err == nil {
			t.Fatal("wrong identity decrypted")
		}
	}
	if _, _, _, _, _, err := a.DecodeClientPacket(p, now); err != nil {
		t.Fatal(err)
	}
}
