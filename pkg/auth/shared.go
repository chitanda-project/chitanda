package auth

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var sharedCaches = struct {
	sync.Mutex
	entries map[string]*ReplayCache
}{entries: make(map[string]*ReplayCache)}

// DefaultReplayPath contains no key material. Refuse ephemeral fallback if the
// service account's persistent state directory cannot be created.
func DefaultReplayPath(identity string) (string, error) {
	dir := os.Getenv("CHITANDA_STATE_DIR")
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(base, "chitanda", "replay")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, fmt.Sprintf("%x.cache", sha256.Sum256([]byte(identity)))), nil
}

// Each caller owns one reference and must close it exactly once. OS locking
// prevents a second process from concurrently owning the same replay file.
func OpenSharedReplayCache(path string, now time.Time) (*ReplayCache, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	sharedCaches.Lock()
	defer sharedCaches.Unlock()
	if cache := sharedCaches.entries[path]; cache != nil {
		cache.sharedRefs++
		return cache, nil
	}
	cache, err := OpenReplayCache(path, now)
	if err != nil {
		return nil, err
	}
	cache.sharedPath, cache.sharedRefs = path, 1
	sharedCaches.entries[path] = cache
	return cache, nil
}
