package auth

import (
	"bufio"
	"container/heap"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	MaxClockSkew       = 90 * time.Second
	replayCompactAfter = 10_000
	AuthDomainV2       = "MYXRAY-AUTH-V2"
)

type ReplayCache struct {
	mu          sync.Mutex
	cond        *sync.Cond
	expires     map[string]time.Time
	expiryQueue replayExpiryHeap
	file        *os.File
	path        string
	writesSince int
	persistent  bool
	persistErr  error
	syncedTx    uint64
	currentTx   uint64
	stopCh      chan struct{}
	doneCh      chan struct{}
	lockFile    *os.File
	sharedPath  string
	sharedRefs  int
	stopOnce    sync.Once
	closed      bool
}

type replayExpiry struct {
	nonce  string
	expiry time.Time
}

type replayExpiryHeap []replayExpiry

func (h replayExpiryHeap) Len() int           { return len(h) }
func (h replayExpiryHeap) Less(i, j int) bool { return h[i].expiry.Before(h[j].expiry) }
func (h replayExpiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *replayExpiryHeap) Push(value any) {
	*h = append(*h, value.(replayExpiry))
}

func (h *replayExpiryHeap) Pop() any {
	old := *h
	last := len(old) - 1
	value := old[last]
	*h = old[:last]
	return value
}

func NewReplayCache() *ReplayCache {
	c := &ReplayCache{
		expires: make(map[string]time.Time),
	}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func OpenReplayCache(path string, now time.Time) (*ReplayCache, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("replay cache path is required")
	}
	lockFile, err := lockReplayFile(path)
	if err != nil {
		return nil, fmt.Errorf("lock replay cache: %w", err)
	}
	success := false
	defer func() {
		if !success {
			_ = lockFile.Close()
		}
	}()
	_, statErr := os.Stat(path)
	created := errors.Is(statErr, os.ErrNotExist)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if created {
		if syncErr := syncDirectory(filepath.Dir(path)); syncErr != nil {
			_ = file.Close()
			return nil, syncErr
		}
	}
	cache := &ReplayCache{
		expires:    make(map[string]time.Time),
		file:       file,
		path:       path,
		persistent: true,
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
		lockFile:   lockFile,
	}
	cache.cond = sync.NewCond(&cache.mu)
	if err := cache.load(now); err != nil {
		_ = file.Close()
		return nil, err
	}
	go cache.groupCommitLoop()
	success = true
	return cache, nil
}

func (c *ReplayCache) groupCommitLoop() {
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	defer close(c.doneCh)

	for {
		select {
		case <-c.stopCh:
			c.mu.Lock()
			if c.file != nil && c.currentTx > c.syncedTx {
				if err := c.file.Sync(); err != nil {
					_ = c.markPersistenceFailure(err)
				} else {
					c.syncedTx = c.currentTx
				}
				c.cond.Broadcast()
			}
			c.mu.Unlock()
			return
		case <-ticker.C:
			c.mu.Lock()
			if c.file != nil && c.currentTx > c.syncedTx {
				err := c.file.Sync()
				if err != nil {
					_ = c.markPersistenceFailure(err)
				} else {
					c.syncedTx = c.currentTx
				}
				c.cond.Broadcast()
			}
			c.mu.Unlock()
		}
	}
}

func (c *ReplayCache) load(now time.Time) error {
	if _, err := c.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	scanner := bufio.NewScanner(c.file)
	for scanner.Scan() {
		expiryText, encodedNonce, ok := strings.Cut(scanner.Text(), "\t")
		expiryUnix, err := strconv.ParseInt(expiryText, 10, 64)
		if !ok || err != nil {
			return errors.New("invalid replay cache record")
		}
		nonceBytes, err := base64.RawURLEncoding.DecodeString(encodedNonce)
		if err != nil || len(nonceBytes) == 0 {
			return errors.New("invalid replay cache nonce")
		}
		expiry := time.Unix(expiryUnix, 0)
		if expiry.After(now) {
			nonce := string(nonceBytes)
			c.expires[nonce] = expiry
			heap.Push(&c.expiryQueue, replayExpiry{nonce: nonce, expiry: expiry})
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	_, err := c.file.Seek(0, io.SeekEnd)
	return err
}

// Check checks if the nonce is already in the replay cache without committing it.
func (c *ReplayCache) Check(nonce string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	for c.expiryQueue.Len() > 0 && !c.expiryQueue[0].expiry.After(now) {
		expired := heap.Pop(&c.expiryQueue).(replayExpiry)
		if current, exists := c.expires[expired.nonce]; exists && current.Equal(expired.expiry) {
			delete(c.expires, expired.nonce)
		}
	}
	_, exists := c.expires[nonce]
	return exists
}

func (c *ReplayCache) Accept(nonce string, now time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false, errors.New("replay cache is closed")
	}
	if c.persistErr != nil {
		return false, c.persistErr
	}
	if c.persistent && c.file == nil {
		return false, c.markPersistenceFailure(errors.New("replay cache file is unavailable"))
	}

	for c.expiryQueue.Len() > 0 && !c.expiryQueue[0].expiry.After(now) {
		expired := heap.Pop(&c.expiryQueue).(replayExpiry)
		if current, exists := c.expires[expired.nonce]; exists && current.Equal(expired.expiry) {
			delete(c.expires, expired.nonce)
		}
	}
	if _, exists := c.expires[nonce]; exists {
		return false, nil
	}
	if len(c.expires) >= 200000 {
		return false, errors.New("replay cache capacity exceeded")
	}
	var thisTx uint64
	if c.file != nil {
		if c.writesSince >= replayCompactAfter {
			if err := c.compact(); err != nil {
				return false, c.markPersistenceFailure(err)
			}
		}
		expiry := now.Add(2 * MaxClockSkew)
		record := strconv.FormatInt(expiry.Unix(), 10) + "\t" + base64.RawURLEncoding.EncodeToString([]byte(nonce)) + "\n"
		if _, err := io.WriteString(c.file, record); err != nil {
			return false, c.markPersistenceFailure(err)
		}
		c.writesSince++
		c.currentTx++
		thisTx = c.currentTx
	}
	expiry := now.Add(2 * MaxClockSkew)
	c.expires[nonce] = expiry
	heap.Push(&c.expiryQueue, replayExpiry{nonce: nonce, expiry: expiry})

	if c.persistent && thisTx > 0 {
		for c.syncedTx < thisTx && c.persistErr == nil {
			c.cond.Wait()
		}
		if c.persistErr != nil {
			return false, c.persistErr
		}
	}
	return true, nil
}

func (c *ReplayCache) markPersistenceFailure(err error) error {
	if c.persistErr == nil {
		c.persistErr = fmt.Errorf("replay cache persistence failed: %w", err)
	}
	if c.cond != nil {
		c.cond.Broadcast()
	}
	return c.persistErr
}

func (c *ReplayCache) compact() error {
	temporary, err := os.CreateTemp(filepath.Dir(c.path), ".replay-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	for nonce, expiry := range c.expires {
		record := strconv.FormatInt(expiry.Unix(), 10) + "\t" + base64.RawURLEncoding.EncodeToString([]byte(nonce)) + "\n"
		if _, err := io.WriteString(temporary, record); err != nil {
			cleanup()
			return err
		}
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := temporary.Close(); err != nil {
		cleanup()
		return err
	}
	if err := c.file.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := os.Rename(temporaryPath, c.path); err != nil {
		c.file, _ = os.OpenFile(c.path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
		_ = os.Remove(temporaryPath)
		return err
	}
	c.file, err = os.OpenFile(c.path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(c.path)); err != nil {
		return err
	}
	c.writesSince = 0
	return nil
}

func syncDirectory(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	_ = directory.Close()
	return syncErr
}

func (c *ReplayCache) Close() error {
	if c.sharedPath != "" {
		sharedCaches.Lock()
		defer sharedCaches.Unlock()
		if c.sharedRefs <= 0 {
			return nil
		}
		c.sharedRefs--
		if c.sharedRefs > 0 {
			return nil
		}
		delete(sharedCaches.entries, c.sharedPath)
	}
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	if c.stopCh != nil {
		c.stopOnce.Do(func() { close(c.stopCh) })
		<-c.doneCh
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() {
		if c.lockFile != nil {
			_ = c.lockFile.Close()
			c.lockFile = nil
		}
	}()
	if c.file == nil {
		return nil
	}
	_ = c.file.Sync()
	err := c.file.Close()
	c.file = nil
	return err
}

func LoadPSK(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	value := strings.TrimSpace(string(raw))
	if decoded, err := hex.DecodeString(value); err == nil && len(decoded) >= 32 {
		return decoded, nil
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil && len(decoded) >= 32 {
		return decoded, nil
	}
	return nil, errors.New("PSK must be at least 32 bytes encoded as hex or base64url")
}

func Signature(psk []byte, mode, method, path, target, timestamp, nonce string) string {
	mac := hmac.New(sha256.New, psk)
	writeLengthPrefixed(mac, AuthDomainV2)
	writeLengthPrefixed(mac, mode)
	writeLengthPrefixed(mac, method)
	writeLengthPrefixed(mac, path)
	writeLengthPrefixed(mac, target)
	writeLengthPrefixed(mac, timestamp)
	writeLengthPrefixed(mac, nonce)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func writeLengthPrefixed(w io.Writer, s string) {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(s)))
	_, _ = w.Write(lenBuf[:])
	_, _ = io.WriteString(w, s)
}

func Verify(psk []byte, mode, method, path, target, timestamp, nonce, signature string, now time.Time) bool {
	unixSeconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || nonce == "" || signature == "" {
		return false
	}
	requestTime := time.Unix(unixSeconds, 0)
	if requestTime.Before(now.Add(-MaxClockSkew)) || requestTime.After(now.Add(MaxClockSkew)) {
		return false
	}
	expected := Signature(psk, mode, method, path, target, timestamp, nonce)
	return hmac.Equal([]byte(expected), []byte(signature))
}
