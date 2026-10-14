package auth

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestPersistentConfigDirWithoutServiceEnvironment(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Setenv("HOME", "")
		t.Setenv("XDG_CONFIG_HOME", "")
	}
	if runtime.GOOS == "windows" {
		t.Setenv("APPDATA", "")
	}
	dir, err := persistentConfigDir()
	if err != nil || !filepath.IsAbs(dir) {
		t.Fatalf("no persistent account path: %q %v", dir, err)
	}
}

func TestDefaultReplayPathExplicitPersistentDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CHITANDA_STATE_DIR", dir)
	path, err := DefaultReplayPath("test")
	if err != nil || filepath.Dir(path) != dir {
		t.Fatalf("state directory changed: %q %v", path, err)
	}
}
