package auth

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
)

// persistentConfigDir supports minimal service environments without switching
// to temporary/in-memory storage. Failure remains fail-closed.
func persistentConfigDir() (string, error) {
	if dir, err := os.UserConfigDir(); err == nil {
		return dir, nil
	}
	account, err := user.Current()
	if err != nil || !filepath.IsAbs(account.HomeDir) {
		_, configErr := os.UserConfigDir()
		return "", configErr
	}
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(account.HomeDir, "AppData", "Roaming"), nil
	case "darwin":
		return filepath.Join(account.HomeDir, "Library", "Application Support"), nil
	default:
		return filepath.Join(account.HomeDir, ".config"), nil
	}
}
