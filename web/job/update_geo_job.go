package job

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"x-ui/config"
	"x-ui/logger"
	"x-ui/web/service"
)

var (
	geoUpdateLock sync.Mutex
)

type GeoSourceConfig struct {
	Name  string
	Repo  string
	Files map[string]string // remote -> local
}

var GeoSources = map[string]GeoSourceConfig{
	"Loyalsoldier": {
		Name: "Loyalsoldier (Standard)",
		Repo: "Loyalsoldier/v2ray-rules-dat",
		Files: map[string]string{
			"geosite.dat": "geosite.dat",
			"geoip.dat":   "geoip.dat",
		},
	},
	"chocolate4u": {
		Name: "chocolate4u (Iran)",
		Repo: "chocolate4u/Iran-v2ray-rules",
		Files: map[string]string{
			"geosite.dat": "geosite_IR.dat",
			"geoip.dat":   "geoip_IR.dat",
		},
	},
	"runetfreedom": {
		Name: "runetfreedom (Russia)",
		Repo: "runetfreedom/russia-v2ray-rules-dat",
		Files: map[string]string{
			"geosite.dat": "geosite_RU.dat",
			"geoip.dat":   "geoip_RU.dat",
		},
	},
	"vuong2023": {
		Name: "vuong2023 (Vietnam)",
		Repo: "vuong2023/vn-v2ray-rules",
		Files: map[string]string{
			"geosite.dat": "geosite_VN.dat",
			"geoip.dat":   "geoip_VN.dat",
		},
	},
}

type UpdateGeoJob struct {
	xrayService    service.XrayService
	settingService service.SettingService
}

func NewUpdateGeoJob() *UpdateGeoJob {
	return new(UpdateGeoJob)
}

func (j *UpdateGeoJob) Run() {
	enabled, err := j.settingService.GetGeoAutoUpdateEnable()
	if err != nil || !enabled {
		return
	}

	sources, err := j.settingService.GetGeoAutoUpdateSources()
	if err != nil || sources == "" {
		sources = "Loyalsoldier"
	}

	logger.Info("[UpdateGeoJob] Scheduled GeoIP/GeoSite update started with sources:", sources)
	updated, unchanged, err := UpdateGeo(sources, &j.xrayService)
	if err != nil {
		logger.Error("[UpdateGeoJob] Failed to update Geo files:", err)
		return
	}

	if len(updated) > 0 {
		logger.Infof("[UpdateGeoJob] Geo files updated: %v (Unchanged: %v). Xray restarted.", updated, unchanged)
	} else {
		logger.Infof("[UpdateGeoJob] All Geo files are up-to-date (%v). No Xray restart required.", unchanged)
	}
}

// UpdateGeo downloads and safely applies GeoIP/GeoSite updates
func UpdateGeo(selectedSources string, xrayService *service.XrayService) (updatedFiles []string, unchangedFiles []string, err error) {
	if !geoUpdateLock.TryLock() {
		return nil, nil, errors.New("another geo update task is already running")
	}
	defer geoUpdateLock.Unlock()

	binDir := config.GetBinFolderPath()
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return nil, nil, fmt.Errorf("failed to ensure bin folder %s: %w", binDir, err)
	}

	tempDir, err := os.MkdirTemp("", "3xui-geo-*")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temp folder: %w", err)
	}
	defer os.RemoveAll(tempDir)

	client := &http.Client{
		Timeout: 300 * time.Second,
	}

	sourceKeys := strings.Split(selectedSources, ",")
	if len(sourceKeys) == 0 || (len(sourceKeys) == 1 && strings.TrimSpace(sourceKeys[0]) == "") {
		sourceKeys = []string{"Loyalsoldier"}
	}

	for _, rawKey := range sourceKeys {
		key := strings.TrimSpace(rawKey)
		source, ok := GeoSources[key]
		if !ok {
			logger.Warning("[UpdateGeoJob] Unknown geo source:", key)
			continue
		}

		for remoteFile, localFile := range source.Files {
			downloadUrl := fmt.Sprintf("https://github.com/%s/releases/latest/download/%s", source.Repo, remoteFile)
			tempFile := filepath.Join(tempDir, localFile)

			logger.Infof("[UpdateGeoJob] Downloading %s from %s ...", localFile, downloadUrl)
			if err := downloadToFile(client, downloadUrl, tempFile); err != nil {
				logger.Errorf("[UpdateGeoJob] Failed downloading %s: %v", localFile, err)
				continue
			}

			destFile := filepath.Join(binDir, localFile)
			changed, err := fileChanged(tempFile, destFile)
			if err != nil {
				logger.Errorf("[UpdateGeoJob] Failed checking file hash for %s: %v", localFile, err)
				continue
			}

			if changed {
				if err := copyFile(tempFile, destFile, 0644); err != nil {
					logger.Errorf("[UpdateGeoJob] Failed copying %s to %s: %v", tempFile, destFile, err)
					continue
				}
				updatedFiles = append(updatedFiles, localFile)
			} else {
				unchangedFiles = append(unchangedFiles, localFile)
			}
		}
	}

	// Restart Xray if and only if at least one file changed
	if len(updatedFiles) > 0 && xrayService != nil {
		if xrayService.IsXrayRunning() {
			logger.Infof("[UpdateGeoJob] %d files updated, restarting Xray...", len(updatedFiles))
			if restartErr := xrayService.RestartXray(true); restartErr != nil {
				logger.Errorf("[UpdateGeoJob] Restart Xray failed: %v", restartErr)
			}
		}
	}

	return updatedFiles, unchangedFiles, nil
}

func downloadToFile(client *http.Client, url string, destPath string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "3x-ui-geo-updater")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad HTTP status: %s", resp.Status)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()

	written, err := io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	// Safety check: ensure file is at least 100KB to avoid saving truncated or 404 pages
	if written < 100*1024 {
		os.Remove(destPath)
		return fmt.Errorf("downloaded file too small (%d bytes), rejected as invalid", written)
	}

	return nil
}

func fileChanged(newPath, oldPath string) (bool, error) {
	if _, err := os.Stat(oldPath); os.IsNotExist(err) {
		return true, nil
	}

	newHash, err := calcSHA256(newPath)
	if err != nil {
		return false, err
	}

	oldHash, err := calcSHA256(oldPath)
	if err != nil {
		return false, err
	}

	return newHash != oldHash, nil
}

func calcSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	return out.Sync()
}
