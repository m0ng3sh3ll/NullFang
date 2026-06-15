package utils

import (
	"os"
	"path/filepath"
	"runtime"
)

func CreateDefaultFolders() error {
	var baseDir string
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "windows" {
		appData := os.Getenv("APPDATA")
		if appData != "" {
			baseDir = filepath.Join(appData, "nullfang")
		} else {
			baseDir = filepath.Join(home, "AppData", "Roaming", "nullfang")
		}
	} else {
		baseDir = filepath.Join(home, ".local", "nullfang")
	}
	defaultPatternsDir := filepath.Join(baseDir, "errors")
	err := os.MkdirAll(defaultPatternsDir, 0755)
	if err != nil {
		return err
	}
	return nil
}
