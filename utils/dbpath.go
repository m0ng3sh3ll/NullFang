package utils

import (
	"os"
	"path/filepath"
	"runtime"
)

func GetDefaultDBPath() string {
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
	err := os.MkdirAll(baseDir, 0755)
	if err != nil {
		// Se não conseguir criar o diretório, retorna um caminho padrão
		// O erro será tratado quando tentar criar o banco de dados
		return filepath.Join(home, "nullfang.db")
	}
	return filepath.Join(baseDir, "nfdb.db")
}
