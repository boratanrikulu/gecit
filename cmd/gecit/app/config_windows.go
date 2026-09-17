package app

import (
	"os"
	"path/filepath"
)

func gecitDataDir() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, "gecit")
}

func defaultConfigPath() string { return filepath.Join(gecitDataDir(), "config.yaml") }
