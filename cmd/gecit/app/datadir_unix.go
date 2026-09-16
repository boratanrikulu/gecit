//go:build !windows

package app

import (
	"fmt"
	"os"
)

func createDataDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	return nil
}
