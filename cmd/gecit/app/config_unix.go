//go:build !windows

package app

import "path/filepath"

func gecitDataDir() string { return "/etc/gecit" }

func defaultConfigPath() string { return filepath.Join(gecitDataDir(), "config.yaml") }
