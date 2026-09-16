//go:build !windows

package app

func defaultConfigPath() string { return "/etc/gecit/config.yaml" }
