package engine

import (
	"fmt"
	"strings"

	gecitdns "github.com/boratanrikulu/gecit/pkg/dns"
)

type Config struct {
	MSS               int      `yaml:"mss" mapstructure:"mss"`
	RestoreMSS        int      `yaml:"restore_mss" mapstructure:"restore_mss"`
	RestoreAfterBytes int      `yaml:"restore_after_bytes" mapstructure:"restore_after_bytes"`
	Ports             []uint16 `yaml:"ports" mapstructure:"ports"`
	Interface         string   `yaml:"interface" mapstructure:"interface"`
	CgroupPath        string   `yaml:"cgroup_path" mapstructure:"cgroup_path"`
	FakeTTL           int      `yaml:"fake_ttl" mapstructure:"fake_ttl"`
	DoHEnabled        bool     `yaml:"doh_enabled" mapstructure:"doh_enabled"`
	DoHUpstream       string   `yaml:"doh_upstream" mapstructure:"doh_upstream"`
}

func DefaultConfig() Config {
	return Config{
		MSS:               40,
		RestoreMSS:        0,
		RestoreAfterBytes: 600,
		Ports:             []uint16{443},
		CgroupPath:        "/sys/fs/cgroup",
		FakeTTL:           8,
		DoHEnabled:        true,
		DoHUpstream:       "cloudflare",
	}
}

func (c Config) Validate() error {
	if c.MSS < 1 || c.MSS > 65535 {
		return fmt.Errorf("mss must be between 1 and 65535, got %d", c.MSS)
	}
	if c.RestoreMSS < 0 || c.RestoreMSS > 65535 {
		return fmt.Errorf("restore_mss must be between 0 and 65535, got %d", c.RestoreMSS)
	}
	if c.RestoreAfterBytes < 1 {
		return fmt.Errorf("restore_after_bytes must be >= 1, got %d", c.RestoreAfterBytes)
	}
	if len(c.Ports) == 0 {
		return fmt.Errorf("at least one target port is required")
	}
	for _, port := range c.Ports {
		if port == 0 {
			return fmt.Errorf("port 0 is not valid")
		}
	}
	if c.FakeTTL < 1 || c.FakeTTL > 255 {
		return fmt.Errorf("fake_ttl must be between 1 and 255, got %d", c.FakeTTL)
	}
	if c.DoHEnabled {
		if strings.TrimSpace(c.DoHUpstream) == "" {
			return fmt.Errorf("doh_upstream is required when DoH is enabled")
		}
		if err := gecitdns.ValidateUpstreams(c.DoHUpstream); err != nil {
			return err
		}
	}
	return nil
}
