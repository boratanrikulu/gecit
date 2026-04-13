package engine

import (
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	tests := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"MSS", cfg.MSS, 40},
		{"RestoreMSS", cfg.RestoreMSS, 0},
		{"RestoreAfterBytes", cfg.RestoreAfterBytes, 600},
		{"FakeTTL", cfg.FakeTTL, 8},
		{"DoHEnabled", cfg.DoHEnabled, true},
		{"DoHUpstream", cfg.DoHUpstream, "cloudflare"},
		{"CgroupPath", cfg.CgroupPath, "/sys/fs/cgroup"},
	}

	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, tt.got, tt.want)
		}
	}

	if len(cfg.Ports) != 1 || cfg.Ports[0] != 443 {
		t.Errorf("Ports: got %v, want [443]", cfg.Ports)
	}
}

func TestConfigValidate(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestConfigValidateRejectsInvalidTTL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FakeTTL = 0

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected invalid TTL to fail validation")
	}
	if !strings.Contains(err.Error(), "fake_ttl") {
		t.Fatalf("expected fake_ttl error, got %v", err)
	}
}

func TestConfigValidateRejectsUnsafeDoHUpstream(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DoHUpstream = "https://user:pass@example.com/dns-query"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected invalid DoH upstream to fail validation")
	}
	if !strings.Contains(err.Error(), "userinfo") {
		t.Fatalf("expected userinfo error, got %v", err)
	}
}
