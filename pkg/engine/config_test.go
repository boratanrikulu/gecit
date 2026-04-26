package engine

import "testing"

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	tests := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"MSS", cfg.MSS, 88},
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
