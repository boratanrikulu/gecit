package router

import "testing"

func TestConfigNormalized(t *testing.T) {
	cfg := Config{
		WANInterface: " wan ",
		ProbeTargets: []string{" discord.com ", "", "youtube.com"},
	}.Normalized()

	if cfg.TableName != "gecit_router" {
		t.Fatalf("TableName = %q, want gecit_router", cfg.TableName)
	}
	if cfg.QueueNum != 200 {
		t.Fatalf("QueueNum = %d, want 200", cfg.QueueNum)
	}
	if cfg.WANInterface != "wan" {
		t.Fatalf("WANInterface = %q, want wan", cfg.WANInterface)
	}
	if len(cfg.ProbeTargets) != 2 {
		t.Fatalf("ProbeTargets = %v, want 2 items", cfg.ProbeTargets)
	}
}

func TestConfigValidate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WANInterface = "wan"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestConfigValidateAcceptsDryRunBackend(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WANInterface = "wan"
	cfg.Backend = QueueBackendDryRun

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestConfigValidateRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "missing wan",
			cfg:  DefaultConfig(),
		},
		{
			name: "bad table",
			cfg: Config{
				WANInterface: "wan",
				TableName:    "bad-table",
			},
		},
		{
			name: "bad ttl",
			cfg: Config{
				WANInterface: "wan",
				FakeTTL:      300,
			},
		},
		{
			name: "bad port",
			cfg: Config{
				WANInterface: "wan",
				TCPPorts:     []uint16{0},
			},
		},
	}

	for _, tt := range tests {
		if err := tt.cfg.Validate(); err == nil {
			t.Fatalf("%s: expected validation error", tt.name)
		}
	}
}
