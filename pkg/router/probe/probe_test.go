package probe

import (
	"strings"
	"testing"

	"github.com/boratanrikulu/gecit/pkg/router"
)

func TestBuildDryRunUsesConfigDefaults(t *testing.T) {
	cfg := router.DefaultConfig()
	cfg.WANInterface = "wan"

	dryRun, err := BuildDryRun(cfg, Plan{})
	if err != nil {
		t.Fatalf("BuildDryRun() error = %v", err)
	}

	if dryRun.QueueNum != 200 {
		t.Fatalf("QueueNum = %d, want 200", dryRun.QueueNum)
	}
	if len(dryRun.Targets) != 2 {
		t.Fatalf("Targets = %v, want 2 items", dryRun.Targets)
	}
	if len(dryRun.Candidates) == 0 {
		t.Fatal("expected at least one candidate")
	}
}

func TestDryRunText(t *testing.T) {
	cfg := router.DefaultConfig()
	cfg.WANInterface = "wan"
	cfg.EnableQUIC = true

	dryRun, err := BuildDryRun(cfg, Plan{
		Targets: []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("BuildDryRun() error = %v", err)
	}

	text := dryRun.Text()
	if !strings.Contains(text, "Router probe dry run") {
		t.Fatalf("missing title: %s", text)
	}
	if !strings.Contains(text, "example.com") {
		t.Fatalf("missing target: %s", text)
	}
	if !strings.Contains(text, "udp") {
		t.Fatalf("expected UDP mention when QUIC is enabled: %s", text)
	}
}
