package router

import (
	"strings"
	"testing"
)

func TestBuildRuleSetPostNAT(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WANInterface = "wan"

	rules, err := BuildRuleSet(cfg)
	if err != nil {
		t.Fatalf("BuildRuleSet() error = %v", err)
	}

	text := strings.Join(rules.Setup, "\n")
	if !strings.Contains(text, "postnat") {
		t.Fatalf("setup missing postnat chain: %s", text)
	}
	if !strings.Contains(text, `oifname "wan"`) {
		t.Fatalf("setup missing wan interface: %s", text)
	}
	if !strings.Contains(text, "queue num 200") {
		t.Fatalf("setup missing queue number: %s", text)
	}
	if !strings.Contains(text, "notrack") {
		t.Fatalf("setup missing mark/notrack rule: %s", text)
	}
	if strings.Contains(text, "udp dport") {
		t.Fatalf("udp rule should not render while QUIC is disabled: %s", text)
	}
}

func TestBuildRuleSetQUICAndShellScript(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WANInterface = "pppoe-wan"
	cfg.EnableQUIC = true
	cfg.EnablePostNAT = false
	cfg.TCPPorts = []uint16{80, 443}
	cfg.UDPPorts = []uint16{443}

	rules, err := BuildRuleSet(cfg)
	if err != nil {
		t.Fatalf("BuildRuleSet() error = %v", err)
	}

	text := strings.Join(rules.Setup, "\n")
	if !strings.Contains(text, "priority mangle") {
		t.Fatalf("expected mangle priority when postnat is disabled: %s", text)
	}
	if !strings.Contains(text, "udp dport 443") {
		t.Fatalf("expected udp rule when QUIC is enabled: %s", text)
	}
	if !strings.Contains(text, "{ 80, 443 }") {
		t.Fatalf("expected tcp port set rendering: %s", text)
	}

	script := rules.ShellScript()
	if !strings.Contains(script, "#!/bin/sh") || !strings.Contains(script, "# Teardown") {
		t.Fatalf("unexpected shell script: %s", script)
	}

	setupBatch := rules.SetupBatch()
	if strings.Contains(setupBatch, "nft add") {
		t.Fatalf("setup batch should contain nft-native statements, got: %s", setupBatch)
	}
	if !strings.Contains(setupBatch, "add table inet gecit_router") {
		t.Fatalf("setup batch missing add table statement: %s", setupBatch)
	}
}
