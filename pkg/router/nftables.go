package router

import (
	"fmt"
	"strings"
)

// RuleSet is a dry-run representation of the nftables state router mode needs.
type RuleSet struct {
	TableName string
	Setup     []string
	Teardown  []string
}

// BuildRuleSet renders the nftables commands required for the planned NFQUEUE path.
func BuildRuleSet(cfg Config) (RuleSet, error) {
	cfg = cfg.Normalized()
	if err := cfg.Validate(); err != nil {
		return RuleSet{}, err
	}

	queueChain := "postnat"
	priority := "srcnat + 1"
	if !cfg.EnablePostNAT {
		queueChain = "post"
		priority = "mangle"
	}

	setup := []string{
		fmt.Sprintf("nft add table inet %s", cfg.TableName),
		fmt.Sprintf(`nft 'add chain inet %s %s { type filter hook postrouting priority %s; }'`, cfg.TableName, queueChain, priority),
		fmt.Sprintf(
			`nft add rule inet %s %s oifname %q meta mark and %s == 0 tcp dport %s ct original packets 1-6 queue num %d bypass`,
			cfg.TableName, queueChain, cfg.WANInterface, formatMark(cfg.PacketMark), formatPortSet(cfg.TCPPorts), cfg.QueueNum,
		),
	}

	if cfg.EnableQUIC && len(cfg.UDPPorts) > 0 {
		setup = append(setup, fmt.Sprintf(
			`nft add rule inet %s %s oifname %q meta mark and %s == 0 udp dport %s ct original packets 1-6 queue num %d bypass`,
			cfg.TableName, queueChain, cfg.WANInterface, formatMark(cfg.PacketMark), formatPortSet(cfg.UDPPorts), cfg.QueueNum,
		))
	}

	setup = append(setup,
		fmt.Sprintf(`nft 'add chain inet %s predefrag { type filter hook output priority -401; }'`, cfg.TableName),
		fmt.Sprintf(`nft add rule inet %s predefrag mark and %s != 0 notrack`, cfg.TableName, formatMark(cfg.PacketMark)),
	)

	return RuleSet{
		TableName: cfg.TableName,
		Setup:     setup,
		Teardown:  []string{fmt.Sprintf("nft delete table inet %s", cfg.TableName)},
	}, nil
}

// ShellScript renders the ruleset as a small reusable shell script.
func (r RuleSet) ShellScript() string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("set -eu\n\n")
	b.WriteString("# Setup\n")
	for _, cmd := range r.Setup {
		b.WriteString(cmd)
		b.WriteByte('\n')
	}
	b.WriteString("\n# Teardown\n")
	for _, cmd := range r.Teardown {
		b.WriteString("# ")
		b.WriteString(cmd)
		b.WriteByte('\n')
	}
	return b.String()
}

// SetupBatch renders the setup commands as nft-native statements for `nft -f -`.
func (r RuleSet) SetupBatch() string {
	return renderBatch(r.Setup)
}

// TeardownBatch renders the teardown commands as nft-native statements for `nft -f -`.
func (r RuleSet) TeardownBatch() string {
	return renderBatch(r.Teardown)
}

func renderBatch(commands []string) string {
	var b strings.Builder
	for _, cmd := range commands {
		stmt := nftStatement(cmd)
		if stmt == "" {
			continue
		}
		b.WriteString(stmt)
		b.WriteByte('\n')
	}
	return b.String()
}

func nftStatement(command string) string {
	command = strings.TrimSpace(command)
	command = strings.TrimPrefix(command, "nft ")
	if len(command) >= 2 && command[0] == '\'' && command[len(command)-1] == '\'' {
		command = command[1 : len(command)-1]
	}
	return command
}

func formatPortSet(ports []uint16) string {
	if len(ports) == 1 {
		return fmt.Sprintf("%d", ports[0])
	}

	var b strings.Builder
	b.WriteString("{ ")
	for i, port := range ports {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(fmt.Sprintf("%d", port))
	}
	b.WriteString(" }")
	return b.String()
}

func formatMark(mark uint32) string {
	return fmt.Sprintf("0x%08x", mark)
}
