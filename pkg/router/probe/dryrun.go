package probe

import (
	"fmt"
	"strings"

	"github.com/boratanrikulu/gecit/pkg/router"
)

// DryRun captures the router-mode probe workflow without touching system state.
type DryRun struct {
	QueueNum         uint16
	Targets          []string
	Candidates       []Candidate
	SetupCommands    []string
	TeardownCommands []string
	Steps            []string
}

// BuildDryRun combines router nftables planning with probe candidate selection.
func BuildDryRun(cfg router.Config, plan Plan) (DryRun, error) {
	cfg = cfg.Normalized()
	rules, err := router.BuildRuleSet(cfg)
	if err != nil {
		return DryRun{}, err
	}

	plan = normalizePlan(cfg, plan)

	steps := []string{
		fmt.Sprintf("Install %d nftables setup commands for table %q.", len(rules.Setup), rules.TableName),
		fmt.Sprintf("Queue the first outbound TCP packets on %s through NFQUEUE %d.", joinPorts(cfg.TCPPorts), cfg.QueueNum),
		fmt.Sprintf("Probe %d target domains with %d candidate strategy profiles.", len(plan.Targets), len(plan.Candidates)),
		"Mark generated packets to avoid queue loops and conntrack corruption.",
	}
	if cfg.EnableQUIC {
		steps = append(steps, fmt.Sprintf("Queue outbound UDP packets on %s for QUIC-specific candidate evaluation.", joinPorts(cfg.UDPPorts)))
	} else {
		steps = append(steps, "Keep UDP passthrough until a QUIC strategy is explicitly enabled and validated.")
	}

	return DryRun{
		QueueNum:         plan.QueueNum,
		Targets:          append([]string(nil), plan.Targets...),
		Candidates:       append([]Candidate(nil), plan.Candidates...),
		SetupCommands:    append([]string(nil), rules.Setup...),
		TeardownCommands: append([]string(nil), rules.Teardown...),
		Steps:            steps,
	}, nil
}

// Text renders a human-readable dry-run report.
func (d DryRun) Text() string {
	var b strings.Builder
	b.WriteString("Router probe dry run\n")
	b.WriteString(fmt.Sprintf("Queue: %d\n", d.QueueNum))
	b.WriteString(fmt.Sprintf("Targets: %s\n", strings.Join(d.Targets, ", ")))
	b.WriteString("\nCandidates:\n")
	for _, candidate := range d.Candidates {
		mode := "tcp"
		if candidate.UDP && candidate.TCP {
			mode = "tcp+udp"
		} else if candidate.UDP {
			mode = "udp"
		}
		b.WriteString(fmt.Sprintf("- %s [%s]\n", candidate.Name, mode))
	}
	b.WriteString("\nSetup commands:\n")
	for _, cmd := range d.SetupCommands {
		b.WriteString("- ")
		b.WriteString(cmd)
		b.WriteByte('\n')
	}
	b.WriteString("\nSteps:\n")
	for _, step := range d.Steps {
		b.WriteString("- ")
		b.WriteString(step)
		b.WriteByte('\n')
	}
	b.WriteString("\nTeardown commands:\n")
	for _, cmd := range d.TeardownCommands {
		b.WriteString("- ")
		b.WriteString(cmd)
		b.WriteByte('\n')
	}
	return b.String()
}

func normalizePlan(cfg router.Config, plan Plan) Plan {
	if plan.QueueNum == 0 {
		plan.QueueNum = cfg.QueueNum
	}
	if len(plan.Targets) == 0 {
		plan.Targets = append([]string(nil), cfg.ProbeTargets...)
	}
	if len(plan.Candidates) == 0 {
		plan.Candidates = append([]Candidate(nil), DefaultPlan().Candidates...)
	}
	return plan
}

func joinPorts(ports []uint16) string {
	if len(ports) == 0 {
		return "(none)"
	}
	items := make([]string, len(ports))
	for i, port := range ports {
		items[i] = fmt.Sprintf("%d", port)
	}
	return strings.Join(items, ", ")
}
