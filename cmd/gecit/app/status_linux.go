package app

import (
	"os"

	bpf "github.com/boratanrikulu/gecit/pkg/ebpf"
	"github.com/boratanrikulu/gecit/pkg/panel"
)

func platformFacts() []panel.Fact {
	facts := []panel.Fact{{Name: "engine", Value: "ebpf-sockops"}}

	if os.Geteuid() != 0 {
		return append(facts, panel.Fact{Name: "note", Value: "run with sudo for accurate capability detection"})
	}
	return append(facts,
		panel.Fact{Name: "sock_ops", Value: boolStatus(bpf.HaveSockOps())},
		panel.Fact{Name: "setsockopt", Value: boolStatus(bpf.HaveSockOpsSetsockopt())},
	)
}
