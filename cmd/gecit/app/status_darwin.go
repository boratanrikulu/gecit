package app

import (
	"os"

	"github.com/boratanrikulu/gecit/pkg/panel"
)

func platformFacts() []panel.Fact {
	facts := []panel.Fact{{Name: "engine", Value: "tun"}}

	if os.Geteuid() != 0 {
		return append(facts, panel.Fact{Name: "note", Value: "run with sudo for accurate capability detection"})
	}
	return append(facts, panel.Fact{Name: "raw socket", Value: "available"})
}
