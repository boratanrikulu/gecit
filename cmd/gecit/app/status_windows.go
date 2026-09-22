package app

import (
	"github.com/boratanrikulu/gecit/pkg/capture"
	"github.com/boratanrikulu/gecit/pkg/panel"
)

func platformFacts() []panel.Fact {
	npcap := "not installed, required for DPI bypass (https://npcap.com)"
	if capture.NpcapAvailable() {
		npcap = "installed"
	}

	facts := []panel.Fact{
		{Name: "engine", Value: "tun (wintun)"},
		{Name: "wintun", Value: "embedded in gecit.exe"},
		{Name: "npcap", Value: npcap},
		{Name: "service", Value: serviceStatusLine()},
		{Name: "config", Value: resolveConfigPath()},
		{Name: "log", Value: logFilePath()},
	}

	if err := checkPrivileges(); err != nil {
		facts = append(facts, panel.Fact{Name: "note", Value: "running gecit needs Administrator"})
	}
	return facts
}

func serviceStatusLine() string {
	m, s, err := openServiceForQuery()
	if err != nil {
		return "not installed"
	}
	defer m.Disconnect()
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return "installed, state unavailable"
	}
	return serviceStateName(status.State)
}
