package app

import (
	"fmt"

	"github.com/boratanrikulu/gecit/pkg/capture"
)

func printPlatformStatus() {
	fmt.Printf("  engine:     tun (wintun)\n")
	fmt.Printf("  wintun:     embedded in gecit.exe\n")

	if capture.NpcapAvailable() {
		fmt.Printf("  npcap:      installed\n")
	} else {
		fmt.Printf("  npcap:      not installed, required for DPI bypass (https://npcap.com)\n")
	}

	fmt.Printf("  service:    %s\n", serviceStatusLine())
	fmt.Printf("  config:     %s\n", resolveConfigPath())
	fmt.Printf("  log:        %s\n", logFilePath())

	if err := checkPrivileges(); err != nil {
		fmt.Printf("  (running gecit needs Administrator)\n")
	}
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
