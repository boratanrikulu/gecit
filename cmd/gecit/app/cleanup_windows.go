package app

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func platformCleanup() bool {
	cleaned := false

	// 1. Remove stale TUN routes.
	if out, err := exec.Command("route", "print", "0.0.0.0").CombinedOutput(); err == nil {
		if commands := staleRouteDeleteCommands(string(out)); len(commands) > 0 {
			fmt.Println("removing stale routes...")
			for _, args := range commands {
				exec.Command(args[0], args[1:]...).CombinedOutput()
			}
			cleaned = true
		}
	}

	// 2. Restore DNS.
	breadcrumb := os.Getenv("ProgramData") + `\gecit-dns-backup`
	if data, err := os.ReadFile(breadcrumb); err == nil {
		lines := strings.SplitN(string(data), "\n", 2)
		prev := strings.TrimSpace(lines[0])
		iface := "Ethernet"
		if len(lines) >= 2 && strings.TrimSpace(lines[1]) != "" {
			iface = strings.TrimSpace(lines[1])
		}

		fmt.Printf("restoring DNS for %s...\n", iface)
		if prev == "" || prev == "dhcp" {
			exec.Command("netsh", "interface", "ip", "set", "dns", iface, "dhcp").CombinedOutput()
		} else {
			exec.Command("netsh", "interface", "ip", "set", "dns", iface, "static", prev).CombinedOutput()
		}
		exec.Command("ipconfig", "/flushdns").CombinedOutput()
		os.Remove(breadcrumb)
		cleaned = true
	}

	return cleaned
}

func staleRouteDeleteCommands(routePrint string) [][]string {
	if !strings.Contains(routePrint, "10.0.85.1") && !strings.Contains(routePrint, "10.0.85.2") {
		return nil
	}

	return [][]string{
		{"route", "delete", "0.0.0.0", "mask", "0.0.0.0", "10.0.85.2"},
		{"route", "delete", "0.0.0.0", "mask", "128.0.0.0"},
		{"route", "delete", "128.0.0.0", "mask", "128.0.0.0"},
		{"route", "delete", "1.1.1.1"},
		{"route", "delete", "8.8.8.8"},
	}
}
