package app

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

func platformCleanup() bool {
	cleaned := false

	// 1. Remove stale TUN routes.
	// Check if gecit routes exist by looking for 0.0.0.0/1 route to TUN IP.
	if out, err := exec.Command("route", "print", "0.0.0.0").CombinedOutput(); err == nil {
		if strings.Contains(string(out), "10.0.85.1") {
			fmt.Println("removing stale routes...")
			exec.Command("route", "delete", "0.0.0.0", "mask", "128.0.0.0").CombinedOutput()
			exec.Command("route", "delete", "128.0.0.0", "mask", "128.0.0.0").CombinedOutput()
			exec.Command("route", "delete", "1.1.1.1").CombinedOutput()
			exec.Command("route", "delete", "8.8.8.8").CombinedOutput()
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
		if prev == "" || prev == "dhcp" || net.ParseIP(prev) == nil {
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
