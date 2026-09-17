package dns

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var breadcrumbFileWin = filepath.Join(os.Getenv("ProgramData"), "gecit-dns-backup")
var savedInterface string

func SetSystemDNS(_ ...string) error {
	iface, err := detectWindowsInterface()
	if err != nil {
		return fmt.Errorf("detect interface: %w", err)
	}
	savedInterface = iface

	if data, err := os.ReadFile(breadcrumbFileWin); err == nil {
		lines := strings.SplitN(string(data), "\n", 2)
		if len(lines) >= 2 {
			prev := strings.TrimSpace(lines[0])
			prevIface := strings.TrimSpace(lines[1])
			if prev != "" && prev != "127.0.0.1" && prevIface != "" {
				if prev == "dhcp" || net.ParseIP(prev) == nil {
					exec.Command("netsh", "interface", "ip", "set", "dns", prevIface, "dhcp").CombinedOutput()
				} else {
					exec.Command("netsh", "interface", "ip", "set", "dns", prevIface, "static", prev).CombinedOutput()
				}
			}
		}
	}

	currentDNS := getCurrentDNS(iface)
	os.WriteFile(breadcrumbFileWin, []byte(currentDNS+"\n"+iface+"\n"), 0644)

	out, err := exec.Command("netsh", "interface", "ip", "set", "dns", iface, "static", "127.0.0.1").CombinedOutput()
	if err != nil {
		return fmt.Errorf("set DNS: %s: %w", strings.TrimSpace(string(out)), err)
	}

	exec.Command("ipconfig", "/flushdns").CombinedOutput()
	return nil
}

func RestoreSystemDNS(_ ...string) error {
	data, err := os.ReadFile(breadcrumbFileWin)
	if err != nil {
		iface := savedInterface
		if iface == "" {
			iface, _ = detectWindowsInterface()
		}
		if iface != "" {
			exec.Command("netsh", "interface", "ip", "set", "dns", iface, "dhcp").CombinedOutput()
		}
		return nil
	}

	lines := strings.SplitN(string(data), "\n", 2)
	prev := "dhcp"
	iface := savedInterface
	if len(lines) >= 1 {
		prev = strings.TrimSpace(lines[0])
	}
	if len(lines) >= 2 && strings.TrimSpace(lines[1]) != "" {
		iface = strings.TrimSpace(lines[1])
	}

	// A breadcrumb that does not hold an IP is a corrupt one, and its contents
	// become netsh arguments. DHCP is the safe reading.
	if prev == "" || prev == "dhcp" || net.ParseIP(prev) == nil {
		exec.Command("netsh", "interface", "ip", "set", "dns", iface, "dhcp").CombinedOutput()
	} else {
		exec.Command("netsh", "interface", "ip", "set", "dns", iface, "static", prev).CombinedOutput()
	}

	exec.Command("ipconfig", "/flushdns").CombinedOutput()
	os.Remove(breadcrumbFileWin)
	return nil
}

func getCurrentDNS(iface string) string {
	out, err := exec.Command("netsh", "interface", "ip", "show", "dns", iface).CombinedOutput()
	if err != nil {
		return "dhcp"
	}
	for _, line := range strings.Split(string(out), "\n") {
		for _, p := range strings.Fields(strings.TrimSpace(line)) {
			if ip := net.ParseIP(p); ip != nil && !ip.IsLoopback() {
				return p
			}
		}
	}
	return "dhcp"
}

func detectWindowsInterface() (string, error) {
	out, err := exec.Command("netsh", "interface", "show", "interface").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("netsh: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Connected") && !strings.Contains(line, "Loopback") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				return strings.Join(fields[3:], " "), nil
			}
		}
	}
	return "", fmt.Errorf("no connected network interface found")
}
