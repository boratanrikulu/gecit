package app

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func platformCleanup() bool {
	cleaned := false

	if data, err := os.ReadFile("/var/run/gecit-dns-backup"); err == nil {
		lines := strings.SplitN(string(data), "\n", 3)
		svc := "Wi-Fi"
		if len(lines) >= 2 && strings.TrimSpace(lines[1]) != "" {
			svc = strings.TrimSpace(lines[1])
		}

		prev := strings.TrimSpace(lines[0])
		fmt.Printf("restoring DNS for %s...\n", svc)
		if prev == "" || prev == "empty" || strings.Contains(prev, "aren't any") {
			exec.Command("networksetup", "-setdnsservers", svc, "empty").CombinedOutput()
		} else {
			args := append([]string{"-setdnsservers", svc}, strings.Fields(prev)...)
			exec.Command("networksetup", args...).CombinedOutput()
		}
		os.Remove("/var/run/gecit-dns-backup")
		cleaned = true
	}

	if out, err := exec.Command("networksetup", "-getdnsservers", "Wi-Fi").CombinedOutput(); err == nil {
		if strings.TrimSpace(string(out)) == "127.0.0.1" {
			fmt.Println("resetting DNS to DHCP...")
			exec.Command("networksetup", "-setdnsservers", "Wi-Fi", "empty").CombinedOutput()
			cleaned = true
		}
	}

	if cleaned {
		exec.Command("killall", "-HUP", "mDNSResponder").CombinedOutput()
	}

	return cleaned
}
