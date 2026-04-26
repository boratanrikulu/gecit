package app

import (
	"fmt"
	"os/exec"
	"strings"

	gecitdns "github.com/boratanrikulu/gecit/pkg/dns"
)

func platformCleanup() bool {
	cleaned := false

	if gecitdns.HasSystemDNSBackup() {
		fmt.Println("restoring DNS...")
		if err := gecitdns.RestoreSystemDNS(); err != nil {
			fmt.Printf("failed to restore DNS: %v\n", err)
		} else {
			cleaned = true
		}
	}

	if out, err := exec.Command("/usr/sbin/networksetup", "-getdnsservers", "Wi-Fi").CombinedOutput(); err == nil {
		if strings.TrimSpace(string(out)) == "127.0.0.1" {
			fmt.Println("resetting DNS to DHCP...")
			if out, err := exec.Command("/usr/sbin/networksetup", "-setdnsservers", "Wi-Fi", "empty").CombinedOutput(); err != nil {
				fmt.Printf("failed to reset DNS: %s: %v\n", strings.TrimSpace(string(out)), err)
			} else {
				cleaned = true
			}
		}
	}

	if cleaned {
		if out, err := exec.Command("/usr/bin/killall", "-HUP", "mDNSResponder").CombinedOutput(); err != nil {
			fmt.Printf("failed to refresh DNS cache: %s: %v\n", strings.TrimSpace(string(out)), err)
		}
	}

	return cleaned
}
