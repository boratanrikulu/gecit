package dns

import (
	"fmt"
	"os"
	"strings"
)

const resolvConf = "/etc/resolv.conf"

// SetSystemDNS comments out existing nameservers and adds 127.0.0.1.
// Original lines are preserved as "# gecit-saved: ..." so they survive
// a crash — RestoreSystemDNS (or manual edit) can recover them.
func SetSystemDNS() error {
	orig, err := os.ReadFile(resolvConf)
	if err != nil {
		return fmt.Errorf("read %s: %w", resolvConf, err)
	}

	var lines []string
	lines = append(lines, "# gecit: DoH DNS active — original lines commented below")
	lines = append(lines, "nameserver 127.0.0.1")

	for _, line := range strings.Split(string(orig), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "# gecit") {
			continue
		}
		if strings.HasPrefix(trimmed, "nameserver") {
			lines = append(lines, "# gecit-saved: "+trimmed)
		} else {
			lines = append(lines, line)
		}
	}

	return os.WriteFile(resolvConf, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

// RestoreSystemDNS uncomments the original nameservers and removes gecit lines.
func RestoreSystemDNS() error {
	data, err := os.ReadFile(resolvConf)
	if err != nil {
		return err
	}

	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "# gecit-saved: ") {
			// Restore the original line.
			lines = append(lines, strings.TrimPrefix(trimmed, "# gecit-saved: "))
		} else if strings.HasPrefix(trimmed, "# gecit") {
			continue // remove gecit marker
		} else if trimmed == "nameserver 127.0.0.1" {
			continue // remove our nameserver
		} else if trimmed != "" {
			lines = append(lines, line)
		}
	}

	if len(lines) == 0 {
		lines = append(lines, "nameserver 8.8.8.8") // safe fallback
	}

	return os.WriteFile(resolvConf, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}
