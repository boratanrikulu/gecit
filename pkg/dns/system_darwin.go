package dns

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

const breadcrumbFile = "/tmp/gecit-dns-backup"

var savedDNS string
var savedService string

// StopMDNSResponder unloads mDNSResponder from launchd so it releases port 53
// and doesn't respawn. ResumeMDNSResponder loads it back.
func StopMDNSResponder() {
	// Kill mDNSResponder repeatedly until port 53 is free.
	// launchd respawns it, so we keep killing until we can bind.
	for i := 0; i < 10; i++ {
		exec.Command("killall", "mDNSResponder").CombinedOutput()
		time.Sleep(200 * time.Millisecond)

		// Check if port 53 is free.
		conn, err := net.ListenPacket("udp", "127.0.0.1:53")
		if err == nil {
			conn.Close()
			return // port is free
		}
	}
}

// ResumeMDNSResponder sends a HUP to restart mDNSResponder cleanly.
// If it was killed, launchd will have already respawned it.
func ResumeMDNSResponder() {
	exec.Command("killall", "-HUP", "mDNSResponder").CombinedOutput()
}

// SetSystemDNS sets macOS system DNS to 127.0.0.1 via networksetup.
// Saves the current DNS servers so they can be restored on stop.
// If gecit crashes, the user can restore with:
//
//	networksetup -setdnsservers Wi-Fi empty
func SetSystemDNS(networkService ...string) error {
	svc := "Wi-Fi"
	if len(networkService) > 0 && networkService[0] != "" {
		svc = networkService[0]
	}
	savedService = svc

	// If breadcrumb exists from a previous crash, restore first.
	if data, err := os.ReadFile(breadcrumbFile); err == nil {
		prev := strings.TrimSpace(string(data))
		if prev != "" && prev != "127.0.0.1" {
			parts := strings.Fields(prev)
			args := append([]string{"-setdnsservers", svc}, parts...)
			exec.Command("networksetup", args...).CombinedOutput()
		}
	}

	// Save current DNS servers to breadcrumb file + memory.
	out, err := exec.Command("networksetup", "-getdnsservers", svc).CombinedOutput()
	if err == nil {
		savedDNS = strings.TrimSpace(string(out))
		// Write breadcrumb so we can recover from crashes.
		content := savedDNS
		if strings.Contains(savedDNS, "aren't any") {
			content = "empty"
		}
		os.WriteFile(breadcrumbFile, []byte(content+"\n"+svc+"\n"), 0644)
	}

	out, err = exec.Command("networksetup", "-setdnsservers", svc, "127.0.0.1").CombinedOutput()
	if err != nil {
		return fmt.Errorf("set DNS: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// RestoreSystemDNS restores macOS DNS to the original servers (or DHCP if none).
func RestoreSystemDNS(networkService ...string) error {
	svc := savedService
	if svc == "" {
		svc = "Wi-Fi"
	}
	if len(networkService) > 0 && networkService[0] != "" {
		svc = networkService[0]
	}

	// Restore saved DNS servers, or "empty" for DHCP.
	args := []string{"-setdnsservers", svc}
	if savedDNS != "" && !strings.Contains(savedDNS, "aren't any") {
		// Saved DNS was explicit servers (e.g., "8.8.8.8\n8.8.4.4").
		for _, server := range strings.Fields(savedDNS) {
			args = append(args, server)
		}
	} else {
		args = append(args, "empty") // DHCP
	}

	exec.Command("networksetup", args...).CombinedOutput()

	// Resume mDNSResponder (was paused during our run).
	ResumeMDNSResponder()

	// Remove breadcrumb — clean shutdown.
	os.Remove(breadcrumbFile)
	return nil
}
