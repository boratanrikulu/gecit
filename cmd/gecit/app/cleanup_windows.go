package app

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	gecitdns "github.com/boratanrikulu/gecit/pkg/dns"
	"golang.org/x/sys/windows"
)

func system32Exe(name string) string {
	if dir, err := windows.GetSystemDirectory(); err == nil && dir != "" {
		return filepath.Join(dir, name)
	}
	return filepath.Join(`C:\Windows`, "System32", name)
}

func runRoute(args ...string) ([]byte, error) {
	return exec.Command(system32Exe("route.exe"), args...).CombinedOutput() // #nosec G204 -- fixed System32 binary; route arguments are fixed cleanup commands.
}

func platformCleanup() bool {
	cleaned := false

	// 1. Remove stale TUN routes.
	// Check if gecit routes exist by looking for 0.0.0.0/1 route to TUN IP.
	if out, err := runRoute("print", "0.0.0.0"); err == nil {
		if strings.Contains(string(out), "10.0.85.1") {
			fmt.Println("removing stale routes...")
			deleteRoutes := [][]string{
				{"delete", "0.0.0.0", "mask", "128.0.0.0"},
				{"delete", "128.0.0.0", "mask", "128.0.0.0"},
				{"delete", "1.1.1.1"},
				{"delete", "8.8.8.8"},
			}
			for _, args := range deleteRoutes {
				if out, err := runRoute(args...); err != nil {
					fmt.Printf("failed to remove route: %s: %v\n", strings.TrimSpace(string(out)), err)
				}
			}
			cleaned = true
		}
	}

	// 2. Restore DNS.
	if gecitdns.HasSystemDNSBackup() {
		fmt.Println("restoring DNS...")
		if err := gecitdns.RestoreSystemDNS(); err != nil {
			fmt.Printf("failed to restore DNS: %v\n", err)
		} else {
			cleaned = true
		}
	}

	return cleaned
}
