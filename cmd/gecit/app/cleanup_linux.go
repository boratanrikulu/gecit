package app

import (
	"fmt"

	gecitdns "github.com/boratanrikulu/gecit/pkg/dns"
)

func platformCleanup() bool {
	if !gecitdns.HasSystemDNSBackup() {
		return false
	}
	fmt.Println("restoring Linux DNS...")
	if err := gecitdns.RestoreSystemDNS(); err != nil {
		fmt.Printf("failed to restore DNS: %v\n", err)
		return false
	}
	return true
}
