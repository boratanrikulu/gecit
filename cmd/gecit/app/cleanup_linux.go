package app

import gecitdns "github.com/boratanrikulu/gecit/pkg/dns"

func platformCleanup() bool {
	if !gecitdns.SystemDNSNeedsRestore() {
		return false
	}
	return gecitdns.RestoreSystemDNS() == nil
}
