//go:build windows

package dns

import (
	"net"
	"testing"
)

func TestValidateWindowsInterfaceNameRejectsUnsafeNames(t *testing.T) {
	for _, iface := range []string{"", "-set", "/x", "=x", "Wi-Fi\nEthernet", "Wi-Fi;calc"} {
		if err := validateWindowsInterfaceName(iface); err == nil {
			t.Fatalf("validateWindowsInterfaceName(%q) succeeded, want error", iface)
		}
	}
}

func TestValidateWindowsInterfaceNameAllowsCommonNames(t *testing.T) {
	for _, iface := range []string{"Wi-Fi", "Ethernet 2", "USB 10/100/1000 LAN", "VPN (Work)/1"} {
		if err := validateWindowsInterfaceName(iface); err != nil {
			t.Fatalf("validateWindowsInterfaceName(%q) returned error: %v", iface, err)
		}
	}
}

func TestIsRestorableDNSServerRejectsUnsafeIPs(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "0.0.0.0", "255.255.255.255", "169.254.1.1", "224.0.0.1", "::1", "::"} {
		if isRestorableDNSServer(mustParseIP(ip)) {
			t.Fatalf("isRestorableDNSServer(%q) = true, want false", ip)
		}
	}
}

func TestIsRestorableDNSServerAllowsCommonResolvers(t *testing.T) {
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "192.168.1.1"} {
		if !isRestorableDNSServer(mustParseIP(ip)) {
			t.Fatalf("isRestorableDNSServer(%q) = false, want true", ip)
		}
	}
}

func mustParseIP(ip string) net.IP {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		panic(ip)
	}
	return parsed
}
