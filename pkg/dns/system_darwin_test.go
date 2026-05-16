//go:build darwin

package dns

import "testing"

func TestValidateServiceRejectsUnsafeNames(t *testing.T) {
	for _, svc := range []string{"", "-setdnsservers", "/tmp/x", "Wi-Fi\nEthernet", "Wi-Fi;id"} {
		if err := validateService(svc); err == nil {
			t.Fatalf("validateService(%q) succeeded, want error", svc)
		}
	}
}

func TestValidateServiceAllowsCommonNames(t *testing.T) {
	for _, svc := range []string{"Wi-Fi", "USB 10/100/1000 LAN", "Thunderbolt Bridge", "VPN (Work)/1"} {
		if err := validateService(svc); err != nil {
			t.Fatalf("validateService(%q) returned error: %v", svc, err)
		}
	}
}
