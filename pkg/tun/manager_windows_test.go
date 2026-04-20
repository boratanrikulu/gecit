//go:build windows

package tun

import (
	"net"
	"testing"
)

func TestInterfaceNameByIndexPrefersUsableInterface(t *testing.T) {
	ifaces := []net.Interface{
		{Index: 22, Name: "vEthernet (Default Switch)", Flags: net.FlagUp | net.FlagBroadcast | net.FlagMulticast},
		{Index: 4, Name: "Wi-Fi", Flags: net.FlagUp | net.FlagBroadcast | net.FlagMulticast | net.FlagRunning},
	}

	if got := interfaceNameByIndex(ifaces, 4); got != "Wi-Fi" {
		t.Fatalf("interfaceNameByIndex(..., 4) = %q, want Wi-Fi", got)
	}
}

func TestInterfaceNameByIndexRejectsVirtualInterfaces(t *testing.T) {
	ifaces := []net.Interface{
		{Index: 22, Name: "vEthernet (Default Switch)", Flags: net.FlagUp | net.FlagBroadcast | net.FlagMulticast},
	}

	if got := interfaceNameByIndex(ifaces, 22); got != "" {
		t.Fatalf("interfaceNameByIndex(..., 22) = %q, want empty for virtual interface", got)
	}
}

func TestIsVirtualInterfaceName(t *testing.T) {
	tests := map[string]bool{
		"Wi-Fi":                      false,
		"Ethernet":                   false,
		"vEthernet (Default Switch)": true,
		"Wintun Userspace Tunnel":    true,
		"tailscale0":                 true,
	}

	for name, want := range tests {
		if got := isVirtualInterfaceName(name); got != want {
			t.Fatalf("isVirtualInterfaceName(%q) = %v, want %v", name, got, want)
		}
	}
}
