//go:build darwin || windows

package tun

import (
	"strings"
	"testing"

	singtun "github.com/sagernet/sing-tun"
)

func TestSelectStackNameAuto(t *testing.T) {
	got, err := selectStackName("auto")
	if err != nil {
		t.Fatalf("selectStackName(auto) error = %v", err)
	}

	want := "system"
	if singtun.WithGVisor {
		want = "gvisor"
	}
	if got != want {
		t.Fatalf("selectStackName(auto) = %q, want %q", got, want)
	}
}

func TestSelectStackNameSystem(t *testing.T) {
	got, err := selectStackName("system")
	if err != nil {
		t.Fatalf("selectStackName(system) error = %v", err)
	}
	if got != "system" {
		t.Fatalf("selectStackName(system) = %q, want system", got)
	}
}

func TestSelectStackNameGVisorRequirement(t *testing.T) {
	got, err := selectStackName("gvisor")
	if singtun.WithGVisor {
		if err != nil {
			t.Fatalf("selectStackName(gvisor) error = %v", err)
		}
		if got != "gvisor" {
			t.Fatalf("selectStackName(gvisor) = %q, want gvisor", got)
		}
		return
	}

	if err == nil {
		t.Fatal("selectStackName(gvisor) expected error without with_gvisor build tag")
	}
	if !strings.Contains(err.Error(), "with_gvisor") {
		t.Fatalf("selectStackName(gvisor) error = %v, want with_gvisor hint", err)
	}
}
