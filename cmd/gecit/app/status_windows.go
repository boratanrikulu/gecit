package app

import (
	"fmt"

	singtun "github.com/sagernet/sing-tun"
)

func printPlatformStatus() {
	fmt.Printf("  engine:     tun (wintun)\n")
	if singtun.WithGVisor {
		fmt.Printf("  tun stack:  gvisor (default), system/mixed available\n")
	} else {
		fmt.Printf("  tun stack:  system (default), gvisor not built in\n")
	}

	if err := checkPrivileges(); err != nil {
		fmt.Printf("  (run as Administrator for accurate capability detection)\n")
		return
	}

	fmt.Printf("  wintun:     available\n")
	fmt.Printf("  injection:  available\n")
}
