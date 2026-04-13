package app

import (
	"fmt"
	"os"

	singtun "github.com/sagernet/sing-tun"
)

func printPlatformStatus() {
	fmt.Printf("  engine:     tun\n")
	if singtun.WithGVisor {
		fmt.Printf("  tun stack:  gvisor (default), system/mixed available\n")
	} else {
		fmt.Printf("  tun stack:  system (default), gvisor not built in\n")
	}

	if os.Geteuid() != 0 {
		fmt.Printf("  (run with sudo for accurate capability detection)\n")
		return
	}

	fmt.Printf("  raw socket: available\n")
}
