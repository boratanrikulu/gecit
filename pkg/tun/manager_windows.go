//go:build windows

package tun

import (
	"net"

	"golang.org/x/sys/windows"
)

var windowsRouteProbeAddrs = [][4]byte{
	{1, 1, 1, 1},
	{8, 8, 8, 8},
}

func detectWindowsPhysicalInterface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	return detectWindowsBestRouteInterface(ifaces)
}

func detectWindowsBestRouteInterface(ifaces []net.Interface) string {
	for _, addr := range windowsRouteProbeAddrs {
		sockaddr := &windows.SockaddrInet4{Addr: addr}
		var index uint32
		if err := windows.GetBestInterfaceEx(sockaddr, &index); err != nil || index == 0 {
			continue
		}
		if name := interfaceNameByIndex(ifaces, int(index)); name != "" {
			return name
		}
	}
	return ""
}

func interfaceNameByIndex(ifaces []net.Interface, index int) string {
	for _, iface := range ifaces {
		if iface.Index != index {
			continue
		}
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			return ""
		}
		if isVirtualInterfaceName(iface.Name) {
			return ""
		}
		return iface.Name
	}
	return ""
}
