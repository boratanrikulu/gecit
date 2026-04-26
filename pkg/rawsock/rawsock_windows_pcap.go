//go:build windows && cgo

package rawsock

import (
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/gopacket/pcap"
	"golang.org/x/sys/windows"
)

type pcapRawSocket struct {
	handle *pcap.Handle
	srcMAC net.HardwareAddr
	dstMAC net.HardwareAddr
}

func New(iface string) (RawSocket, error) {
	pcapDev, err := resolvePcapDevice(iface)
	if err != nil {
		return nil, fmt.Errorf("resolve pcap device for %s: %w", iface, err)
	}

	handle, err := pcap.OpenLive(pcapDev, 0, false, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("pcap open %s: %w (is Npcap installed?)", iface, err)
	}

	srcMAC, dstMAC, err := discoverMACs(iface)
	if err != nil {
		handle.Close()
		return nil, err
	}

	return &pcapRawSocket{handle: handle, srcMAC: srcMAC, dstMAC: dstMAC}, nil
}

func (s *pcapRawSocket) SendFake(conn ConnInfo, payload []byte, ttl int) error {
	if err := ValidatePacketInput(conn, ttl); err != nil {
		return err
	}
	ipTcp, err := BuildPacket(conn, payload, ttl)
	if err != nil {
		return err
	}
	if isZeroMAC(s.srcMAC) || isZeroMAC(s.dstMAC) || isBroadcastMAC(s.dstMAC) {
		return fmt.Errorf("refusing to send fake packet without resolved unicast MACs")
	}

	frame := make([]byte, 14+len(ipTcp))
	copy(frame[0:6], s.dstMAC)
	copy(frame[6:12], s.srcMAC)
	frame[12] = 0x08
	frame[13] = 0x00
	copy(frame[14:], ipTcp)

	return s.handle.WritePacketData(frame)
}

func (s *pcapRawSocket) Close() error {
	s.handle.Close()
	return nil
}

// discoverMACs finds the local NIC MAC and gateway MAC from the ARP table.
func windowsSystem32Exe(name string) string {
	if dir, err := windows.GetSystemDirectory(); err == nil && dir != "" {
		return filepath.Join(dir, name)
	}
	return filepath.Join(`C:\Windows`, "System32", name)
}

func discoverMACs(ifaceName string) (srcMAC, dstMAC net.HardwareAddr, err error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
		return nil, nil, fmt.Errorf("interface %s has no usable hardware address", ifaceName)
	}
	srcMAC = iface.HardwareAddr

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("interface addresses for %s: %w", ifaceName, err)
	}
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok {
			if ipv4 := ipNet.IP.To4(); ipv4 != nil && !ipv4.IsLoopback() && !ipv4.Equal(net.IPv4(10, 0, 85, 1)) {
				if gwMAC := gatewayMAC(ipv4); gwMAC != nil {
					if isZeroMAC(gwMAC) || isBroadcastMAC(gwMAC) {
						return nil, nil, fmt.Errorf("gateway MAC for %s is not unicast", ipv4)
					}
					return srcMAC, gwMAC, nil
				}
				return nil, nil, fmt.Errorf("gateway MAC not found for interface %s", ifaceName)
			}
		}
	}
	return nil, nil, fmt.Errorf("no usable IPv4 address on interface %s", ifaceName)
}

func isZeroMAC(mac net.HardwareAddr) bool {
	if len(mac) == 0 {
		return true
	}
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}

func isBroadcastMAC(mac net.HardwareAddr) bool {
	if len(mac) == 0 {
		return false
	}
	for _, b := range mac {
		if b != 0xff {
			return false
		}
	}
	return true
}

// gatewayMAC finds the default gateway's MAC address from the ARP table.
func gatewayMAC(localIP net.IP) net.HardwareAddr {
	// Find default gateway IP.
	out, err := exec.Command(windowsSystem32Exe("route.exe"), "print", "0.0.0.0").CombinedOutput()
	if err != nil {
		return nil
	}

	var gwIP string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 4 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" && fields[3] == localIP.String() {
			gwIP = fields[2]
			break
		}
		if gwIP == "" && len(fields) >= 3 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			gwIP = fields[2]
		}
	}
	if gwIP == "" {
		return nil
	}

	// Look up gateway MAC in ARP table.
	out, err = exec.Command(windowsSystem32Exe("arp.exe"), "-a").CombinedOutput()
	if err != nil {
		return nil
	}

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && fields[0] == gwIP {
			mac, err := net.ParseMAC(strings.ReplaceAll(fields[1], "-", ":"))
			if err == nil {
				return mac
			}
		}
	}
	return nil
}

func resolvePcapDevice(friendlyName string) (string, error) {
	goIface, err := net.InterfaceByName(friendlyName)
	if err != nil {
		return "", fmt.Errorf("interface %s: %w", friendlyName, err)
	}
	goAddrs, err := goIface.Addrs()
	if err != nil || len(goAddrs) == 0 {
		return "", fmt.Errorf("no addresses on %s", friendlyName)
	}

	ipSet := make(map[string]bool)
	for _, a := range goAddrs {
		if ipNet, ok := a.(*net.IPNet); ok {
			ipSet[ipNet.IP.String()] = true
		}
	}

	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("pcap find devices: %w", err)
	}
	for _, dev := range devs {
		for _, addr := range dev.Addresses {
			if ipSet[addr.IP.String()] {
				return dev.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no pcap device found for %s", friendlyName)
}

func defaultInterface() (string, error) {
	// Find the physical interface that has the default gateway.
	// This avoids selecting disconnected Wi-Fi or other inactive adapters.
	gwIP := defaultGatewayIP()

	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("pcap find devices: %w (is Npcap installed?)", err)
	}

	// First pass: find device on the same subnet as the gateway.
	if gwIP != nil {
		for _, dev := range devs {
			for _, addr := range dev.Addresses {
				ip := addr.IP.To4()
				if ip == nil || ip.IsLoopback() || ip.Equal(net.IPv4(10, 0, 85, 1)) {
					continue
				}
				mask := addr.Netmask
				if mask != nil && ip.Mask(mask).Equal(gwIP.Mask(mask)) {
					return dev.Name, nil
				}
			}
		}
	}

	// Fallback: first device with a non-loopback, non-TUN IPv4 address.
	for _, dev := range devs {
		for _, addr := range dev.Addresses {
			if ip := addr.IP.To4(); ip != nil && !ip.IsLoopback() && !ip.Equal(net.IPv4(10, 0, 85, 1)) {
				return dev.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no suitable network interface found")
}

func defaultGatewayIP() net.IP {
	out, err := exec.Command(windowsSystem32Exe("route.exe"), "print", "0.0.0.0").CombinedOutput()
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 3 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			return net.ParseIP(fields[2])
		}
	}
	return nil
}
