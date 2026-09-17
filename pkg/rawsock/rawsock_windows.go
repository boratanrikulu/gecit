package rawsock

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/google/gopacket/pcap"
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

	srcMAC, dstMAC := discoverMACs()

	return &pcapRawSocket{handle: handle, srcMAC: srcMAC, dstMAC: dstMAC}, nil
}

func (s *pcapRawSocket) SendFake(conn ConnInfo, payload []byte, ttl int) error {
	ipTcp := BuildPacket(conn, payload, ttl)

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
func discoverMACs() (srcMAC, dstMAC net.HardwareAddr) {
	// Default fallback: broadcast dst, zero src.
	srcMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}
	dstMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	// Find local NIC MAC.
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok {
				if ipv4 := ipNet.IP.To4(); ipv4 != nil && !ipv4.IsLoopback() && !ipv4.Equal(net.IPv4(10, 0, 85, 1)) {
					srcMAC = iface.HardwareAddr
					// Find gateway MAC from ARP table.
					if gwMAC := gatewayMAC(ipv4); gwMAC != nil {
						dstMAC = gwMAC
					}
					return
				}
			}
		}
	}
	return
}

// gatewayMAC finds the default gateway's MAC address from the ARP table.
func gatewayMAC(localIP net.IP) net.HardwareAddr {
	// Find default gateway IP.
	out, err := exec.Command("cmd", "/c", "route", "print", "0.0.0.0").CombinedOutput()
	if err != nil {
		return nil
	}

	var gwIP string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 3 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			gwIP = fields[2]
			break
		}
	}
	if gwIP == "" {
		return nil
	}

	// Look up gateway MAC in ARP table.
	out, err = exec.Command("arp", "-a").CombinedOutput()
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
	out, err := exec.Command("cmd", "/c", "route", "print", "0.0.0.0").CombinedOutput()
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
