//go:build windows && cgo

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

func New() (RawSocket, error) {
	iface, err := defaultInterface()
	if err != nil {
		return nil, fmt.Errorf("detect interface: %w", err)
	}

	handle, err := pcap.OpenLive(iface, 0, false, 100*time.Millisecond)
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
	out, err := exec.Command("route", "print", "0.0.0.0").CombinedOutput()
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

func defaultInterface() (string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("pcap find devices: %w (is Npcap installed?)", err)
	}

	for _, dev := range devs {
		for _, addr := range dev.Addresses {
			if ip := addr.IP.To4(); ip != nil && !ip.IsLoopback() {
				if ip.Equal(net.IPv4(10, 0, 85, 1)) {
					continue
				}
				return dev.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no suitable network interface found")
}
