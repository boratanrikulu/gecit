//go:build windows && cgo

package capture

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type pcapCapture struct {
	handle *pcap.Handle
	ports  map[uint16]bool
	done   chan struct{}
}

func NewCapture(iface string, ports []uint16) (Detector, error) {
	if !NpcapAvailable() {
		return nil, fmt.Errorf("Npcap not installed — required for DPI bypass on Windows (download from npcap.com)")
	}

	// Windows pcap needs device path (\Device\NPF_{GUID}), not friendly name.
	pcapDev, err := resolvePcapDevice(iface)
	if err != nil {
		return nil, err
	}

	handle, err := pcap.OpenLive(pcapDev, 68, false, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("pcap open %s: %w", iface, err)
	}

	filter := "tcp src port 443 and tcp[tcpflags] & (tcp-syn|tcp-ack) = (tcp-syn|tcp-ack)"
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("set BPF filter: %w", err)
	}

	portMap := make(map[uint16]bool)
	for _, p := range ports {
		portMap[p] = true
	}

	return &pcapCapture{
		handle: handle,
		ports:  portMap,
		done:   make(chan struct{}),
	}, nil
}

func (c *pcapCapture) Start(cb Callback) error {
	src := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	src.NoCopy = true

	go func() {
		for {
			select {
			case <-c.done:
				return
			default:
			}
			packet, err := src.NextPacket()
			if err != nil {
				select {
				case <-c.done:
					return
				default:
				}
				continue
			}
			c.processPacket(packet, cb)
		}
	}()

	return nil
}

func (c *pcapCapture) Stop() error {
	close(c.done)
	c.handle.Close()
	return nil
}

func (c *pcapCapture) processPacket(packet gopacket.Packet, cb Callback) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp := tcpLayer.(*layers.TCP)

	if !tcp.SYN || !tcp.ACK {
		return
	}
	if !c.ports[uint16(tcp.SrcPort)] {
		return
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip := ipLayer.(*layers.IPv4)

	evt := ConnectionEvent{
		SrcIP:     append(net.IP{}, ip.DstIP.To4()...),
		DstIP:     append(net.IP{}, ip.SrcIP.To4()...),
		SrcPort:   uint16(tcp.DstPort),
		DstPort:   uint16(tcp.SrcPort),
		Seq:       tcp.Ack,
		Ack:       tcp.Seq + 1,
		ServerTTL: ip.TTL,
	}

	cb(evt)
}

// resolvePcapDevice maps a friendly interface name (e.g. "Ethernet") to
// the pcap device path (e.g. \Device\NPF_{GUID}) by matching IP addresses.
func resolvePcapDevice(friendlyName string) (string, error) {
	goIface, err := net.InterfaceByName(friendlyName)
	if err != nil {
		return "", fmt.Errorf("interface %s: %w", friendlyName, err)
	}
	goAddrs, err := goIface.Addrs()
	if err != nil || len(goAddrs) == 0 {
		return "", fmt.Errorf("no addresses on %s", friendlyName)
	}

	// Collect IPs from the Go interface.
	ipSet := make(map[string]bool)
	for _, a := range goAddrs {
		if ipNet, ok := a.(*net.IPNet); ok {
			ipSet[ipNet.IP.String()] = true
		}
	}

	// Find pcap device with matching IP.
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

// NpcapAvailable checks if Npcap is installed by trying to find its DLL.
func NpcapAvailable() bool {
	_, err := pcap.FindAllDevs()
	return err == nil
}

var npcapCheckOnce sync.Once
var npcapInstalled bool

func CheckNpcap() bool {
	npcapCheckOnce.Do(func() {
		npcapInstalled = NpcapAvailable()
	})
	return npcapInstalled
}
