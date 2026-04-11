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
	mu     sync.Mutex
	done   chan struct{}
}

func NewCapture(iface string, ports []uint16) (Detector, error) {
	handle, err := pcap.OpenLive(iface, 68, false, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("pcap open %s: %w (run with sudo)", iface, err)
	}

	// Only capture SYN-ACK packets (tcp flags SYN+ACK = 0x12).
	// This drastically reduces pcap load — ignores all data packets.
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

	// Must be SYN+ACK (incoming from server)
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
		SrcIP:   append(net.IP{}, ip.DstIP.To4()...), // our IP
		DstIP:   append(net.IP{}, ip.SrcIP.To4()...), // server IP
		SrcPort: uint16(tcp.DstPort),                 // our port
		DstPort: uint16(tcp.SrcPort),                 // server port (443)
		Seq:     tcp.Ack,                             // our snd_nxt
		Ack:     tcp.Seq + 1,                         // our rcv_nxt
	}

	cb(evt)
}

// DefaultInterface returns the default network interface name.
func DefaultInterface() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		if len(iface.Name) >= 2 && iface.Name[:2] == "en" {
			return iface.Name, nil
		}
	}

	return "", fmt.Errorf("no suitable network interface found")
}
