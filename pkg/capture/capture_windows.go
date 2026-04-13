//go:build windows && !cgo

package capture

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/windows"
)

const (
	sioRcvAll = windows.IOC_IN | windows.IOC_VENDOR | 1
	rcvAllOn  = 1
)

type rawCapture struct {
	socket    windows.Handle
	ports     map[uint16]bool
	done      chan struct{}
	closeOnce sync.Once
}

func NewCapture(iface string, ports []uint16) (Detector, error) {
	localIP, err := resolveInterfaceIPv4(iface)
	if err != nil {
		return nil, err
	}

	socket, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_IP)
	if err != nil {
		return nil, fmt.Errorf("raw capture socket: %w", err)
	}

	if err := windows.Bind(socket, &windows.SockaddrInet4{Addr: localIP}); err != nil {
		windows.Closesocket(socket)
		return nil, fmt.Errorf("bind raw capture socket: %w", err)
	}
	if err := windows.SetsockoptInt(socket, windows.SOL_SOCKET, windows.SO_RCVTIMEO, 250); err != nil {
		windows.Closesocket(socket)
		return nil, fmt.Errorf("set raw capture timeout: %w", err)
	}

	mode := uint32(rcvAllOn)
	var bytesReturned uint32
	if err := windows.WSAIoctl(
		socket,
		sioRcvAll,
		(*byte)(unsafe.Pointer(&mode)),
		uint32(unsafe.Sizeof(mode)),
		nil,
		0,
		&bytesReturned,
		nil,
		0,
	); err != nil {
		windows.Closesocket(socket)
		return nil, fmt.Errorf("enable raw capture on %s: %w", iface, err)
	}

	portMap := make(map[uint16]bool, len(ports))
	for _, port := range ports {
		portMap[port] = true
	}

	return &rawCapture{
		socket: socket,
		ports:  portMap,
		done:   make(chan struct{}),
	}, nil
}

func (c *rawCapture) Start(cb Callback) error {
	go c.loop(cb)
	return nil
}

func (c *rawCapture) Stop() error {
	c.closeOnce.Do(func() {
		close(c.done)
		_ = windows.Closesocket(c.socket)
	})
	return nil
}

func (c *rawCapture) loop(cb Callback) {
	buf := make([]byte, 65535)
	for {
		n, _, err := windows.Recvfrom(c.socket, buf, 0)
		if err != nil {
			select {
			case <-c.done:
				return
			default:
			}
			if errors.Is(err, windows.WSAETIMEDOUT) {
				continue
			}
			return
		}
		if n == 0 {
			continue
		}
		c.processPacket(buf[:n], cb)
	}
}

func (c *rawCapture) processPacket(packet []byte, cb Callback) {
	pkt := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true,
	})
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	ip4 := ipLayer.(*layers.IPv4)
	tcp := tcpLayer.(*layers.TCP)
	if !tcp.SYN || !tcp.ACK {
		return
	}
	if !c.ports[uint16(tcp.SrcPort)] {
		return
	}

	cb(ConnectionEvent{
		SrcIP:   append(net.IP{}, ip4.DstIP.To4()...),
		DstIP:   append(net.IP{}, ip4.SrcIP.To4()...),
		SrcPort: uint16(tcp.DstPort),
		DstPort: uint16(tcp.SrcPort),
		Seq:     tcp.Ack,
		Ack:     tcp.Seq + 1,
	})
}

func resolveInterfaceIPv4(name string) ([4]byte, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return [4]byte{}, fmt.Errorf("interface %s: %w", name, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return [4]byte{}, fmt.Errorf("addresses for %s: %w", name, err)
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 == nil || ip4.IsLoopback() {
			continue
		}
		var out [4]byte
		copy(out[:], ip4)
		return out, nil
	}
	return [4]byte{}, fmt.Errorf("no IPv4 address found on %s", name)
}
