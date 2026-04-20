//go:build windows

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
	socket4   windows.Handle
	socket6   windows.Handle
	hasIPv4   bool
	hasIPv6   bool
	ports     map[uint16]bool
	done      chan struct{}
	closeOnce sync.Once
}

func NewCapture(iface string, ports []uint16) (Detector, error) {
	if det, err, ok := tryPcapCapture(iface, ports); ok {
		if err == nil {
			return det, nil
		}
		rawDet, rawErr := newRawCapture(iface, ports)
		if rawErr == nil {
			return rawDet, nil
		}
		return nil, fmt.Errorf("pcap capture failed: %v; raw capture failed: %w", err, rawErr)
	}
	return newRawCapture(iface, ports)
}

func newRawCapture(iface string, ports []uint16) (Detector, error) {
	localIPv4, localIPv6, err := resolveInterfaceIPs(iface)
	if err != nil {
		return nil, err
	}

	portMap := make(map[uint16]bool, len(ports))
	for _, port := range ports {
		portMap[port] = true
	}

	capture := &rawCapture{
		ports: portMap,
		done:  make(chan struct{}),
	}

	if localIPv4 != nil {
		socket, err := openRawCaptureSocket4(localIPv4)
		if err != nil {
			return nil, err
		}
		capture.socket4 = socket
		capture.hasIPv4 = true
	}
	if localIPv6 != nil {
		socket, err := openRawCaptureSocket6(localIPv6)
		if err != nil {
			if capture.hasIPv4 {
				_ = windows.Closesocket(capture.socket4)
			}
			return nil, err
		}
		capture.socket6 = socket
		capture.hasIPv6 = true
	}
	if !capture.hasIPv4 && !capture.hasIPv6 {
		return nil, fmt.Errorf("no usable IPv4 or IPv6 address found on %s", iface)
	}

	return capture, nil
}

func (c *rawCapture) Start(cb Callback) error {
	if c.hasIPv4 {
		go c.loop(c.socket4, cb)
	}
	if c.hasIPv6 {
		go c.loop(c.socket6, cb)
	}
	return nil
}

func (c *rawCapture) Stop() error {
	c.closeOnce.Do(func() {
		close(c.done)
		if c.hasIPv4 {
			_ = windows.Closesocket(c.socket4)
		}
		if c.hasIPv6 {
			_ = windows.Closesocket(c.socket6)
		}
	})
	return nil
}

func (c *rawCapture) loop(socket windows.Handle, cb Callback) {
	buf := make([]byte, 65535)
	for {
		n, _, err := windows.Recvfrom(socket, buf, 0)
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
	if len(packet) == 0 {
		return
	}

	switch packet[0] >> 4 {
	case 4:
		c.processIPv4(packet, cb)
	case 6:
		c.processIPv6(packet, cb)
	}
}

func (c *rawCapture) processIPv4(packet []byte, cb Callback) {
	pkt := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true,
	})
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if ipLayer == nil || tcpLayer == nil {
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

func (c *rawCapture) processIPv6(packet []byte, cb Callback) {
	pkt := gopacket.NewPacket(packet, layers.LayerTypeIPv6, gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true,
	})
	ipLayer := pkt.Layer(layers.LayerTypeIPv6)
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if ipLayer == nil || tcpLayer == nil {
		return
	}

	ip6 := ipLayer.(*layers.IPv6)
	tcp := tcpLayer.(*layers.TCP)
	if !tcp.SYN || !tcp.ACK {
		return
	}
	if !c.ports[uint16(tcp.SrcPort)] {
		return
	}

	cb(ConnectionEvent{
		SrcIP:   append(net.IP{}, ip6.DstIP.To16()...),
		DstIP:   append(net.IP{}, ip6.SrcIP.To16()...),
		SrcPort: uint16(tcp.DstPort),
		DstPort: uint16(tcp.SrcPort),
		Seq:     tcp.Ack,
		Ack:     tcp.Seq + 1,
	})
}

func resolveInterfaceIPs(name string) (net.IP, net.IP, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, nil, fmt.Errorf("interface %s: %w", name, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("addresses for %s: %w", name, err)
	}

	var ipv4 net.IP
	var ipv6 net.IP
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 != nil && !ip4.IsLoopback() && ipv4 == nil {
			ipv4 = append(net.IP{}, ip4...)
			continue
		}
		ip16 := ipNet.IP.To16()
		if ip16 != nil && !ipNet.IP.IsLoopback() && ip4 == nil && ipv6 == nil {
			ipv6 = append(net.IP{}, ip16...)
		}
	}
	if ipv4 == nil && ipv6 == nil {
		return nil, nil, fmt.Errorf("no IPv4 or IPv6 address found on %s", name)
	}
	return ipv4, ipv6, nil
}

func openRawCaptureSocket4(localIP net.IP) (windows.Handle, error) {
	socket, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_IP)
	if err != nil {
		return 0, fmt.Errorf("raw ipv4 capture socket: %w", err)
	}

	addr := &windows.SockaddrInet4{}
	copy(addr.Addr[:], localIP.To4())
	if err := windows.Bind(socket, addr); err != nil {
		windows.Closesocket(socket)
		return 0, fmt.Errorf("bind raw ipv4 capture socket: %w", err)
	}
	if err := windows.SetsockoptInt(socket, windows.SOL_SOCKET, windows.SO_RCVTIMEO, 250); err != nil {
		windows.Closesocket(socket)
		return 0, fmt.Errorf("set raw ipv4 capture timeout: %w", err)
	}
	if err := enableRawCapture(socket); err != nil {
		windows.Closesocket(socket)
		return 0, fmt.Errorf("enable raw ipv4 capture: %w", err)
	}
	return socket, nil
}

func openRawCaptureSocket6(localIP net.IP) (windows.Handle, error) {
	socket, err := windows.Socket(windows.AF_INET6, windows.SOCK_RAW, windows.IPPROTO_IPV6)
	if err != nil {
		return 0, fmt.Errorf("raw ipv6 capture socket: %w", err)
	}

	addr := &windows.SockaddrInet6{}
	copy(addr.Addr[:], localIP.To16())
	if err := windows.Bind(socket, addr); err != nil {
		windows.Closesocket(socket)
		return 0, fmt.Errorf("bind raw ipv6 capture socket: %w", err)
	}
	if err := windows.SetsockoptInt(socket, windows.SOL_SOCKET, windows.SO_RCVTIMEO, 250); err != nil {
		windows.Closesocket(socket)
		return 0, fmt.Errorf("set raw ipv6 capture timeout: %w", err)
	}
	if err := enableRawCapture(socket); err != nil {
		windows.Closesocket(socket)
		return 0, fmt.Errorf("enable raw ipv6 capture: %w", err)
	}
	return socket, nil
}

func enableRawCapture(socket windows.Handle) error {
	mode := uint32(rcvAllOn)
	var bytesReturned uint32
	return windows.WSAIoctl(
		socket,
		sioRcvAll,
		(*byte)(unsafe.Pointer(&mode)),
		uint32(unsafe.Sizeof(mode)),
		nil,
		0,
		&bytesReturned,
		nil,
		0,
	)
}
