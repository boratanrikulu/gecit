//go:build windows

package rawsock

import (
	"fmt"

	"golang.org/x/sys/windows"
)

const (
	ipProtoRaw  = 255
	ipV6HdrIncl = 2
)

type platformRawSocket struct {
	fd4     windows.Handle
	fd6     windows.Handle
	hasIPv6 bool
}

func New() (RawSocket, error) {
	if sock, err, ok := tryPcapRawSocket(); ok {
		if err == nil {
			return sock, nil
		}
		native, nativeErr := newWindowsRawSocket()
		if nativeErr == nil {
			return native, nil
		}
		return nil, fmt.Errorf("pcap raw socket failed: %v; native raw socket failed: %w", err, nativeErr)
	}
	return newWindowsRawSocket()
}

func newWindowsRawSocket() (RawSocket, error) {
	fd, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, ipProtoRaw)
	if err != nil {
		return nil, fmt.Errorf("raw socket: %w", err)
	}
	if err := windows.SetsockoptInt(fd, windows.IPPROTO_IP, windows.IP_HDRINCL, 1); err != nil {
		windows.Closesocket(fd)
		return nil, fmt.Errorf("IP_HDRINCL: %w", err)
	}
	return &platformRawSocket{fd4: fd}, nil
}

func (s *platformRawSocket) SendFake(conn ConnInfo, payload []byte, ttl int) error {
	pkt := BuildPacket(conn, payload, ttl)
	if len(pkt) == 0 {
		return fmt.Errorf("invalid IP family or address pair")
	}

	switch connIPFamily(conn) {
	case ipFamilyIPv4:
		addr := &windows.SockaddrInet4{}
		copy(addr.Addr[:], conn.DstIP.To4())
		return windows.Sendto(s.fd4, pkt, 0, addr)
	case ipFamilyIPv6:
		if err := s.ensureIPv6Socket(); err != nil {
			return err
		}
		addr := &windows.SockaddrInet6{}
		copy(addr.Addr[:], conn.DstIP.To16())
		return windows.Sendto(s.fd6, pkt, 0, addr)
	default:
		return fmt.Errorf("invalid IP family or address pair")
	}
}

func (s *platformRawSocket) Close() error {
	var firstErr error
	if err := windows.Closesocket(s.fd4); err != nil {
		firstErr = err
	}
	if s.hasIPv6 {
		if err := windows.Closesocket(s.fd6); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *platformRawSocket) ensureIPv6Socket() error {
	if s.hasIPv6 {
		return nil
	}

	fd, err := windows.Socket(windows.AF_INET6, windows.SOCK_RAW, ipProtoRaw)
	if err != nil {
		return fmt.Errorf("raw ipv6 socket: %w", err)
	}
	if err := windows.SetsockoptInt(fd, windows.IPPROTO_IPV6, ipV6HdrIncl, 1); err != nil {
		windows.Closesocket(fd)
		return fmt.Errorf("IPV6_HDRINCL: %w", err)
	}

	s.fd6 = fd
	s.hasIPv6 = true
	return nil
}
