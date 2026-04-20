package rawsock

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

type platformRawSocket struct {
	fd4        int
	fd6        int
	packetMark uint32
	hasMark    bool
}

func New() (RawSocket, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("raw socket: %w", err)
	}

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("IP_HDRINCL: %w", err)
	}

	return &platformRawSocket{
		fd4: fd,
		fd6: -1,
	}, nil
}

func (s *platformRawSocket) SendFake(conn ConnInfo, payload []byte, ttl int) error {
	pkt := BuildPacket(conn, payload, ttl)
	if len(pkt) == 0 {
		return fmt.Errorf("invalid IP family or address pair")
	}

	switch connIPFamily(conn) {
	case ipFamilyIPv4:
		addr := syscall.SockaddrInet4{Port: 0}
		copy(addr.Addr[:], conn.DstIP.To4())
		return syscall.Sendto(s.fd4, pkt, 0, &addr)
	case ipFamilyIPv6:
		if err := s.ensureIPv6Socket(); err != nil {
			return err
		}
		addr := syscall.SockaddrInet6{Port: 0}
		copy(addr.Addr[:], conn.DstIP.To16())
		return syscall.Sendto(s.fd6, pkt, 0, &addr)
	default:
		return fmt.Errorf("invalid IP family or address pair")
	}
}

func (s *platformRawSocket) ensureIPv6Socket() error {
	if s.fd6 >= 0 {
		return nil
	}

	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("raw ipv6 socket: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1); err != nil {
		unix.Close(fd)
		return fmt.Errorf("IPV6_HDRINCL: %w", err)
	}
	if s.hasMark {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(s.packetMark)); err != nil {
			unix.Close(fd)
			return fmt.Errorf("SO_MARK: %w", err)
		}
	}

	s.fd6 = fd
	return nil
}

func (s *platformRawSocket) Close() error {
	var firstErr error
	if s.fd4 >= 0 {
		if err := syscall.Close(s.fd4); err != nil {
			firstErr = err
		}
		s.fd4 = -1
	}
	if s.fd6 >= 0 {
		if err := syscall.Close(s.fd6); err != nil && firstErr == nil {
			firstErr = err
		}
		s.fd6 = -1
	}
	return firstErr
}
