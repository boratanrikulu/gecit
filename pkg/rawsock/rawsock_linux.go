package rawsock

import (
	"fmt"
	"syscall"
)

type platformRawSocket struct {
	fd int
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

	return &platformRawSocket{fd: fd}, nil
}

func (s *platformRawSocket) SendFake(conn ConnInfo, payload []byte, ttl int) error {
	pkt := BuildPacket(conn, payload, ttl)
	if pkt == nil {
		return fmt.Errorf("BuildPacket failed: IPs must be IPv4")
	}

	dstIP4 := conn.DstIP.To4()
	if dstIP4 == nil {
		return fmt.Errorf("SendFake: destination is not IPv4")
	}
	addr := syscall.SockaddrInet4{Port: 0}
	copy(addr.Addr[:], dstIP4)

	return syscall.Sendto(s.fd, pkt, 0, &addr)
}

func (s *platformRawSocket) Close() error {
	return syscall.Close(s.fd)
}
