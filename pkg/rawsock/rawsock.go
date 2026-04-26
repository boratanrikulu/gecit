package rawsock

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

// ConnInfo holds connection details for crafting fake packets.
type ConnInfo struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Seq     uint32 // TCP sequence number the real data will use
	Ack     uint32 // TCP ACK number (rcv_nxt from the connection)
}

// RawSocket sends crafted TCP packets with custom TTL.
type RawSocket interface {
	// SendFake sends a fake TCP data packet that DPI will process
	// but the destination server will never receive (low TTL).
	SendFake(conn ConnInfo, payload []byte, ttl int) error
	Close() error
}

const (
	ipHeaderLen       = 20
	tcpHeaderLen      = 20
	maxIPv4PacketLen  = 65535
	maxFakePayloadLen = maxIPv4PacketLen - ipHeaderLen - tcpHeaderLen
)

func ValidatePacketInput(conn ConnInfo, ttl int) error {
	if ttl < 1 || ttl > 255 {
		return fmt.Errorf("ttl must be between 1 and 255, got %d", ttl)
	}
	if conn.SrcIP.To4() == nil {
		return fmt.Errorf("source IP must be IPv4, got %s", conn.SrcIP)
	}
	if conn.DstIP.To4() == nil {
		return fmt.Errorf("destination IP must be IPv4, got %s", conn.DstIP)
	}
	if conn.SrcPort == 0 || conn.DstPort == 0 {
		return fmt.Errorf("source and destination ports must be non-zero")
	}
	return nil
}

func IsUnsafeTarget(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.Equal(net.IPv4zero) ||
			ip4.Equal(net.IPv4bcast) ||
			ip4.IsLoopback() ||
			ip4.IsPrivate() ||
			ip4.IsLinkLocalUnicast() ||
			ip4.IsLinkLocalMulticast() ||
			ip4.IsMulticast() ||
			isCGNAT(ip4)
	}
	return ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast()
}

func isCGNAT(ip net.IP) bool {
	ip4 := ip.To4()
	return ip4 != nil && ip4[0] == 100 && ip4[1]&0xc0 == 0x40
}

// BuildPacket constructs a complete IP+TCP packet with the given payload.
// Used by both Linux and macOS raw socket implementations.
func BuildPacket(conn ConnInfo, payload []byte, ttl int) ([]byte, error) {
	if err := ValidatePacketInput(conn, ttl); err != nil {
		return nil, err
	}
	if len(payload) > maxFakePayloadLen {
		return nil, fmt.Errorf("payload too large for IPv4 packet: %d > %d", len(payload), maxFakePayloadLen)
	}

	tcpHdr := buildTCPHeader(conn)
	tcpLen := len(tcpHdr) + len(payload)
	ipHdr := buildIPHeader(conn, ttl, tcpLen)

	pkt := make([]byte, 0, len(ipHdr)+len(tcpHdr)+len(payload))
	pkt = append(pkt, ipHdr...)
	pkt = append(pkt, tcpHdr...)
	pkt = append(pkt, payload...)

	// Compute TCP checksum (pseudo-header + TCP header + payload).
	tcpChecksumOffset := len(ipHdr) + 16
	checksumData := make([]byte, 0, 12+len(tcpHdr)+len(payload))
	checksumData = append(checksumData, conn.SrcIP.To4()...)
	checksumData = append(checksumData, conn.DstIP.To4()...)
	checksumData = append(checksumData, 0, syscall.IPPROTO_TCP)
	tcpLenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(tcpLenBuf, uint16(tcpLen)) // #nosec G115 -- tcpLen is bounded by maxFakePayloadLen above.
	checksumData = append(checksumData, tcpLenBuf...)
	checksumData = append(checksumData, pkt[len(ipHdr):]...)
	binary.BigEndian.PutUint16(pkt[tcpChecksumOffset:tcpChecksumOffset+2], Checksum(checksumData))

	return pkt, nil
}

func buildIPHeader(conn ConnInfo, ttl int, payloadLen int) []byte {
	totalLen := ipHeaderLen + payloadLen
	hdr := make([]byte, ipHeaderLen)
	hdr[0] = 0x45                                 // Version=4, IHL=5
	ipHeaderPutUint16(hdr[2:4], uint16(totalLen)) // #nosec G115 -- totalLen is bounded by maxIPv4PacketLen before buildIPHeader.
	ipHeaderPutUint16(hdr[4:6], 0x1234)           // ID
	hdr[8] = byte(ttl)                            // #nosec G115 -- ttl is validated by ValidatePacketInput before buildIPHeader.
	hdr[9] = syscall.IPPROTO_TCP                  // Protocol
	copy(hdr[12:16], conn.SrcIP.To4())
	copy(hdr[16:20], conn.DstIP.To4())
	// IP header checksum — required for pcap_sendpacket (kernel won't fill it).
	binary.BigEndian.PutUint16(hdr[10:12], Checksum(hdr))
	return hdr
}

func buildTCPHeader(conn ConnInfo) []byte {
	hdr := make([]byte, tcpHeaderLen)
	binary.BigEndian.PutUint16(hdr[0:2], conn.SrcPort)
	binary.BigEndian.PutUint16(hdr[2:4], conn.DstPort)
	binary.BigEndian.PutUint32(hdr[4:8], conn.Seq)
	binary.BigEndian.PutUint32(hdr[8:12], conn.Ack)
	hdr[12] = 0x50 // Data offset: 5 (20 bytes)
	hdr[13] = 0x18 // Flags: PSH+ACK
	binary.BigEndian.PutUint16(hdr[14:16], 502)
	return hdr
}

// Checksum computes the Internet checksum (RFC 1071).
func Checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
