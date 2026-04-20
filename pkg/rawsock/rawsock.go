package rawsock

import (
	"encoding/binary"
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

const (
	ipFamilyUnknown = 0
	ipFamilyIPv4    = 4
	ipFamilyIPv6    = 6
)

// RawSocket sends crafted TCP packets with custom TTL.
type RawSocket interface {
	// SendFake sends a fake TCP data packet that DPI will process
	// but the destination server will never receive (low TTL).
	SendFake(conn ConnInfo, payload []byte, ttl int) error
	Close() error
}

// BuildPacket constructs a complete IP+TCP packet with the given payload.
// Used by both Linux and macOS raw socket implementations.
func BuildPacket(conn ConnInfo, payload []byte, ttl int) []byte {
	switch connIPFamily(conn) {
	case ipFamilyIPv4:
		return buildIPv4Packet(conn, payload, ttl)
	case ipFamilyIPv6:
		return buildIPv6Packet(conn, payload, ttl)
	default:
		return nil
	}
}

func connIPFamily(conn ConnInfo) int {
	src4 := conn.SrcIP.To4()
	dst4 := conn.DstIP.To4()
	switch {
	case src4 != nil && dst4 != nil:
		return ipFamilyIPv4
	case conn.SrcIP.To16() != nil && conn.DstIP.To16() != nil:
		return ipFamilyIPv6
	default:
		return ipFamilyUnknown
	}
}

func buildIPv4Packet(conn ConnInfo, payload []byte, ttl int) []byte {
	tcpHdr := buildTCPHeader(conn)
	ipHdr := buildIPHeader(conn, ttl, len(tcpHdr)+len(payload))
	if len(ipHdr) == 0 {
		return nil
	}

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
	binary.BigEndian.PutUint16(tcpLenBuf, uint16(len(tcpHdr)+len(payload)))
	checksumData = append(checksumData, tcpLenBuf...)
	checksumData = append(checksumData, pkt[len(ipHdr):]...)
	cs := Checksum(checksumData)
	pkt[tcpChecksumOffset] = byte(cs >> 8)
	pkt[tcpChecksumOffset+1] = byte(cs)

	return pkt
}

func buildIPv6Packet(conn ConnInfo, payload []byte, ttl int) []byte {
	srcIP := conn.SrcIP.To16()
	dstIP := conn.DstIP.To16()
	if srcIP == nil || dstIP == nil {
		return nil
	}

	tcpHdr := buildTCPHeader(conn)
	ipHdr := buildIPv6Header(srcIP, dstIP, ttl, len(tcpHdr)+len(payload))

	pkt := make([]byte, 0, len(ipHdr)+len(tcpHdr)+len(payload))
	pkt = append(pkt, ipHdr...)
	pkt = append(pkt, tcpHdr...)
	pkt = append(pkt, payload...)

	tcpChecksumOffset := len(ipHdr) + 16
	checksumData := make([]byte, 0, 40+len(tcpHdr)+len(payload))
	checksumData = append(checksumData, srcIP...)
	checksumData = append(checksumData, dstIP...)
	tcpLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(tcpLenBuf, uint32(len(tcpHdr)+len(payload)))
	checksumData = append(checksumData, tcpLenBuf...)
	checksumData = append(checksumData, 0, 0, 0, syscall.IPPROTO_TCP)
	checksumData = append(checksumData, pkt[len(ipHdr):]...)
	cs := Checksum(checksumData)
	pkt[tcpChecksumOffset] = byte(cs >> 8)
	pkt[tcpChecksumOffset+1] = byte(cs)

	return pkt
}

func buildIPHeader(conn ConnInfo, ttl int, payloadLen int) []byte {
	srcIP := conn.SrcIP.To4()
	dstIP := conn.DstIP.To4()
	if srcIP == nil || dstIP == nil {
		return nil
	}

	totalLen := 20 + payloadLen
	hdr := make([]byte, 20)
	hdr[0] = 0x45                                 // Version=4, IHL=5
	ipHeaderPutUint16(hdr[2:4], uint16(totalLen)) // Total length (byte order is platform-dependent)
	ipHeaderPutUint16(hdr[4:6], 0x1234)           // ID
	hdr[8] = byte(ttl)                            // TTL
	hdr[9] = syscall.IPPROTO_TCP                  // Protocol
	copy(hdr[12:16], srcIP)
	copy(hdr[16:20], dstIP)
	// IP header checksum — required for pcap_sendpacket (kernel won't fill it).
	cs := Checksum(hdr)
	hdr[10] = byte(cs >> 8)
	hdr[11] = byte(cs)
	return hdr
}

func buildIPv6Header(srcIP, dstIP net.IP, ttl int, payloadLen int) []byte {
	hdr := make([]byte, 40)
	hdr[0] = 0x60 // Version 6, traffic class and flow label are zeroed.
	binary.BigEndian.PutUint16(hdr[4:6], uint16(payloadLen))
	hdr[6] = syscall.IPPROTO_TCP
	hdr[7] = byte(ttl)
	copy(hdr[8:24], srcIP)
	copy(hdr[24:40], dstIP)
	return hdr
}

func buildTCPHeader(conn ConnInfo) []byte {
	hdr := make([]byte, 20)
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
