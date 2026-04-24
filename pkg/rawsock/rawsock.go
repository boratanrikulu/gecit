package rawsock

import (
	"encoding/binary"
	"net"
	"syscall"
)

// ConnInfo holds connection details for crafting fake packets.
type ConnInfo struct {
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Seq       uint32 // TCP sequence number the real data will use
	Ack       uint32 // TCP ACK number (rcv_nxt from the connection)
	ServerTTL uint8  // TTL value of the SYN-ACK packet received from the server. 0 means unknown.
}

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
	tcpHdr := buildTCPHeader(conn)
	ipHdr := buildIPHeader(conn, ttl, len(tcpHdr)+len(payload))

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

func buildIPHeader(conn ConnInfo, ttl int, payloadLen int) []byte {
	totalLen := 20 + payloadLen
	hdr := make([]byte, 20)
	hdr[0] = 0x45                                 // Version=4, IHL=5
	ipHeaderPutUint16(hdr[2:4], uint16(totalLen)) // Total length (byte order is platform-dependent)
	ipHeaderPutUint16(hdr[4:6], 0x1234)           // ID
	hdr[8] = byte(ttl)                            // TTL
	hdr[9] = syscall.IPPROTO_TCP                  // Protocol
	copy(hdr[12:16], conn.SrcIP.To4())
	copy(hdr[16:20], conn.DstIP.To4())
	// IP header checksum — required for pcap_sendpacket (kernel won't fill it).
	cs := Checksum(hdr)
	hdr[10] = byte(cs >> 8)
	hdr[11] = byte(cs)
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
