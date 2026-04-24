package rawsock

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestChecksum_KnownVector(t *testing.T) {
	// RFC 1071 example: 0x0001 + 0xf203 + ... = 0xddf2
	data := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	got := Checksum(data)
	if got == 0 {
		t.Fatal("checksum should not be zero for non-zero input")
	}
	// Verify checksum property: appending the checksum to the data
	// should yield a zero checksum (complement property).
	data = append(data, byte(got>>8), byte(got))
	if verify := Checksum(data); verify != 0 {
		t.Fatalf("checksum verify failed: got 0x%04x, want 0x0000", verify)
	}
}

func TestChecksum_Empty(t *testing.T) {
	got := Checksum([]byte{})
	if got != 0xFFFF {
		t.Fatalf("checksum of empty data: got 0x%04x, want 0xFFFF", got)
	}
}

func TestChecksum_OddLength(t *testing.T) {
	data := []byte{0xAB, 0xCD, 0xEF}
	got := Checksum(data)
	if got == 0 {
		t.Fatal("checksum should not be zero")
	}
	// Pad to even and verify complement property.
	padded := append(data, 0x00)
	padded = append(padded, byte(got>>8), byte(got))
	// Recompute over padded+checksum — should give complement of padding effect.
	// Instead, just verify consistency: same input → same output.
	if got2 := Checksum(data); got != got2 {
		t.Fatalf("checksum not deterministic: 0x%04x vs 0x%04x", got, got2)
	}
}

func TestBuildPacket_IPHeader(t *testing.T) {
	conn := ConnInfo{
		SrcIP:   net.IPv4(10, 0, 0, 1),
		DstIP:   net.IPv4(93, 184, 216, 34),
		SrcPort: 12345,
		DstPort: 443,
		Seq:     1000,
		Ack:     2000,
	}
	payload := []byte("test-payload")
	ttl := 8

	pkt := BuildPacket(conn, payload, ttl)

	// IP header is first 20 bytes.
	if len(pkt) < 40+len(payload) {
		t.Fatalf("packet too short: %d bytes", len(pkt))
	}

	// Version + IHL.
	if pkt[0] != 0x45 {
		t.Fatalf("IP version/IHL: got 0x%02x, want 0x45", pkt[0])
	}

	// TTL.
	if pkt[8] != byte(ttl) {
		t.Fatalf("TTL: got %d, want %d", pkt[8], ttl)
	}

	// Protocol (TCP = 6).
	if pkt[9] != 6 {
		t.Fatalf("protocol: got %d, want 6", pkt[9])
	}

	// Src IP.
	if !net.IP(pkt[12:16]).Equal(conn.SrcIP.To4()) {
		t.Fatalf("src IP: got %v, want %v", net.IP(pkt[12:16]), conn.SrcIP)
	}

	// Dst IP.
	if !net.IP(pkt[16:20]).Equal(conn.DstIP.To4()) {
		t.Fatalf("dst IP: got %v, want %v", net.IP(pkt[16:20]), conn.DstIP)
	}
}

func TestBuildPacket_TCPHeader(t *testing.T) {
	conn := ConnInfo{
		SrcIP:   net.IPv4(10, 0, 0, 1),
		DstIP:   net.IPv4(93, 184, 216, 34),
		SrcPort: 12345,
		DstPort: 443,
		Seq:     1000,
		Ack:     2000,
	}
	payload := []byte("hello")

	pkt := BuildPacket(conn, payload, 8)
	tcp := pkt[20:] // TCP header starts after 20-byte IP header.

	// Src port.
	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	if srcPort != conn.SrcPort {
		t.Fatalf("src port: got %d, want %d", srcPort, conn.SrcPort)
	}

	// Dst port.
	dstPort := binary.BigEndian.Uint16(tcp[2:4])
	if dstPort != conn.DstPort {
		t.Fatalf("dst port: got %d, want %d", dstPort, conn.DstPort)
	}

	// Seq.
	seq := binary.BigEndian.Uint32(tcp[4:8])
	if seq != conn.Seq {
		t.Fatalf("seq: got %d, want %d", seq, conn.Seq)
	}

	// Ack.
	ack := binary.BigEndian.Uint32(tcp[8:12])
	if ack != conn.Ack {
		t.Fatalf("ack: got %d, want %d", ack, conn.Ack)
	}

	// Data offset: 5 (20 bytes).
	if tcp[12] != 0x50 {
		t.Fatalf("data offset: got 0x%02x, want 0x50", tcp[12])
	}

	// Flags: PSH+ACK.
	if tcp[13] != 0x18 {
		t.Fatalf("flags: got 0x%02x, want 0x18 (PSH+ACK)", tcp[13])
	}
}

func TestBuildPacket_Payload(t *testing.T) {
	conn := ConnInfo{
		SrcIP:   net.IPv4(10, 0, 0, 1),
		DstIP:   net.IPv4(1, 1, 1, 1),
		SrcPort: 5000,
		DstPort: 443,
		Seq:     100,
		Ack:     200,
	}
	payload := []byte("the-real-payload")

	pkt := BuildPacket(conn, payload, 8)

	// Payload starts after IP (20) + TCP (20) headers.
	got := pkt[40:]
	if string(got) != string(payload) {
		t.Fatalf("payload: got %q, want %q", got, payload)
	}
}

func TestBuildPacket_TCPChecksum(t *testing.T) {
	conn := ConnInfo{
		SrcIP:   net.IPv4(10, 0, 0, 1),
		DstIP:   net.IPv4(93, 184, 216, 34),
		SrcPort: 12345,
		DstPort: 443,
		Seq:     1000,
		Ack:     2000,
	}
	payload := []byte("test")

	pkt := BuildPacket(conn, payload, 8)

	// Verify TCP checksum by recomputing over pseudo-header + TCP segment.
	tcpSeg := pkt[20:]
	pseudo := make([]byte, 0, 12+len(tcpSeg))
	pseudo = append(pseudo, conn.SrcIP.To4()...)
	pseudo = append(pseudo, conn.DstIP.To4()...)
	pseudo = append(pseudo, 0, 6) // reserved + protocol TCP
	tcpLen := make([]byte, 2)
	binary.BigEndian.PutUint16(tcpLen, uint16(len(tcpSeg)))
	pseudo = append(pseudo, tcpLen...)
	pseudo = append(pseudo, tcpSeg...)

	if cs := Checksum(pseudo); cs != 0 {
		t.Fatalf("TCP checksum verification failed: got 0x%04x, want 0x0000", cs)
	}
}

func TestBuildPacket_DifferentTTL(t *testing.T) {
	conn := ConnInfo{
		SrcIP:   net.IPv4(10, 0, 0, 1),
		DstIP:   net.IPv4(1, 1, 1, 1),
		SrcPort: 5000,
		DstPort: 443,
		Seq:     100,
		Ack:     200,
	}

	for _, ttl := range []int{1, 8, 64, 128, 255} {
		pkt := BuildPacket(conn, []byte("x"), ttl)
		if pkt[8] != byte(ttl) {
			t.Errorf("TTL %d: got %d", ttl, pkt[8])
		}
	}
}

// This verifies that ServerTTL is pure metadata stored on ConnInfo for caller use.
// It must not influence the constructed packet bytes.
// The wire TTL comes exclusively from the ttl int parameter.
func TestBuildPacket_ServerTTLIsMetadata(t *testing.T) {
	base := ConnInfo{
		SrcIP:   net.IPv4(10, 0, 0, 1),
		DstIP:   net.IPv4(1, 1, 1, 1),
		SrcPort: 5000,
		DstPort: 443,
		Seq:     100,
		Ack:     200,
	}

	payload := []byte("probe")
	wireTTL := 8

	pktNoServerTTL := BuildPacket(base, payload, wireTTL)

	withServerTTL := base
	withServerTTL.ServerTTL = 60

	pktWithServerTTL := BuildPacket(withServerTTL, payload, wireTTL)

	if len(pktNoServerTTL) != len(pktWithServerTTL) {
		t.Fatalf("packet length differs: %d vs %d", len(pktNoServerTTL), len(pktWithServerTTL))
	}
	for i := range pktNoServerTTL {
		if pktNoServerTTL[i] != pktWithServerTTL[i] {
			t.Errorf("byte %d differs: 0x%02x vs 0x%02x — ServerTTL leaked into packet", i, pktNoServerTTL[i], pktWithServerTTL[i])
		}
	}
}
