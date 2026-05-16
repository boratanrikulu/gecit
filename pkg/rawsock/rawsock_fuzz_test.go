package rawsock

import (
	"encoding/binary"
	"net"
	"syscall"
	"testing"
)

func FuzzBuildPacket(f *testing.F) {
	f.Add([]byte{
		10, 0, 0, 1,
		93, 184, 216, 34,
		0x30, 0x39,
		0x01, 0xbb,
		8,
		'h', 'e', 'l', 'l', 'o',
	})
	f.Add([]byte{10, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 187, 8})
	f.Add([]byte{10, 0, 0, 1, 1, 1, 1, 1, 1, 2, 3, 4, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 13 {
			return
		}
		payload := data[13:]
		if len(payload) > 4096 {
			payload = payload[:4096]
		}

		conn := ConnInfo{
			SrcIP:   net.IPv4(data[0], data[1], data[2], data[3]),
			DstIP:   net.IPv4(data[4], data[5], data[6], data[7]),
			SrcPort: binary.BigEndian.Uint16(data[8:10]),
			DstPort: binary.BigEndian.Uint16(data[10:12]),
			Seq:     0x01020304,
			Ack:     0x05060708,
		}
		ttl := int(data[12])

		pkt, err := BuildPacket(conn, payload, ttl)
		valid := conn.SrcPort != 0 && conn.DstPort != 0 && ttl >= 1 && ttl <= 255
		if !valid {
			if err == nil {
				t.Fatalf("BuildPacket accepted invalid input: srcPort=%d dstPort=%d ttl=%d", conn.SrcPort, conn.DstPort, ttl)
			}
			return
		}
		if err != nil {
			t.Fatalf("BuildPacket rejected valid input: %v", err)
		}
		if got, want := len(pkt), ipHeaderLen+tcpHeaderLen+len(payload); got != want {
			t.Fatalf("packet length got %d, want %d", got, want)
		}
		if pkt[0] != 0x45 || pkt[8] != byte(ttl) || pkt[9] != syscall.IPPROTO_TCP {
			t.Fatalf("invalid IP header: version=0x%02x ttl=%d proto=%d", pkt[0], pkt[8], pkt[9])
		}
		tcp := pkt[ipHeaderLen:]
		if got := binary.BigEndian.Uint16(tcp[0:2]); got != conn.SrcPort {
			t.Fatalf("src port got %d, want %d", got, conn.SrcPort)
		}
		if got := binary.BigEndian.Uint16(tcp[2:4]); got != conn.DstPort {
			t.Fatalf("dst port got %d, want %d", got, conn.DstPort)
		}
	})
}
