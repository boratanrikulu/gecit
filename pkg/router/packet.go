package router

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Protocol identifies the L4 protocol of a queued packet.
type Protocol string

const (
	ProtocolUnknown Protocol = "unknown"
	ProtocolTCP     Protocol = "tcp"
	ProtocolUDP     Protocol = "udp"
)

// PacketMeta is the normalized view of one queued packet.
type PacketMeta struct {
	IPVersion uint8
	Protocol  Protocol
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	TCP       TCPMeta
	UDP       UDPMeta
	Payload   []byte
}

// TCPMeta contains the fields router mode needs from a TCP packet.
type TCPMeta struct {
	Seq uint32
	Ack uint32
	SYN bool
	ACK bool
	PSH bool
	RST bool
	FIN bool
}

// UDPMeta contains the fields router mode needs from a UDP packet.
type UDPMeta struct {
	Length uint16
}

// ParsePacket extracts a portable metadata view from a raw IPv4 or IPv6 packet.
func ParsePacket(packet []byte) (PacketMeta, error) {
	if len(packet) == 0 {
		return PacketMeta{}, fmt.Errorf("empty packet")
	}

	switch packet[0] >> 4 {
	case 4:
		return parseIPv4(packet)
	case 6:
		return parseIPv6(packet)
	default:
		return PacketMeta{}, fmt.Errorf("unsupported IP version %d", packet[0]>>4)
	}
}

// FlowKey returns a stable key for first-packet gating.
func (m PacketMeta) FlowKey() string {
	return fmt.Sprintf("%d|%s|%s|%s|%d|%d", m.IPVersion, m.Protocol, m.SrcIP, m.DstIP, m.SrcPort, m.DstPort)
}

// LooksLikeTLSClientHello performs a small, conservative check before injection.
func LooksLikeTLSClientHello(payload []byte) bool {
	if len(payload) < 9 {
		return false
	}
	if payload[0] != 0x16 {
		return false
	}
	if payload[1] != 0x03 {
		return false
	}
	if payload[5] != 0x01 {
		return false
	}

	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if recordLen < 4 {
		return false
	}
	// Ensure the declared record length doesn't exceed what we actually have.
	if 5+recordLen > len(payload) {
		return false
	}

	handshakeLen := int(payload[6])<<16 | int(payload[7])<<8 | int(payload[8])
	return handshakeLen > 0
}

func parseIPv4(packet []byte) (PacketMeta, error) {
	pkt := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true,
	})
	ip4Layer := pkt.Layer(layers.LayerTypeIPv4)
	if ip4Layer == nil {
		return PacketMeta{}, fmt.Errorf("missing IPv4 layer")
	}
	ip4 := ip4Layer.(*layers.IPv4)

	meta := PacketMeta{
		IPVersion: 4,
		SrcIP:     append(net.IP{}, ip4.SrcIP...),
		DstIP:     append(net.IP{}, ip4.DstIP...),
	}
	return fillTransportMetaFromPacket(meta, pkt), nil
}

func parseIPv6(packet []byte) (PacketMeta, error) {
	pkt := gopacket.NewPacket(packet, layers.LayerTypeIPv6, gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true,
	})
	ip6Layer := pkt.Layer(layers.LayerTypeIPv6)
	if ip6Layer == nil {
		return PacketMeta{}, fmt.Errorf("missing IPv6 layer")
	}
	ip6 := ip6Layer.(*layers.IPv6)

	meta := PacketMeta{
		IPVersion: 6,
		SrcIP:     append(net.IP{}, ip6.SrcIP...),
		DstIP:     append(net.IP{}, ip6.DstIP...),
	}
	return fillTransportMetaFromPacket(meta, pkt), nil
}

func fillTransportMetaFromPacket(meta PacketMeta, pkt gopacket.Packet) PacketMeta {
	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		meta.Protocol = ProtocolTCP
		meta.SrcPort = uint16(tcp.SrcPort)
		meta.DstPort = uint16(tcp.DstPort)
		meta.Payload = append([]byte{}, tcp.Payload...)
		meta.TCP = TCPMeta{
			Seq: tcp.Seq,
			Ack: tcp.Ack,
			SYN: tcp.SYN,
			ACK: tcp.ACK,
			PSH: tcp.PSH,
			RST: tcp.RST,
			FIN: tcp.FIN,
		}
		return meta
	}
	if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		meta.Protocol = ProtocolUDP
		meta.SrcPort = uint16(udp.SrcPort)
		meta.DstPort = uint16(udp.DstPort)
		meta.Payload = append([]byte{}, udp.Payload...)
		meta.UDP = UDPMeta{Length: udp.Length}
		return meta
	}
	return meta
}
