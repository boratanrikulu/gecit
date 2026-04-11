package router

import (
	"net"
	"testing"

	"github.com/boratanrikulu/gecit/pkg/fake"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestParsePacketIPv4TCP(t *testing.T) {
	packet := buildIPv4TCPPacket(t, fake.TLSClientHello)

	meta, err := ParsePacket(packet)
	if err != nil {
		t.Fatalf("ParsePacket() error = %v", err)
	}

	if meta.Protocol != ProtocolTCP {
		t.Fatalf("Protocol = %q, want tcp", meta.Protocol)
	}
	if meta.IPVersion != 4 {
		t.Fatalf("IPVersion = %d, want 4", meta.IPVersion)
	}
	if meta.SrcPort != 45678 || meta.DstPort != 443 {
		t.Fatalf("ports = %d -> %d, want 45678 -> 443", meta.SrcPort, meta.DstPort)
	}
	if !meta.TCP.PSH || !meta.TCP.ACK {
		t.Fatalf("expected PSH+ACK flags, got %+v", meta.TCP)
	}
}

func TestProcessorInjectsOncePerFlow(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WANInterface = "wan"

	processor, err := NewProcessor(cfg)
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}

	packet := buildIPv4TCPPacket(t, fake.TLSClientHello)

	first, err := processor.ProcessPacket(packet, 0)
	if err != nil {
		t.Fatalf("ProcessPacket(first) error = %v", err)
	}
	if !first.Inject {
		t.Fatalf("expected first packet to inject, reason=%q", first.Reason)
	}
	if first.Conn.Seq == 0 || len(first.FakePayload) == 0 {
		t.Fatalf("unexpected action payload: %+v", first)
	}

	second, err := processor.ProcessPacket(packet, 0)
	if err != nil {
		t.Fatalf("ProcessPacket(second) error = %v", err)
	}
	if second.Inject {
		t.Fatalf("expected duplicate flow to be skipped, reason=%q", second.Reason)
	}
}

func TestProcessorSkipsMarkedAndNonClientHelloTraffic(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WANInterface = "wan"

	processor, err := NewProcessor(cfg)
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}

	packet := buildIPv4TCPPacket(t, []byte("GET / HTTP/1.1\r\n\r\n"))

	action, err := processor.ProcessPacket(packet, cfg.PacketMark)
	if err != nil {
		t.Fatalf("ProcessPacket(marked) error = %v", err)
	}
	if action.Inject {
		t.Fatalf("marked packet should not inject, reason=%q", action.Reason)
	}

	action, err = processor.ProcessPacket(packet, 0)
	if err != nil {
		t.Fatalf("ProcessPacket(http) error = %v", err)
	}
	if action.Inject {
		t.Fatalf("non-clienthello packet should not inject, reason=%q", action.Reason)
	}
}

func TestLooksLikeTLSClientHello(t *testing.T) {
	if !LooksLikeTLSClientHello(fake.TLSClientHello) {
		t.Fatal("expected deterministic fake clienthello to match")
	}
	if LooksLikeTLSClientHello([]byte("hello")) {
		t.Fatal("short plaintext must not match")
	}
}

func buildIPv4TCPPacket(t *testing.T, payload []byte) []byte {
	t.Helper()

	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.IPv4(192, 0, 2, 10),
		DstIP:    net.IPv4(198, 51, 100, 20),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 45678,
		DstPort: 443,
		Seq:     1000,
		Ack:     2000,
		PSH:     true,
		ACK:     true,
		Window:  64240,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum() error = %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, ip4, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("SerializeLayers() error = %v", err)
	}
	return buf.Bytes()
}
