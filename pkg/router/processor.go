package router

import (
	"sync"
	"time"

	"github.com/boratanrikulu/gecit/pkg/fake"
	"github.com/boratanrikulu/gecit/pkg/rawsock"
)

const defaultFlowTTL = 2 * time.Minute

// Action describes what router mode should do with a queued packet.
type Action struct {
	Inject      bool
	Conn        rawsock.ConnInfo
	FakePayload []byte
	Reason      string
}

// Processor decides whether a queued packet should trigger a fake injection.
type Processor struct {
	cfg         Config
	flowTTL     time.Duration
	flows       *flowTable
	now         func() time.Time
	fakePayload func() []byte
}

// NewProcessor returns a stateful router-mode decision engine.
func NewProcessor(cfg Config) (*Processor, error) {
	cfg = cfg.Normalized()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &Processor{
		cfg:         cfg,
		flowTTL:     defaultFlowTTL,
		flows:       newFlowTable(defaultFlowTTL, cfg.MaxFlows),
		now:         time.Now,
		fakePayload: fake.RandomTLSClientHello,
	}, nil
}

// ProcessPacket classifies one queued packet and decides whether to inject a fake.
func (p *Processor) ProcessPacket(packet []byte, mark uint32) (Action, error) {
	if mark&p.cfg.PacketMark != 0 {
		return Action{Reason: "generated packet mark"}, nil
	}

	meta, err := ParsePacket(packet)
	if err != nil {
		return Action{Reason: "packet parse failed"}, err
	}
	if meta.Protocol != ProtocolTCP {
		return Action{Reason: "non-tcp packet"}, nil
	}
	if meta.IPVersion != 4 {
		return Action{Reason: "ipv6 fake injection not implemented"}, nil
	}
	if !portAllowed(meta.DstPort, p.cfg.TCPPorts) {
		return Action{Reason: "tcp port not targeted"}, nil
	}
	if len(meta.Payload) == 0 {
		return Action{Reason: "tcp packet has no payload"}, nil
	}
	if !LooksLikeTLSClientHello(meta.Payload) {
		return Action{Reason: "tcp payload is not a TLS ClientHello"}, nil
	}

	if !p.flows.MarkOnce(meta.FlowKey(), p.now()) {
		return Action{Reason: "flow already handled or flow table full"}, nil
	}

	conn, ok := packetToConnInfo(meta)
	if !ok {
		return Action{Reason: "failed to convert IPs to IPv4"}, nil
	}

	return Action{
		Inject:      true,
		Conn:        conn,
		FakePayload: p.fakePayload(),
		Reason:      "inject fake clienthello before queued handshake",
	}, nil
}

func packetToConnInfo(meta PacketMeta) (rawsock.ConnInfo, bool) {
	srcIP4 := meta.SrcIP.To4()
	dstIP4 := meta.DstIP.To4()
	if srcIP4 == nil || dstIP4 == nil {
		return rawsock.ConnInfo{}, false
	}
	return rawsock.ConnInfo{
		SrcIP:   append([]byte{}, srcIP4...),
		DstIP:   append([]byte{}, dstIP4...),
		SrcPort: meta.SrcPort,
		DstPort: meta.DstPort,
		Seq:     meta.TCP.Seq,
		Ack:     meta.TCP.Ack,
	}, true
}

func portAllowed(port uint16, ports []uint16) bool {
	for _, candidate := range ports {
		if candidate == port {
			return true
		}
	}
	return false
}

type flowTable struct {
	mu      sync.Mutex
	ttl     time.Duration
	limit   int
	entries map[string]time.Time
}

func newFlowTable(ttl time.Duration, limit int) *flowTable {
	return &flowTable{
		ttl:     ttl,
		limit:   limit,
		entries: make(map[string]time.Time),
	}
}

func (t *flowTable) MarkOnce(key string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	for flowKey, seenAt := range t.entries {
		if now.Sub(seenAt) > t.ttl {
			delete(t.entries, flowKey)
		}
	}

	if _, exists := t.entries[key]; exists {
		return false
	}
	if len(t.entries) >= t.limit {
		return false
	}

	t.entries[key] = now
	return true
}
