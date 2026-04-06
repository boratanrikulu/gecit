//go:build linux

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"sync"

	gecitdns "github.com/boratanrikulu/gecit/pkg/dns"
	"github.com/boratanrikulu/gecit/pkg/fake"
	"github.com/boratanrikulu/gecit/pkg/rawsock"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/sirupsen/logrus"
)

// Config holds the userspace configuration pushed to BPF maps.
type Config struct {
	MSS               int      // small MSS for fragmentation (default: 40)
	RestoreMSS        int      // normal MSS to restore (0 = auto/1460)
	RestoreAfterBytes int      // restore after N bytes sent (default: 600)
	Ports             []uint16 // target destination ports (default: [443])
	CgroupPath        string   // cgroup v2 mount (default: /sys/fs/cgroup)
	FakeTTL           int      // TTL for fake packets (default: 8)
}

// connEvent must match struct conn_event in maps.h exactly.
type connEvent struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
}

// Manager loads, attaches, and manages the BPF sock_ops program.
type Manager struct {
	collection *ebpf.Collection
	link       link.Link
	reader     *perf.Reader
	rawSock    rawsock.RawSocket
	cfg        Config
	logger     *logrus.Logger
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

func NewManager(cfg Config, logger *logrus.Logger) *Manager {
	if cfg.MSS == 0 {
		cfg.MSS = 40
	}
	if cfg.RestoreAfterBytes == 0 {
		cfg.RestoreAfterBytes = 600
	}
	if cfg.CgroupPath == "" {
		cfg.CgroupPath = "/sys/fs/cgroup"
	}
	if len(cfg.Ports) == 0 {
		cfg.Ports = []uint16{443}
	}
	if cfg.FakeTTL == 0 {
		cfg.FakeTTL = 8
	}

	return &Manager{cfg: cfg, logger: logger}
}

// Start loads the BPF program, attaches to cgroup, starts fake packet injection.
func (m *Manager) Start(ctx context.Context) error {
	if !HaveSockOps() {
		return fmt.Errorf("kernel does not support sock_ops BPF programs")
	}
	if !HaveSockOpsSetsockopt() {
		return fmt.Errorf("kernel does not support bpf_setsockopt in sock_ops (need 5.x+)")
	}

	m.logger.Info("loading BPF sock_ops program")

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(SockopsProgram))
	if err != nil {
		return fmt.Errorf("load BPF spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create BPF collection: %w", err)
	}
	m.collection = coll

	btf.FlushKernelSpec()
	runtime.GC()

	prog := coll.Programs["gecit_sockops"]
	if prog == nil {
		return fmt.Errorf("BPF program 'gecit_sockops' not found in collection")
	}

	m.logger.WithField("cgroup", m.cfg.CgroupPath).Info("attaching sock_ops to cgroup")

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    m.cfg.CgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: prog,
	})
	if err != nil {
		coll.Close()
		return fmt.Errorf("attach cgroup sock_ops: %w", err)
	}
	m.link = l

	if err := m.pushConfig(); err != nil {
		m.Stop()
		return fmt.Errorf("push config: %w", err)
	}
	if err := m.pushTargetPorts(); err != nil {
		m.Stop()
		return fmt.Errorf("push target ports: %w", err)
	}

	eventsMap := coll.Maps["conn_events"]
	if eventsMap == nil {
		m.Stop()
		return errMapNotFound("conn_events")
	}
	rd, err := perf.NewReader(eventsMap, 4096)
	if err != nil {
		m.Stop()
		return fmt.Errorf("open perf reader: %w", err)
	}
	m.reader = rd

	rs, err := rawsock.New()
	if err != nil {
		m.Stop()
		return fmt.Errorf("raw socket: %w", err)
	}
	m.rawSock = rs

	childCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.wg.Add(1)
	go m.readEvents(childCtx)

	m.logger.WithFields(logrus.Fields{
		"mss":      m.cfg.MSS,
		"fake_ttl": m.cfg.FakeTTL,
		"ports":    m.cfg.Ports,
	}).Info("gecit active — MSS fragmentation + fake packet injection")

	return nil
}

func (m *Manager) readEvents(ctx context.Context) {
	defer m.wg.Done()

	for {
		record, err := m.reader.Read()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			return
		}

		if len(record.RawSample) < 20 {
			continue
		}

		var evt connEvent
		evt.SrcIP = binary.NativeEndian.Uint32(record.RawSample[0:4])
		evt.DstIP = binary.NativeEndian.Uint32(record.RawSample[4:8])
		evt.SrcPort = binary.NativeEndian.Uint16(record.RawSample[8:10])
		evt.DstPort = binary.NativeEndian.Uint16(record.RawSample[10:12])
		evt.Seq = binary.NativeEndian.Uint32(record.RawSample[12:16])
		evt.Ack = binary.NativeEndian.Uint32(record.RawSample[16:20])

		m.injectFake(evt)
	}
}

func (m *Manager) injectFake(evt connEvent) {
	conn := rawsock.ConnInfo{
		SrcIP:   uint32ToIP(evt.SrcIP),
		DstIP:   uint32ToIP(evt.DstIP),
		SrcPort: evt.SrcPort,
		DstPort: evt.DstPort,
		Seq:     evt.Seq,
		Ack:     evt.Ack,
	}

	if err := m.rawSock.SendFake(conn, fake.TLSClientHello, m.cfg.FakeTTL); err != nil {
		m.logger.WithError(err).Warn("failed to send fake packet")
		return
	}

	// Resolve domain from DoH DNS cache (best-effort).
	dst := fmt.Sprintf("%s:%d", conn.DstIP, conn.DstPort)
	if dns := gecitdns.GetDNSServer(); dns != nil {
		if domain := dns.PopDomain(conn.DstIP.String()); domain != "" {
			dst = fmt.Sprintf("%s:%d", domain, conn.DstPort)
		}
	}

	m.logger.WithFields(logrus.Fields{
		"dst": dst,
		"seq": evt.Seq,
		"ack": evt.Ack,
		"ttl": m.cfg.FakeTTL,
	}).Info("fake ClientHello injected")
}

// Stop detaches the BPF program and releases all resources.
func (m *Manager) Stop() error {
	m.logger.Info("stopping gecit")

	if m.cancel != nil {
		m.cancel()
	}
	if m.reader != nil {
		m.reader.Close()
	}
	m.wg.Wait()

	if m.rawSock != nil {
		m.rawSock.Close()
		m.rawSock = nil
	}
	if m.link != nil {
		m.link.Close()
		m.link = nil
	}
	if m.collection != nil {
		m.collection.Close()
		m.collection = nil
	}

	m.logger.Info("gecit stopped")
	return nil
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.NativeEndian.PutUint32(ip, n)
	return ip
}

func errMapNotFound(name string) error {
	return fmt.Errorf("BPF map %q not found in collection", name)
}
