//go:build linux

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"

	gecitdns "github.com/boratanrikulu/gecit/pkg/dns"
	gecitbpf "github.com/boratanrikulu/gecit/pkg/ebpf/bpf"
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
	MSS                 int
	RestoreMSS          int
	RestoreAfterBytes   int
	Ports               []uint16
	ExcludeIPs          []net.IP
	CgroupPath          string
	FakeTTL             int
	AllowPrivateTargets bool
}

// Manager loads, attaches, and manages the BPF sock_ops program.
type Manager struct {
	objs    *gecitbpf.SockopsObjects
	link    link.Link
	reader  *perf.Reader
	rawSock rawsock.RawSocket
	cfg     Config
	logger  *logrus.Logger
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func NewManager(cfg Config, logger *logrus.Logger) *Manager {
	if cfg.MSS == 0 {
		cfg.MSS = 88
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

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(gecitbpf.Program))
	if err != nil {
		return fmt.Errorf("load BPF spec: %w", err)
	}

	objs, err := gecitbpf.LoadSockops(spec)
	if err != nil {
		return fmt.Errorf("load sockops objects: %w", err)
	}
	m.objs = objs

	btf.FlushKernelSpec()
	runtime.GC()

	m.logger.WithField("cgroup", m.cfg.CgroupPath).Info("attaching sock_ops to cgroup")

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    m.cfg.CgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objs.GecitSockops,
	})
	if err != nil {
		objs.Close()
		m.objs = nil
		return fmt.Errorf("attach cgroup sock_ops: %w", err)
	}
	m.link = l

	if err := m.pushConfig(); err != nil {
		return m.stopAfterStartError(fmt.Errorf("push config: %w", err))
	}
	if err := m.pushTargetPorts(); err != nil {
		return m.stopAfterStartError(fmt.Errorf("push target ports: %w", err))
	}
	if err := m.pushExcludeIPs(); err != nil {
		return m.stopAfterStartError(fmt.Errorf("push exclude IPs: %w", err))
	}

	rd, err := perf.NewReader(objs.ConnEvents, 64<<10)
	if err != nil {
		return m.stopAfterStartError(fmt.Errorf("open perf reader: %w", err))
	}
	m.reader = rd

	rs, err := rawsock.New("")
	if err != nil {
		return m.stopAfterStartError(fmt.Errorf("raw socket: %w", err))
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

		if record.LostSamples > 0 {
			m.logger.WithField("lost", record.LostSamples).Warn("BPF perf events dropped; fake injection may be incomplete")
			continue
		}

		if len(record.RawSample) < 20 {
			m.logger.WithField("size", len(record.RawSample)).Warn("unexpected BPF conn event size")
			continue
		}

		var evt gecitbpf.ConnEvent
		evt.SrcIP = binary.NativeEndian.Uint32(record.RawSample[0:4])
		evt.DstIP = binary.NativeEndian.Uint32(record.RawSample[4:8])
		evt.SrcPort = binary.NativeEndian.Uint16(record.RawSample[8:10])
		evt.DstPort = binary.NativeEndian.Uint16(record.RawSample[10:12])
		evt.Seq = binary.NativeEndian.Uint32(record.RawSample[12:16])
		evt.Ack = binary.NativeEndian.Uint32(record.RawSample[16:20])

		m.injectFake(evt)
	}
}

func (m *Manager) injectFake(evt gecitbpf.ConnEvent) {
	conn := rawsock.ConnInfo{
		SrcIP:   uint32ToIP(evt.SrcIP),
		DstIP:   uint32ToIP(evt.DstIP),
		SrcPort: evt.SrcPort,
		DstPort: evt.DstPort,
		Seq:     evt.Seq,
		Ack:     evt.Ack,
	}

	if conn.SrcIP.To4() == nil || conn.DstIP.To4() == nil || conn.DstIP.Equal(net.IPv4zero) {
		m.logger.WithField("dst", conn.DstIP.String()).Warn("skipping non-IPv4 fake injection")
		return
	}
	if !m.cfg.AllowPrivateTargets && rawsock.IsUnsafeTarget(conn.DstIP) {
		m.logger.WithField("dst", conn.DstIP.String()).Warn("skipping fake injection to private/local target")
		return
	}

	if err := m.rawSock.SendFake(conn, fake.TLSClientHello, m.cfg.FakeTTL); err != nil {
		m.logger.WithError(err).Warn("failed to send fake packet")
		return
	}

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
	var err error
	if m.reader != nil {
		err = errors.Join(err, m.reader.Close())
		m.reader = nil
	}
	m.wg.Wait()

	if m.rawSock != nil {
		err = errors.Join(err, m.rawSock.Close())
		m.rawSock = nil
	}
	if m.link != nil {
		err = errors.Join(err, m.link.Close())
		m.link = nil
	}
	if m.objs != nil {
		m.objs.Close()
		m.objs = nil
	}

	m.logger.Info("gecit stopped")
	return err
}

func (m *Manager) stopAfterStartError(startErr error) error {
	if stopErr := m.Stop(); stopErr != nil {
		return errors.Join(startErr, stopErr)
	}
	return startErr
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.NativeEndian.PutUint32(ip, n)
	return ip
}
