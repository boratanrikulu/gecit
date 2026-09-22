//go:build (darwin || windows) && with_gvisor

package tun

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/boratanrikulu/gecit/pkg/engine"
	"github.com/boratanrikulu/gecit/pkg/rawsock"
	"github.com/boratanrikulu/gecit/pkg/seqtrack"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	singlog "github.com/sagernet/sing/common/logger"
	"github.com/sirupsen/logrus"
)

const tunMTU = 1420

type Config struct {
	Ports     []uint16
	FakeTTL   int
	Interface string
}

type Manager struct {
	tunDevice      tun.Tun
	stack          tun.Stack
	rawSock        rawsock.RawSocket
	cfg            Config
	targetPorts    map[uint16]bool
	logger         *logrus.Logger
	ctx            context.Context
	cancel         context.CancelFunc
	ifaceFinder    control.InterfaceFinder
	bindControl    control.Func
	networkMonitor tun.NetworkUpdateMonitor
	ifaceMonitor   tun.DefaultInterfaceMonitor
	seqTracker     *seqtrack.SeqTracker

	connections   atomic.Uint64
	fakesInjected atomic.Uint64
	injectErrors  atomic.Uint64
}

func (m *Manager) Stats() engine.Stats {
	return engine.Stats{
		Connections:   m.connections.Load(),
		FakesInjected: m.fakesInjected.Load(),
		InjectErrors:  m.injectErrors.Load(),
	}
}

func NewManager(cfg Config, logger *logrus.Logger) *Manager {
	if cfg.FakeTTL == 0 {
		cfg.FakeTTL = 8
	}
	if len(cfg.Ports) == 0 {
		cfg.Ports = []uint16{443}
	}
	ports := make(map[uint16]bool)
	for _, p := range cfg.Ports {
		ports[p] = true
	}
	return &Manager{
		cfg:         cfg,
		targetPorts: ports,
		logger:      logger,
	}
}

func (m *Manager) Start(ctx context.Context) (err error) {
	m.ctx, m.cancel = context.WithCancel(ctx)

	// Each step below brings something up that the next one can fail after.
	// The panel can retry a config that fails, so a half-started manager has to
	// leave nothing behind: a pcap handle, a TUN device and two route monitors
	// per attempt otherwise.
	defer func() {
		if err != nil {
			m.teardown()
		}
	}()

	physIface := m.cfg.Interface
	if physIface == "" {
		physIface = detectPhysicalInterface()
	}

	rs, err := rawsock.New(physIface)
	if err != nil {
		return fmt.Errorf("raw socket: %w", err)
	}
	m.rawSock = rs

	if err := m.startSeqTracker(physIface); err != nil {
		m.logger.WithError(err).Warn("seq tracker unavailable — fakes may be rejected by DPI")
	}

	if err := m.initNetworking(physIface); err != nil {
		return err
	}

	tunOpts := m.tunOptions()
	tunDevice, err := tun.New(tunOpts)
	if err != nil {
		return fmt.Errorf("create TUN: %w", err)
	}
	m.tunDevice = tunDevice

	tunName, _ := tunDevice.Name()
	m.logger.WithField("name", tunName).Info("TUN device created")

	stack, err := tun.NewStack("gvisor", tun.StackOptions{
		Context:                m.ctx,
		Tun:                    tunDevice,
		TunOptions:             tunOpts,
		UDPTimeout:             30 * time.Second,
		Handler:                &handler{mgr: m},
		Logger:                 singlog.Logger(m.logger),
		ForwarderBindInterface: true,
		InterfaceFinder:        m.ifaceFinder,
	})
	if err != nil {
		return fmt.Errorf("create stack: %w", err)
	}
	m.stack = stack

	if err := tunDevice.Start(); err != nil {
		return fmt.Errorf("start TUN: %w", err)
	}

	if err := stack.Start(); err != nil {
		return fmt.Errorf("start stack: %w", err)
	}

	m.logger.WithFields(logrus.Fields{
		"tun":   tunName,
		"ports": m.cfg.Ports,
		"ttl":   m.cfg.FakeTTL,
	}).Info("TUN engine active")

	return nil
}

func (m *Manager) Stop() error {
	m.logger.Info("stopping TUN engine")

	if m.cancel != nil {
		m.cancel()
	}
	m.teardown()

	m.logger.Info("TUN engine stopped")
	return nil
}

// teardown releases everything Start brought up, in the reverse order. Each
// field is cleared as it goes, so a stop after a failed start closes what
// exists and nothing twice.
func (m *Manager) teardown() {
	if m.stack != nil {
		m.stack.Close()
		m.stack = nil
	}
	if m.tunDevice != nil {
		m.tunDevice.Close()
		m.tunDevice = nil
	}
	if m.rawSock != nil {
		m.rawSock.Close()
		m.rawSock = nil
	}
	if m.ifaceMonitor != nil {
		m.ifaceMonitor.Close()
		m.ifaceMonitor = nil
	}
	if m.networkMonitor != nil {
		m.networkMonitor.Close()
		m.networkMonitor = nil
	}
	m.stopSeqTracker()
}

func (m *Manager) dialServer(network, addr string, timeout time.Duration) (net.Conn, error) {
	return (&net.Dialer{Timeout: timeout, Control: m.bindControl}).DialContext(m.ctx, network, addr)
}

// DialContext dials via physical NIC, bypassing TUN. Exported for DoH client.
// Safe to call before Start() - uses lazy initialization if bindControl not yet set.
func (m *Manager) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	ctrl := m.bindControl
	if ctrl == nil {
		// Not yet initialized (called before Start). Build a temporary bind.
		finder := control.NewDefaultInterfaceFinder()
		iface := m.cfg.Interface
		if iface == "" {
			iface = detectPhysicalInterface()
		}
		ctrl = control.Append(nil, control.BindToInterface(finder, iface, -1))
	}
	return (&net.Dialer{Timeout: 5 * time.Second, Control: ctrl}).DialContext(ctx, network, addr)
}

func (m *Manager) startSeqTracker(iface string) error {
	if iface == "" {
		return fmt.Errorf("no physical interface found")
	}
	st, err := seqtrack.NewSeqTracker(iface, m.cfg.Ports)
	if err != nil {
		return err
	}
	m.seqTracker = st
	seqtrack.SetSeqTracker(st)
	m.logger.WithField("interface", iface).Info("seq/ack tracker active")
	return nil
}

// stopSeqTracker releases the pcap handle. Dropping only the global would leave
// the tracker capturing into a map nothing drains.
func (m *Manager) stopSeqTracker() {
	if m.seqTracker != nil {
		m.seqTracker.Stop()
		m.seqTracker = nil
	}
	seqtrack.SetSeqTracker(nil)
}

// initNetworking sets up interface binding, network monitor, and interface
// monitor. These are required by sing-tun's AutoRoute for loop prevention.
func (m *Manager) initNetworking(physIface string) error {
	m.ifaceFinder = control.NewDefaultInterfaceFinder()
	m.bindControl = control.Append(nil, control.BindToInterface(m.ifaceFinder, physIface, -1))

	var err error
	m.networkMonitor, err = tun.NewNetworkUpdateMonitor(singlog.Logger(m.logger))
	if err != nil {
		return fmt.Errorf("network monitor: %w", err)
	}
	m.ifaceMonitor, err = tun.NewDefaultInterfaceMonitor(m.networkMonitor, singlog.Logger(m.logger), tun.DefaultInterfaceMonitorOptions{
		InterfaceFinder: m.ifaceFinder,
	})
	if err != nil {
		return fmt.Errorf("interface monitor: %w", err)
	}
	if err := m.networkMonitor.Start(); err != nil {
		return fmt.Errorf("start network monitor: %w", err)
	}
	if err := m.ifaceMonitor.Start(); err != nil {
		return fmt.Errorf("start interface monitor: %w", err)
	}
	return nil
}

func (m *Manager) tunOptions() tun.Options {
	return tun.Options{
		Name:             "utun85",
		Inet4Address:     []netip.Prefix{netip.MustParsePrefix("10.0.85.1/30")},
		MTU:              tunMTU,
		AutoRoute:        true,
		InterfaceMonitor: m.ifaceMonitor,
		InterfaceFinder:  m.ifaceFinder,
		DNSServers:       []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	}
}

func detectPhysicalInterface() string {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := iface.Name
		// Skip virtual interfaces (TUN, bridge, veth, etc.)
		for _, prefix := range []string{"utun", "bridge", "veth", "vmnet", "lo"} {
			if len(name) >= len(prefix) && name[:len(prefix)] == prefix {
				name = ""
				break
			}
		}
		if name == "" {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ipv4 := ipNet.IP.To4(); ipv4 != nil && !ipv4.IsLoopback() && !ipv4.Equal(net.IPv4(10, 0, 85, 1)) {
				return name
			}
		}
	}
	return ""
}
