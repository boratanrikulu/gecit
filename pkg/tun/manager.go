//go:build darwin || windows

package tun

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"time"

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
	Stack     string
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
	stackName      string
}

func NewManager(cfg Config, logger *logrus.Logger) *Manager {
	if cfg.FakeTTL == 0 {
		cfg.FakeTTL = 8
	}
	if len(cfg.Ports) == 0 {
		cfg.Ports = []uint16{443}
	}
	if strings.TrimSpace(cfg.Stack) == "" {
		cfg.Stack = "auto"
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

func (m *Manager) Start(ctx context.Context) error {
	m.ctx, m.cancel = context.WithCancel(ctx)

	rs, err := rawsock.New()
	if err != nil {
		return fmt.Errorf("raw socket: %w", err)
	}
	m.rawSock = rs

	if err := m.startSeqTracker(); err != nil {
		m.logger.WithError(err).Warn("seq tracker unavailable — fakes may be rejected by DPI")
	}

	if err := m.initNetworking(); err != nil {
		m.rawSock.Close()
		return err
	}

	stackName, err := selectStackName(m.cfg.Stack)
	if err != nil {
		m.rawSock.Close()
		return err
	}
	m.stackName = stackName

	tunOpts := m.tunOptions()
	tunDevice, err := tun.New(tunOpts)
	if err != nil {
		m.rawSock.Close()
		return fmt.Errorf("create TUN: %w", err)
	}
	m.tunDevice = tunDevice

	tunName, _ := tunDevice.Name()
	m.logger.WithField("name", tunName).Info("TUN device created")

	stack, err := tun.NewStack(stackName, tun.StackOptions{
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
		tunDevice.Close()
		m.rawSock.Close()
		return fmt.Errorf("create stack: %w", err)
	}
	m.stack = stack

	if err := tunDevice.Start(); err != nil {
		stack.Close()
		tunDevice.Close()
		m.rawSock.Close()
		return fmt.Errorf("start TUN: %w", err)
	}

	if err := stack.Start(); err != nil {
		tunDevice.Close()
		m.rawSock.Close()
		return fmt.Errorf("start stack: %w", err)
	}

	m.logger.WithFields(logrus.Fields{
		"tun":   tunName,
		"stack": stackName,
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
	if m.stack != nil {
		m.stack.Close()
	}
	if m.tunDevice != nil {
		m.tunDevice.Close()
	}
	if m.rawSock != nil {
		m.rawSock.Close()
	}
	if m.ifaceMonitor != nil {
		m.ifaceMonitor.Close()
	}
	if m.networkMonitor != nil {
		m.networkMonitor.Close()
	}
	seqtrack.SetSeqTracker(nil)

	m.logger.Info("TUN engine stopped")
	return nil
}

func (m *Manager) dialServer(network, addr string, timeout time.Duration) (net.Conn, error) {
	return (&net.Dialer{Timeout: timeout, Control: m.bindControl}).DialContext(m.ctx, network, addr)
}

// DialContext dials via physical NIC, bypassing TUN. Exported for DoH client.
func (m *Manager) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 5 * time.Second, Control: m.bindControl}).DialContext(ctx, network, addr)
}

func (m *Manager) StackName() string {
	if m.stackName != "" {
		return m.stackName
	}
	if normalized := strings.TrimSpace(strings.ToLower(m.cfg.Stack)); normalized != "" && normalized != "auto" {
		return normalized
	}
	if tun.WithGVisor {
		return "gvisor"
	}
	return "system"
}

func (m *Manager) startSeqTracker() error {
	iface := m.cfg.Interface
	if iface == "" {
		iface = detectPhysicalInterface()
	}
	if iface == "" {
		return fmt.Errorf("no physical interface found")
	}
	st, err := seqtrack.NewSeqTracker(iface, m.cfg.Ports)
	if err != nil {
		return err
	}
	seqtrack.SetSeqTracker(st)
	m.logger.WithField("interface", iface).Info("seq/ack tracker active")
	return nil
}

// initNetworking sets up interface binding, network monitor, and interface
// monitor. These are required by sing-tun's AutoRoute for loop prevention.
func (m *Manager) initNetworking() error {
	m.ifaceFinder = control.NewDefaultInterfaceFinder()
	physIface := m.cfg.Interface
	if physIface == "" {
		physIface = detectPhysicalInterface()
	}
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
		m.networkMonitor.Close()
		return fmt.Errorf("start interface monitor: %w", err)
	}
	return nil
}

func (m *Manager) tunOptions() tun.Options {
	return tun.Options{
		Name:             platformTunName(),
		Inet4Address:     []netip.Prefix{netip.MustParsePrefix("10.0.85.1/30")},
		MTU:              tunMTU,
		AutoRoute:        true,
		InterfaceMonitor: m.ifaceMonitor,
		InterfaceFinder:  m.ifaceFinder,
		DNSServers:       []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	}
}

func selectStackName(raw string) (string, error) {
	stack := strings.TrimSpace(strings.ToLower(raw))
	switch stack {
	case "", "auto":
		if tun.WithGVisor {
			return "gvisor", nil
		}
		return "system", nil
	case "system":
		return "system", nil
	case "gvisor", "mixed":
		if !tun.WithGVisor {
			return "", fmt.Errorf("%s stack requires build tag with_gvisor", stack)
		}
		return stack, nil
	default:
		return "", fmt.Errorf("unknown TUN stack %q", raw)
	}
}

func platformTunName() string {
	if runtime.GOOS == "windows" {
		return "gecit"
	}
	return "utun85"
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
