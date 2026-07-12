//go:build (darwin || windows) && with_gvisor

package tun

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/boratanrikulu/gecit/pkg/domains"
	"github.com/boratanrikulu/gecit/pkg/seqtrack"
	"github.com/boratanrikulu/gecit/pkg/rawsock"
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
	Domains   []string
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
	domainResolver *domains.Resolver
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

func (m *Manager) Start(ctx context.Context) error {
	m.ctx, m.cancel = context.WithCancel(ctx)

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
		m.rawSock.Close()
		return err
	}

	domainsToResolve := m.cfg.Domains
	if len(domainsToResolve) == 0 {
		m.logger.Info("no domains configured — routing all traffic")
	}

	var resolvedIPs []string
	if len(domainsToResolve) > 0 {
		m.domainResolver = domains.New(domainsToResolve, m.logger)
		if err := m.domainResolver.Resolve(); err != nil {
			m.logger.WithError(err).Warn("some domains failed to resolve — retrying")
		}
		resolvedIPs = m.domainResolver.IPs()
		if len(resolvedIPs) == 0 {
			m.rawSock.Close()
			return fmt.Errorf("no target domains resolved to any IP — cannot route")
		}
		m.logger.WithField("count", len(resolvedIPs)).Info("target domains resolved")
		for _, ip := range resolvedIPs {
			m.logger.WithField("ip", ip).Debug("resolved target IP")
		}
		m.domainResolver.StartRefresh(5 * time.Minute)
	}

	tunOpts := m.buildTunOptions(resolvedIPs)
	tunDevice, err := tun.New(tunOpts)
	if err != nil {
		m.rawSock.Close()
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
		"tun":       tunName,
		"ports":     m.cfg.Ports,
		"ttl":       m.cfg.FakeTTL,
		"interface": physIface,
		"ips":       len(resolvedIPs),
	}).Info("TUN engine active")

	m.logger.Debug("testing outbound connectivity")
	if conn, err := (&net.Dialer{Timeout: 3 * time.Second, Control: m.bindControl}).DialContext(ctx, "tcp", "1.1.1.1:443"); err != nil {
		m.logger.WithError(err).Warn("outbound connectivity test failed")
	} else {
		conn.Close()
		m.logger.Debug("outbound connectivity test passed")
	}

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

func (m *Manager) IsTargetIP(ip string) bool {
	if m.domainResolver == nil {
		return true
	}
	return m.domainResolver.ContainsIP(ip)
}

func (m *Manager) dialServer(network, addr string, timeout time.Duration) (net.Conn, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		conn, err := (&net.Dialer{Timeout: timeout, Control: m.bindControl}).DialContext(m.ctx, network, addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if attempt < 2 {
			time.Sleep(time.Duration(50*(1<<attempt)) * time.Millisecond)
		}
	}
	return nil, fmt.Errorf("dial failed after 3 attempts: %w", lastErr)
}

// DialContext dials via physical NIC, bypassing TUN. Exported for DoH client.
// Safe to call before Start() - uses lazy initialization if bindControl not yet set.
func (m *Manager) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	ctrl := m.bindControl
	if ctrl == nil {
		finder := control.NewDefaultInterfaceFinder()
		ifName := m.cfg.Interface
		if ifName == "" {
			ifName = detectPhysicalInterface()
		}
		ifIndex := -1
		if ifaces, err := net.Interfaces(); err == nil {
			for _, iface := range ifaces {
				if iface.Name == ifName {
					ifIndex = iface.Index
					break
				}
			}
		}
		ctrl = control.Append(nil, control.BindToInterface(finder, ifName, ifIndex))
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
	seqtrack.SetSeqTracker(st)
	m.logger.WithField("interface", iface).Info("seq/ack tracker active")
	return nil
}

// initNetworking sets up interface binding, network monitor, and interface
// monitor. These are required by sing-tun's AutoRoute for loop prevention.
func (m *Manager) initNetworking(physIface string) error {
	m.ifaceFinder = control.NewDefaultInterfaceFinder()

	ifIndex := -1
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if iface.Name == physIface {
				ifIndex = iface.Index
				break
			}
		}
	}
	if ifIndex == -1 {
		return fmt.Errorf("interface %q not found", physIface)
	}
	m.logger.WithFields(logrus.Fields{
		"interface": physIface,
		"index":     ifIndex,
	}).Debug("physical interface resolved")
	m.bindControl = control.Append(nil, control.BindToInterface(m.ifaceFinder, physIface, ifIndex))

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

func (m *Manager) buildTunOptions(resolvedIPs []string) tun.Options {
	opts := tun.Options{
		Name:              tun.CalculateInterfaceName(""),
		Inet4Address:      []netip.Prefix{netip.MustParsePrefix("10.0.85.1/30")},
		MTU:               tunMTU,
		AutoRoute:         true,
		InterfaceMonitor:  m.ifaceMonitor,
		InterfaceFinder:   m.ifaceFinder,
		DNSServers:        []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	}
	if len(resolvedIPs) > 0 {
		routes := make([]netip.Prefix, 0, len(resolvedIPs))
		for _, ip := range resolvedIPs {
			routes = append(routes, netip.MustParsePrefix(ip+"/32"))
		}
		opts.Inet4RouteAddress = routes
	}
	return opts
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

