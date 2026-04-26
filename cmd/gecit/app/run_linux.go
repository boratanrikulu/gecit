package app

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"

	gecitdns "github.com/boratanrikulu/gecit/pkg/dns"
	bpf "github.com/boratanrikulu/gecit/pkg/ebpf"
	"github.com/boratanrikulu/gecit/pkg/engine"
	"github.com/sirupsen/logrus"
)

type ebpfEngine struct {
	mgr        *bpf.Manager
	dns        *gecitdns.Server
	dohEnabled bool
	logger     *logrus.Logger
}

func newPlatformEngine(cfg engine.Config, logger *logrus.Logger) (engine.Engine, error) {
	upstream := cfg.DoHUpstream
	if upstream == "" {
		upstream = "cloudflare"
	}

	return &ebpfEngine{
		mgr: bpf.NewManager(bpf.Config{
			MSS:                 cfg.MSS,
			RestoreMSS:          cfg.RestoreMSS,
			RestoreAfterBytes:   cfg.RestoreAfterBytes,
			Ports:               cfg.Ports,
			ExcludeIPs:          dohUpstreamIPs(upstream),
			CgroupPath:          cfg.CgroupPath,
			FakeTTL:             cfg.FakeTTL,
			AllowPrivateTargets: cfg.AllowPrivateTargets,
		}, logger),
		dns:        gecitdns.NewServerWithOptions(upstream, logger, nil, cfg.AllowPlainDoH),
		dohEnabled: cfg.DoHEnabled,
		logger:     logger,
	}, nil
}

// dohUpstreamIPs extracts IP addresses from DoH upstream config
// so eBPF can exclude them from fake injection.
// dohUpstreamIPs resolves all DoH upstream hostnames to IPs before
// gecit takes over system DNS. These IPs are excluded from eBPF fake
// injection so DoH traffic isn't disrupted.
func dohUpstreamIPs(upstream string) []net.IP {
	var ips []net.IP
	for _, u := range strings.Split(upstream, ",") {
		u = strings.TrimSpace(u)
		if p, ok := gecitdns.Presets[u]; ok {
			u = p.URL
		}
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		host := parsed.Hostname()
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
			continue
		}
		// Hostname — resolve before we take over system DNS.
		resolved, err := net.LookupIP(host)
		if err != nil {
			continue
		}
		for _, ip := range resolved {
			if ip.To4() != nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

func (e *ebpfEngine) Start(ctx context.Context) error {
	if e.dohEnabled {
		if err := e.dns.Start(); err != nil {
			return err
		}
		if err := gecitdns.SetSystemDNS(); err != nil {
			if stopErr := e.dns.Stop(); stopErr != nil {
				e.logger.WithError(stopErr).Warn("failed to stop DNS server")
			}
			return err
		}
		e.logger.Info("encrypted DNS active")
	}

	if err := e.mgr.Start(ctx); err != nil {
		if e.dohEnabled {
			if restoreErr := gecitdns.RestoreSystemDNS(); restoreErr != nil {
				e.logger.WithError(restoreErr).Warn("failed to restore system DNS")
			}
			if stopErr := e.dns.Stop(); stopErr != nil {
				e.logger.WithError(stopErr).Warn("failed to stop DNS server")
			}
		}
		return err
	}

	return nil
}

func (e *ebpfEngine) Stop() error {
	var err error
	if e.dohEnabled {
		if restoreErr := gecitdns.RestoreSystemDNS(); restoreErr != nil {
			err = errors.Join(err, restoreErr)
			e.logger.WithError(restoreErr).Warn("failed to restore system DNS")
		}
		if stopErr := e.dns.Stop(); stopErr != nil {
			err = errors.Join(err, stopErr)
			e.logger.WithError(stopErr).Warn("failed to stop DNS server")
		}
		if err == nil {
			e.logger.Info("system DNS restored")
		}
	}
	return errors.Join(err, e.mgr.Stop())
}

func (e *ebpfEngine) Mode() string { return "ebpf-sockops" }
