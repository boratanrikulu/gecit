//go:build darwin || windows

package app

import (
	"context"
	"fmt"

	gecitdns "github.com/boratanrikulu/gecit/pkg/dns"
	"github.com/boratanrikulu/gecit/pkg/engine"
	gecittun "github.com/boratanrikulu/gecit/pkg/tun"
	"github.com/sirupsen/logrus"
)

type tunEngine struct {
	mgr        *gecittun.Manager
	dns        *gecitdns.Server
	dohEnabled bool
	logger     *logrus.Logger
}

func newPlatformEngine(cfg engine.Config, logger *logrus.Logger) (engine.Engine, error) {
	upstream := cfg.DoHUpstream
	if upstream == "" {
		upstream = "cloudflare"
	}

	mgr := gecittun.NewManager(gecittun.Config{
		Ports:     cfg.Ports,
		FakeTTL:   cfg.FakeTTL,
		Interface: cfg.Interface,
	}, logger)

	return &tunEngine{
		mgr:        mgr,
		dns:        gecitdns.NewServer(upstream, logger, mgr.DialContext),
		dohEnabled: cfg.DoHEnabled,
		logger:     logger,
	}, nil
}

func (e *tunEngine) Start(ctx context.Context) error {
	if e.dohEnabled {
		stopSystemDNS()

		if err := e.dns.Start(); err != nil {
			resumeSystemDNS()
			return err
		}
		if err := gecitdns.SetSystemDNS(); err != nil {
			e.dns.Stop()
			resumeSystemDNS()
			return err
		}
		e.logger.Info("encrypted DNS active")
	}

	if err := e.mgr.Start(ctx); err != nil {
		if e.dohEnabled {
			gecitdns.RestoreSystemDNS()
			e.dns.Stop()
			resumeSystemDNS()
		}
		return err
	}

	return nil
}

func (e *tunEngine) Stop() error {
	var errs []error
	if err := e.mgr.Stop(); err != nil {
		errs = append(errs, fmt.Errorf("tun manager stop: %w", err))
	}
	if e.dohEnabled {
		if err := gecitdns.RestoreSystemDNS(); err != nil {
			errs = append(errs, fmt.Errorf("restore system DNS: %w", err))
		}
		if err := e.dns.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("dns server stop: %w", err))
		}
		resumeSystemDNS()
	}
	if len(errs) > 0 {
		return errs[0] // return first error; others are logged via caller
	}
	return nil
}

func (e *tunEngine) Mode() string { return "tun" }
