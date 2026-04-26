//go:build (darwin || windows) && with_gvisor

package app

import (
	"context"
	"errors"

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
		Ports:               cfg.Ports,
		FakeTTL:             cfg.FakeTTL,
		Interface:           cfg.Interface,
		AllowPrivateTargets: cfg.AllowPrivateTargets,
	}, logger)

	return &tunEngine{
		mgr:        mgr,
		dns:        gecitdns.NewServerWithOptions(upstream, logger, mgr.DialContext, cfg.AllowPlainDoH),
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
			if stopErr := e.dns.Stop(); stopErr != nil {
				e.logger.WithError(stopErr).Warn("failed to stop DNS server")
			}
			resumeSystemDNS()
			return err
		}
		e.logger.Info("encrypted DNS active")
	}

	if err := e.mgr.Start(ctx); err != nil {
		if e.dohEnabled {
			if restoreErr := gecitdns.RestoreSystemDNS(); restoreErr != nil {
				e.logger.WithError(restoreErr).Warn("failed to restore DNS")
			}
			if stopErr := e.dns.Stop(); stopErr != nil {
				e.logger.WithError(stopErr).Warn("failed to stop DNS server")
			}
			resumeSystemDNS()
		}
		return err
	}

	return nil
}

func (e *tunEngine) Stop() error {
	var err error
	if stopErr := e.mgr.Stop(); stopErr != nil {
		err = errors.Join(err, stopErr)
	}
	if e.dohEnabled {
		if restoreErr := gecitdns.RestoreSystemDNS(); restoreErr != nil {
			err = errors.Join(err, restoreErr)
			e.logger.WithError(restoreErr).Warn("failed to restore DNS")
		}
		if stopErr := e.dns.Stop(); stopErr != nil {
			err = errors.Join(err, stopErr)
			e.logger.WithError(stopErr).Warn("failed to stop DNS server")
		}
		resumeSystemDNS()
	}
	return err
}

func (e *tunEngine) Mode() string { return "tun" }
