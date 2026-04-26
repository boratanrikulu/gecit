package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	gecitdns "github.com/boratanrikulu/gecit/pkg/dns"
	"github.com/boratanrikulu/gecit/pkg/engine"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	maxTargetPorts = 64
	minTCPMSS      = 88
)

var runCmd = &cobra.Command{
	Use:     "run",
	Short:   "Start the DPI bypass engine",
	PreRunE: validateRunFlags,
	RunE:    runEngine,
}

func init() {
	runCmd.Flags().Int("fake-ttl", 8, "TTL for fake packets (reaches DPI, not server)")
	runCmd.Flags().Bool("doh", true, "enable built-in DoH DNS resolver")
	runCmd.Flags().String("doh-upstream", "cloudflare", "DoH upstream: preset (cloudflare,google,quad9,nextdns,adguard) or URL")
	runCmd.Flags().Bool("allow-plain-doh", false, "allow plaintext HTTP DoH upstreams (unsafe)")
	runCmd.Flags().Bool("allow-private-targets", false, "allow fake packet injection to private, loopback, and link-local targets")
	runCmd.Flags().Int("mss", minTCPMSS, "TCP MSS for ClientHello fragmentation (Linux only)")
	runCmd.Flags().Int("restore-after-bytes", 600, "restore normal MSS after N bytes (Linux only)")
	runCmd.Flags().Int("restore-mss", 0, "restored MSS value, 0 = auto/1460 (Linux only)")
	runCmd.Flags().String("cgroup", "/sys/fs/cgroup", "cgroup v2 path (Linux only)")
	runCmd.Flags().BoolP("verbose", "v", false, "enable debug logging")

	mustBindPFlag("verbose", runCmd.Flags().Lookup("verbose"))
	mustBindPFlag("fake_ttl", runCmd.Flags().Lookup("fake-ttl"))
	mustBindPFlag("doh_enabled", runCmd.Flags().Lookup("doh"))
	mustBindPFlag("doh_upstream", runCmd.Flags().Lookup("doh-upstream"))
	mustBindPFlag("allow_plain_doh", runCmd.Flags().Lookup("allow-plain-doh"))
	mustBindPFlag("allow_private_targets", runCmd.Flags().Lookup("allow-private-targets"))
	mustBindPFlag("mss", runCmd.Flags().Lookup("mss"))
	mustBindPFlag("restore_after_bytes", runCmd.Flags().Lookup("restore-after-bytes"))
	mustBindPFlag("restore_mss", runCmd.Flags().Lookup("restore-mss"))
	mustBindPFlag("cgroup_path", runCmd.Flags().Lookup("cgroup"))

	rootCmd.AddCommand(runCmd)
}

func runEngine(cmd *cobra.Command, args []string) error {
	if err := checkPrivileges(); err != nil {
		return err
	}

	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	if viper.GetBool("verbose") {
		logger.SetLevel(logrus.DebugLevel)
	}

	cfg, err := runConfigFromFlags()
	if err != nil {
		return err
	}

	eng, err := newPlatformEngine(cfg, logger)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	if err := eng.Start(ctx); err != nil {
		return err
	}

	logger.WithField("mode", eng.Mode()).Info("gecit is running — press Ctrl+C to stop")

	sig := <-sigCh
	logger.WithField("signal", sig).Info("shutting down...")
	cancel()

	stopDone := make(chan error, 1)
	go func() {
		stopDone <- eng.Stop()
	}()

	signalCount := 1
	for {
		select {
		case err := <-stopDone:
			return err
		case sig := <-sigCh:
			signalCount++
			if signalCount == 2 {
				logger.WithField("signal", sig).Warn("shutdown still in progress; press Ctrl+C again to force quit and DNS restore may be incomplete")
				continue
			}
			logger.WithField("signal", sig).Error("forcing exit before graceful shutdown completed")
			os.Exit(2)
		}
	}
}

func validateRunFlags(_ *cobra.Command, _ []string) error {
	_, err := runConfigFromFlags()
	return err
}

func runConfigFromFlags() (engine.Config, error) {
	ports, err := toUint16Slice(viper.GetIntSlice("ports"))
	if err != nil {
		return engine.Config{}, err
	}

	fakeTTL := viper.GetInt("fake_ttl")
	if fakeTTL < 1 || fakeTTL > 255 {
		return engine.Config{}, fmt.Errorf("--fake-ttl must be between 1 and 255, got %d", fakeTTL)
	}

	mss := viper.GetInt("mss")
	if mss < minTCPMSS || mss > 65535 {
		return engine.Config{}, fmt.Errorf("--mss must be between %d and 65535, got %d", minTCPMSS, mss)
	}

	restoreAfter := viper.GetInt("restore_after_bytes")
	if restoreAfter < 0 {
		return engine.Config{}, fmt.Errorf("--restore-after-bytes must be >= 0, got %d", restoreAfter)
	}

	restoreMSS := viper.GetInt("restore_mss")
	if restoreMSS != 0 && (restoreMSS < minTCPMSS || restoreMSS > 65535) {
		return engine.Config{}, fmt.Errorf("--restore-mss must be 0 or between %d and 65535, got %d", minTCPMSS, restoreMSS)
	}

	upstream := viper.GetString("doh_upstream")
	if viper.GetBool("doh_enabled") {
		if err := gecitdns.ValidateUpstreams(upstream, viper.GetBool("allow_plain_doh")); err != nil {
			return engine.Config{}, err
		}
	}

	return engine.Config{
		MSS:                 mss,
		RestoreMSS:          restoreMSS,
		RestoreAfterBytes:   restoreAfter,
		Ports:               ports,
		Interface:           viper.GetString("interface"),
		CgroupPath:          viper.GetString("cgroup_path"),
		FakeTTL:             fakeTTL,
		DoHEnabled:          viper.GetBool("doh_enabled"),
		DoHUpstream:         upstream,
		AllowPlainDoH:       viper.GetBool("allow_plain_doh"),
		AllowPrivateTargets: viper.GetBool("allow_private_targets"),
	}, nil
}

func toUint16Slice(ints []int) ([]uint16, error) {
	if len(ints) == 0 {
		return nil, fmt.Errorf("--ports must include at least one port")
	}
	if len(ints) > maxTargetPorts {
		return nil, fmt.Errorf("--ports accepts at most %d ports, got %d", maxTargetPorts, len(ints))
	}

	out := make([]uint16, len(ints))
	seen := make(map[int]struct{}, len(ints))
	for i, v := range ints {
		if v < 1 || v > 65535 {
			return nil, fmt.Errorf("--ports values must be between 1 and 65535, got %d", v)
		}
		if _, ok := seen[v]; ok {
			return nil, fmt.Errorf("--ports contains duplicate port %d", v)
		}
		seen[v] = struct{}{}
		out[i] = uint16(v)
	}
	return out, nil
}
