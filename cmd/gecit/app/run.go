package app

import (
	"fmt"

	"github.com/boratanrikulu/gecit/pkg/engine"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start the DPI bypass engine",
	RunE:  runEngine,
}

func init() {
	runCmd.Flags().Int("fake-ttl", 8, "TTL for fake packets (reaches DPI, not server)")
	runCmd.Flags().Bool("doh", true, "enable built-in DoH DNS resolver")
	runCmd.Flags().String("doh-upstream", "cloudflare", "DoH upstream: preset (cloudflare,google,quad9,nextdns,adguard) or URL")
	runCmd.Flags().Int("mss", 88, "TCP MSS for ClientHello fragmentation (Linux only)")
	runCmd.Flags().Int("restore-after-bytes", 600, "restore normal MSS after N bytes (Linux only)")
	runCmd.Flags().Int("restore-mss", 0, "restored MSS value, 0 = auto/1460 (Linux only)")
	runCmd.Flags().String("cgroup", "/sys/fs/cgroup", "cgroup v2 path (Linux only)")
	runCmd.Flags().BoolP("verbose", "v", false, "enable debug logging")

	viper.BindPFlag("verbose", runCmd.Flags().Lookup("verbose"))
	viper.BindPFlag("fake_ttl", runCmd.Flags().Lookup("fake-ttl"))
	viper.BindPFlag("doh_enabled", runCmd.Flags().Lookup("doh"))
	viper.BindPFlag("doh_upstream", runCmd.Flags().Lookup("doh-upstream"))
	viper.BindPFlag("mss", runCmd.Flags().Lookup("mss"))
	viper.BindPFlag("restore_after_bytes", runCmd.Flags().Lookup("restore-after-bytes"))
	viper.BindPFlag("restore_mss", runCmd.Flags().Lookup("restore-mss"))
	viper.BindPFlag("cgroup_path", runCmd.Flags().Lookup("cgroup"))

	rootCmd.AddCommand(runCmd)
}

func runEngine(cmd *cobra.Command, args []string) error {
	if err := checkPrivileges(); err != nil {
		return err
	}

	logger := newLogger(viper.GetBool("verbose"))

	cfg, err := engineConfigFromViper(viper.GetViper())
	if err != nil {
		return err
	}

	eng, err := newPlatformEngine(cfg, logger)
	if err != nil {
		return err
	}

	return supervise(eng, logger)
}

func engineConfigFromViper(v *viper.Viper) (engine.Config, error) {
	ports, err := toPorts(v.GetIntSlice("ports"))
	if err != nil {
		return engine.Config{}, err
	}

	cfg := engine.Config{
		MSS:               v.GetInt("mss"),
		RestoreMSS:        v.GetInt("restore_mss"),
		RestoreAfterBytes: v.GetInt("restore_after_bytes"),
		Ports:             ports,
		Interface:         v.GetString("interface"),
		CgroupPath:        v.GetString("cgroup_path"),
		FakeTTL:           v.GetInt("fake_ttl"),
		DoHEnabled:        v.GetBool("doh_enabled"),
		DoHUpstream:       v.GetString("doh_upstream"),
	}

	if err := validateConfig(cfg); err != nil {
		return engine.Config{}, err
	}
	return cfg, nil
}

// A port outside the uint16 range would otherwise wrap into a valid-looking
// one: 70000 becomes 4464.
func toPorts(ints []int) ([]uint16, error) {
	out := make([]uint16, len(ints))
	for i, v := range ints {
		if v < 1 || v > 65535 {
			return nil, fmt.Errorf("ports must be 1-65535, got %d", v)
		}
		out[i] = uint16(v)
	}
	return out, nil
}
