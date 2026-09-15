package app

import (
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

	eng, err := newPlatformEngine(engineConfigFromViper(), logger)
	if err != nil {
		return err
	}

	return supervise(eng, logger)
}

func engineConfigFromViper() engine.Config {
	return engine.Config{
		MSS:               viper.GetInt("mss"),
		RestoreMSS:        viper.GetInt("restore_mss"),
		RestoreAfterBytes: viper.GetInt("restore_after_bytes"),
		Ports:             toUint16Slice(viper.GetIntSlice("ports")),
		Interface:         viper.GetString("interface"),
		CgroupPath:        viper.GetString("cgroup_path"),
		FakeTTL:           viper.GetInt("fake_ttl"),
		DoHEnabled:        viper.GetBool("doh_enabled"),
		DoHUpstream:       viper.GetString("doh_upstream"),
	}
}

func toUint16Slice(ints []int) []uint16 {
	out := make([]uint16, len(ints))
	for i, v := range ints {
		out[i] = uint16(v)
	}
	return out
}
