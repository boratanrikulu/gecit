package app

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/boratanrikulu/gecit/pkg/engine"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var configPath string

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage the gecit config file",
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Write a default config file if none exists",
	RunE:  runConfigInit,
}

var configPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Print the config file path gecit will read",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(resolveConfigPath())
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "",
		"config file (default "+defaultConfigPath()+")")
	rootCmd.PersistentPreRunE = loadConfig

	defaults := engine.DefaultConfig()
	configInitCmd.Flags().String("doh-upstream", defaults.DoHUpstream, "DoH upstream to write")
	configInitCmd.Flags().Int("fake-ttl", defaults.FakeTTL, "fake packet TTL to write")

	// init writes the file that loadConfig would refuse to read. cobra runs
	// only the nearest PersistentPreRunE, so this one shadows the root's.
	configInitCmd.PersistentPreRunE = func(*cobra.Command, []string) error { return nil }

	configCmd.AddCommand(configInitCmd, configPathCmd)
	rootCmd.AddCommand(configCmd)
}

func resolveConfigPath() string {
	if configPath != "" {
		return configPath
	}
	return defaultConfigPath()
}

// loadConfig reads the config file into viper. Values there sit below
// explicitly passed flags and above every default, so a flag still wins.
// A missing file at the default path is not an error: gecit runs on its
// defaults with no config file at all.
func loadConfig(cmd *cobra.Command, args []string) error {
	return readConfigFile(resolveConfigPath(), configPath != "")
}

func readConfigFile(path string, explicit bool) error {
	viper.SetConfigFile(path)
	err := viper.ReadInConfig()
	if err == nil {
		return nil
	}
	if !explicit && errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("read config %s: %w", path, err)
}

func runConfigInit(cmd *cobra.Command, args []string) error {
	path := resolveConfigPath()

	if _, err := os.Stat(path); err == nil {
		fmt.Printf("config already exists at %s, leaving it alone\n", path)
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}

	cfg := engine.DefaultConfig()
	cfg.DoHUpstream, _ = cmd.Flags().GetString("doh-upstream")
	cfg.FakeTTL, _ = cmd.Flags().GetInt("fake-ttl")

	if err := os.WriteFile(path, []byte(renderConfig(cfg)), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	fmt.Printf("wrote %s\n", path)
	return nil
}

func renderConfig(cfg engine.Config) string {
	return fmt.Sprintf(`# gecit configuration.
# Flags passed on the command line override every value here.

# Destination ports to target.
ports: %v

# Network interface to bind to. Empty means auto-detect.
# macOS and Windows only.
interface: %q

# TTL for fake packets. High enough to reach the DPI middlebox, low enough
# that it never reaches the server.
fake_ttl: %d

# Built-in DoH resolver. Disabling it leaves system DNS untouched.
doh_enabled: %t

# Preset (cloudflare, google, quad9, nextdns, adguard) or a URL.
# Comma-separated for fallback order.
doh_upstream: %q

# Debug logging.
verbose: false

# Linux only, ignored on macOS and Windows.
mss: %d
restore_after_bytes: %d
restore_mss: %d
cgroup_path: %q
`,
		cfg.Ports,
		cfg.Interface,
		cfg.FakeTTL,
		cfg.DoHEnabled,
		cfg.DoHUpstream,
		cfg.MSS,
		cfg.RestoreAfterBytes,
		cfg.RestoreMSS,
		cfg.CgroupPath,
	)
}
