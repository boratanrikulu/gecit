package app

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	gecitdns "github.com/boratanrikulu/gecit/pkg/dns"
	"github.com/boratanrikulu/gecit/pkg/engine"
	"github.com/boratanrikulu/gecit/pkg/panel"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var configPath string

// Every key gecit reads. A file key outside this set is a typo that would
// otherwise do nothing at all.
var configKeys = []string{
	"cgroup_path",
	"doh_enabled",
	"doh_upstream",
	"fake_ttl",
	"interface",
	"mss",
	"panel_addr",
	"panel_enabled",
	"ports",
	"restore_after_bytes",
	"restore_mss",
	"verbose",
}

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

	defaults := engine.DefaultConfig()
	configInitCmd.Flags().String("doh-upstream", defaults.DoHUpstream, "DoH upstream to write")
	configInitCmd.Flags().Int("fake-ttl", defaults.FakeTTL, "fake packet TTL to write")

	configCmd.AddCommand(configInitCmd, configPathCmd)
	rootCmd.AddCommand(configCmd)
}

func resolveConfigPath() string {
	if configPath != "" {
		return configPath
	}
	return defaultConfigPath()
}

// loadConfig is called by `run` alone. cleanup, status and the service verbs
// have to keep working when the config file is the broken thing: the installer
// runs `gecit cleanup` on uninstall, and refusing there would leave the machine
// pointing at a resolver that is being removed.
func loadConfig() error {
	return readConfigFile(viper.GetViper(), resolveConfigPath(), configPath != "")
}

// readConfigFile layers a config file under the flags already bound to v.
// viper resolves a passed flag above the file and the file above a flag's
// default, so a flag still wins. A missing file at the default path is not an
// error: gecit runs on its defaults with no config file at all.
func readConfigFile(v *viper.Viper, path string, explicit bool) error {
	v.SetConfigFile(path)
	err := v.ReadInConfig()
	if err != nil {
		if !explicit && errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read config %s: %w", path, err)
	}
	return checkConfigKeys(v, path)
}

func checkConfigKeys(v *viper.Viper, path string) error {
	known := make(map[string]bool, len(configKeys))
	for _, k := range configKeys {
		known[k] = true
	}

	var unknown []string
	for k := range v.AllSettings() {
		if !known[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf("read config %s: unknown %s: %s",
		path, plural("key", len(unknown)), strings.Join(unknown, ", "))
}

func plural(word string, n int) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

func runConfigInit(cmd *cobra.Command, args []string) error {
	// The file configures a process that runs as root or LocalSystem, so it
	// has to be written somewhere an unprivileged user cannot reach.
	if err := checkPrivileges(); err != nil {
		return err
	}

	path := resolveConfigPath()

	if _, err := os.Stat(path); err == nil {
		fmt.Printf("config already exists at %s, leaving it alone\n", path)
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	cfg := engine.DefaultConfig()
	upstream, err := cmd.Flags().GetString("doh-upstream")
	if err != nil {
		return err
	}
	ttl, err := cmd.Flags().GetInt("fake-ttl")
	if err != nil {
		return err
	}
	cfg.DoHUpstream = upstream
	cfg.FakeTTL = ttl

	if err := validateConfig(cfg); err != nil {
		return err
	}

	if err := prepareConfigDir(path); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(renderConfig(cfg)), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	fmt.Printf("wrote %s\n", path)
	return nil
}

// prepareConfigDir hardens the directory gecit owns. A path the operator chose
// with --config may hold unrelated files, and rewriting its ACL would demote
// everyone else's access to them.
func prepareConfigDir(path string) error {
	dir := filepath.Dir(path)
	if path == defaultConfigPath() {
		return createDataDir(dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	return nil
}

// validateConfig rejects settings that would otherwise fail silently or in a
// way that is hard to trace back here.
func validateConfig(cfg engine.Config) error {
	if cfg.FakeTTL < 1 || cfg.FakeTTL > 255 {
		return fmt.Errorf("fake_ttl must be 1-255, got %d", cfg.FakeTTL)
	}
	if len(cfg.Ports) == 0 {
		return errors.New("ports must list at least one port")
	}
	for _, p := range cfg.Ports {
		if p == 0 {
			return errors.New("ports must be 1-65535, got 0")
		}
	}
	if cfg.DoHEnabled {
		if err := gecitdns.ValidateUpstreams(cfg.DoHUpstream); err != nil {
			return fmt.Errorf("doh_upstream: %w", err)
		}
	}
	if cfg.PanelEnabled {
		if err := panel.ValidateAddr(cfg.PanelAddr); err != nil {
			return err
		}
	}
	return nil
}

func renderConfig(cfg engine.Config) string {
	return fmt.Sprintf(`# gecit configuration.
# Flags passed on the command line override every value here.

# Destination ports to target.
ports: %s

# Network interface to bind to. Empty means auto-detect.
# macOS and Windows only.
interface: %q

# TTL for fake packets. High enough to reach the DPI middlebox, low enough
# that it never reaches the server.
fake_ttl: %d

# Built-in DoH resolver. Disabling it leaves system DNS untouched.
# Write true or false. YAML reads a bare yes or no as a string, which reads
# back here as false.
doh_enabled: %t

# Preset (cloudflare, google, quad9, nextdns, adguard) or an https URL.
# Comma-separated for fallback order.
doh_upstream: %q

# Debug logging.
verbose: %t

# Local web panel: stats, logs and this config in a browser.
# Loopback only, and it requires the token in %s.
# Reached at http://gecit.localhost:8088, which needs no DNS record.
panel_enabled: %t
panel_addr: %q

# Linux only, ignored on macOS and Windows.
mss: %d
restore_after_bytes: %d
restore_mss: %d
cgroup_path: %q
`,
		formatPorts(cfg.Ports),
		cfg.Interface,
		cfg.FakeTTL,
		cfg.DoHEnabled,
		cfg.DoHUpstream,
		cfg.Verbose,
		panelTokenPath(),
		cfg.PanelEnabled,
		cfg.PanelAddr,
		cfg.MSS,
		cfg.RestoreAfterBytes,
		cfg.RestoreMSS,
		cfg.CgroupPath,
	)
}

// A YAML flow sequence needs commas. Formatting the slice with %v yields
// "[443 8443]", which parses back as a single string.
func formatPorts(ports []uint16) string {
	out := make([]string, len(ports))
	for i, p := range ports {
		out[i] = strconv.Itoa(int(p))
	}
	return "[" + strings.Join(out, ", ") + "]"
}
