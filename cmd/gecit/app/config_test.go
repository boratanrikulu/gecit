package app

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/boratanrikulu/gecit/pkg/engine"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// Tests use their own viper. viper.Reset() on the global would wipe the
// bindings run.go and root.go install in init(), which the whole binary needs.
func testViper(t *testing.T, body string) *viper.Viper {
	t.Helper()
	v := viper.New()
	if err := readConfigFile(v, writeConfig(t, body), true); err != nil {
		t.Fatalf("read config: %v", err)
	}
	return v
}

func TestRenderConfigRoundTrips(t *testing.T) {
	cfg := engine.Config{
		MSS:               64,
		RestoreMSS:        1460,
		RestoreAfterBytes: 900,
		Ports:             []uint16{443, 8443, 9443},
		Interface:         `Local Area Connection #2`,
		CgroupPath:        "/sys/fs/cgroup/unified",
		FakeTTL:           12,
		DoHEnabled:        true,
		DoHUpstream:       "https://8.8.8.8/dns-query",
	}

	v := testViper(t, renderConfig(cfg))

	got := engine.Config{
		MSS:               v.GetInt("mss"),
		RestoreMSS:        v.GetInt("restore_mss"),
		RestoreAfterBytes: v.GetInt("restore_after_bytes"),
		Ports:             mustPorts(t, v.GetIntSlice("ports")),
		Interface:         v.GetString("interface"),
		CgroupPath:        v.GetString("cgroup_path"),
		FakeTTL:           v.GetInt("fake_ttl"),
		DoHEnabled:        v.GetBool("doh_enabled"),
		DoHUpstream:       v.GetString("doh_upstream"),
	}
	if !reflect.DeepEqual(got, cfg) {
		t.Errorf("round trip changed the config\n got %+v\nwant %+v", got, cfg)
	}
}

func mustPorts(t *testing.T, ints []int) []uint16 {
	t.Helper()
	ports, err := toPorts(ints)
	if err != nil {
		t.Fatalf("ports: %v", err)
	}
	return ports
}

// %v renders []uint16{443, 8443} as "[443 8443]", which YAML reads as one
// string and viper hands back as an empty slice.
func TestRenderConfigQuotesPortList(t *testing.T) {
	cfg := engine.DefaultConfig()
	cfg.Ports = []uint16{443, 8443}

	rendered := renderConfig(cfg)
	if !strings.Contains(rendered, "ports: [443, 8443]") {
		t.Errorf("ports line is not a YAML flow sequence:\n%s", rendered)
	}

	v := testViper(t, rendered)
	if got := v.GetIntSlice("ports"); !reflect.DeepEqual(got, []int{443, 8443}) {
		t.Errorf("ports = %v, want [443 8443]", got)
	}
}

// The config file has to beat a bound flag's default. viper consults a flag
// default only after the config file, but a viper bump could regress it and
// the failure mode is a silently ignored config file.
func TestConfigFileBeatsFlagDefault(t *testing.T) {
	v := viper.New()
	flags := pflag.NewFlagSet("run", pflag.ContinueOnError)
	flags.Int("fake-ttl", 8, "")
	v.BindPFlag("fake_ttl", flags.Lookup("fake-ttl"))

	if err := readConfigFile(v, writeConfig(t, "fake_ttl: 20\n"), true); err != nil {
		t.Fatal(err)
	}
	if got := v.GetInt("fake_ttl"); got != 20 {
		t.Errorf("fake_ttl = %d, want 20 from the config file", got)
	}

	if err := flags.Set("fake-ttl", "12"); err != nil {
		t.Fatal(err)
	}
	if got := v.GetInt("fake_ttl"); got != 12 {
		t.Errorf("fake_ttl = %d, want 12 from the flag", got)
	}
}

// run.go binds flags under snake_case viper keys. A misspelled binding key
// would leave the flag silently ignored while the config file kept working.
func TestRunFlagsBindToConfigKeys(t *testing.T) {
	for _, tc := range []struct {
		flag, key, value string
		read             func() string
	}{
		{"fake-ttl", "fake_ttl", "17", func() string { return viper.GetString("fake_ttl") }},
		{"doh-upstream", "doh_upstream", "quad9", func() string { return viper.GetString("doh_upstream") }},
		{"mss", "mss", "72", func() string { return viper.GetString("mss") }},
	} {
		f := runCmd.Flags().Lookup(tc.flag)
		if f == nil {
			t.Errorf("run has no --%s flag", tc.flag)
			continue
		}
		original := f.Value.String()
		if err := runCmd.Flags().Set(tc.flag, tc.value); err != nil {
			t.Fatal(err)
		}
		if got := tc.read(); got != tc.value {
			t.Errorf("--%s is not bound to viper key %q: got %q", tc.flag, tc.key, got)
		}
		if err := runCmd.Flags().Set(tc.flag, original); err != nil {
			t.Fatal(err)
		}
	}
}

// A default path that does not exist means "run on defaults", but a path the
// operator typed has to fail loudly.
func TestMissingConfigFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.yaml")

	if err := readConfigFile(viper.New(), missing, false); err != nil {
		t.Errorf("missing default path should be tolerated, got %v", err)
	}
	if err := readConfigFile(viper.New(), missing, true); err == nil {
		t.Error("missing explicit path should error")
	}
}

func TestMalformedConfigFileAlwaysErrors(t *testing.T) {
	path := writeConfig(t, "ports: [443\nfake_ttl: nope\n")
	if err := readConfigFile(viper.New(), path, false); err == nil {
		t.Error("malformed config should error even when the path is the default")
	}
}

// A misspelled key is a setting that silently does nothing, which is worse
// than a startup failure.
func TestUnknownConfigKeyRejected(t *testing.T) {
	path := writeConfig(t, "fake-ttl: 44\nfake_ttl: 8\n")
	err := readConfigFile(viper.New(), path, true)
	if err == nil {
		t.Fatal("unknown key should error")
	}
	if !strings.Contains(err.Error(), "fake-ttl") {
		t.Errorf("error should name the unknown key, got %v", err)
	}
}

func TestValidateConfig(t *testing.T) {
	valid := func() engine.Config {
		cfg := engine.DefaultConfig()
		cfg.Ports = []uint16{443}
		return cfg
	}

	if err := validateConfig(valid()); err != nil {
		t.Fatalf("default config should validate, got %v", err)
	}

	for name, mutate := range map[string]func(*engine.Config){
		"ttl zero":        func(c *engine.Config) { c.FakeTTL = 0 },
		"ttl negative":    func(c *engine.Config) { c.FakeTTL = -3 },
		"ttl over a byte": func(c *engine.Config) { c.FakeTTL = 256 },
		"no ports":        func(c *engine.Config) { c.Ports = nil },
		"port zero":       func(c *engine.Config) { c.Ports = []uint16{0} },
		"plaintext doh":   func(c *engine.Config) { c.DoHUpstream = "http://attacker.example/dns" },
		"empty doh":       func(c *engine.Config) { c.DoHUpstream = "" },
	} {
		cfg := valid()
		mutate(&cfg)
		if err := validateConfig(cfg); err == nil {
			t.Errorf("%s should be rejected", name)
		}
	}

	// A disabled resolver never dials, so its upstream does not matter.
	cfg := valid()
	cfg.DoHEnabled = false
	cfg.DoHUpstream = ""
	if err := validateConfig(cfg); err != nil {
		t.Errorf("upstream should be ignored when DoH is off, got %v", err)
	}
}

func TestToPortsRejectsOutOfRange(t *testing.T) {
	// uint16 conversion would turn 70000 into 4464.
	for _, ints := range [][]int{{70000}, {0}, {-1}, {443, 65536}} {
		if _, err := toPorts(ints); err == nil {
			t.Errorf("toPorts(%v) should error", ints)
		}
	}
	got, err := toPorts([]int{443, 8443})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []uint16{443, 8443}) {
		t.Errorf("toPorts = %v, want [443 8443]", got)
	}
}

// `config init` writes the file that loadConfig would refuse to read, so it
// must not inherit the root's config-loading hook.
func TestConfigInitSkipsConfigLoading(t *testing.T) {
	if configInitCmd.PersistentPreRunE == nil {
		t.Fatal("config init must shadow the root PersistentPreRunE")
	}
	if err := configInitCmd.PersistentPreRunE(configInitCmd, nil); err != nil {
		t.Errorf("config init hook should not read a config file, got %v", err)
	}
}

// Validation has to run on the path that actually builds the engine config,
// not only when called directly.
func TestEngineConfigFromViperValidates(t *testing.T) {
	good := testViper(t, renderConfig(engine.DefaultConfig()))
	cfg, err := engineConfigFromViper(good)
	if err != nil {
		t.Fatalf("default config should build, got %v", err)
	}
	if !reflect.DeepEqual(cfg.Ports, []uint16{443}) {
		t.Errorf("ports = %v, want [443]", cfg.Ports)
	}

	for name, body := range map[string]string{
		"plaintext doh":     "doh_upstream: \"http://attacker.example/dns\"\ndoh_enabled: true\nfake_ttl: 8\nports: [443]\n",
		"port out of range": "ports: [70000]\nfake_ttl: 8\ndoh_upstream: \"cloudflare\"\ndoh_enabled: true\n",
		"ttl out of range":  "ports: [443]\nfake_ttl: 300\ndoh_upstream: \"cloudflare\"\ndoh_enabled: true\n",
	} {
		v := testViper(t, body)
		if _, err := engineConfigFromViper(v); err == nil {
			t.Errorf("%s should be rejected by engineConfigFromViper", name)
		}
	}
}
