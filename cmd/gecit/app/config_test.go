package app

import (
	"os"
	"path/filepath"
	"reflect"
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

func TestRenderConfigRoundTrips(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	cfg := engine.DefaultConfig()
	cfg.DoHUpstream = "quad9,cloudflare"
	cfg.FakeTTL = 12

	if err := readConfigFile(writeConfig(t, renderConfig(cfg)), true); err != nil {
		t.Fatalf("read rendered config: %v", err)
	}

	if got := viper.GetString("doh_upstream"); got != "quad9,cloudflare" {
		t.Errorf("doh_upstream = %q, want %q", got, "quad9,cloudflare")
	}
	if got := viper.GetInt("fake_ttl"); got != 12 {
		t.Errorf("fake_ttl = %d, want 12", got)
	}
	if got := viper.GetBool("doh_enabled"); got != cfg.DoHEnabled {
		t.Errorf("doh_enabled = %v, want %v", got, cfg.DoHEnabled)
	}
	if got := viper.GetIntSlice("ports"); len(got) != 1 || got[0] != 443 {
		t.Errorf("ports = %v, want [443]", got)
	}
	if got := viper.GetString("cgroup_path"); got != cfg.CgroupPath {
		t.Errorf("cgroup_path = %q, want %q", got, cfg.CgroupPath)
	}
}

// The config file has to beat a bound flag's default value. viper consults a
// flag default only after the config file, but a viper bump could regress it
// and the failure mode is a silently ignored config file.
func TestConfigFileBeatsFlagDefault(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	flags := pflag.NewFlagSet("run", pflag.ContinueOnError)
	flags.Int("fake-ttl", 8, "")
	viper.BindPFlag("fake_ttl", flags.Lookup("fake-ttl"))

	if err := readConfigFile(writeConfig(t, "fake_ttl: 20\n"), true); err != nil {
		t.Fatal(err)
	}

	if got := viper.GetInt("fake_ttl"); got != 20 {
		t.Errorf("fake_ttl = %d, want 20 from the config file", got)
	}
}

func TestChangedFlagBeatsConfigFile(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	flags := pflag.NewFlagSet("run", pflag.ContinueOnError)
	flags.Int("fake-ttl", 8, "")
	viper.BindPFlag("fake_ttl", flags.Lookup("fake-ttl"))

	if err := readConfigFile(writeConfig(t, "fake_ttl: 20\n"), true); err != nil {
		t.Fatal(err)
	}
	if err := flags.Set("fake-ttl", "12"); err != nil {
		t.Fatal(err)
	}

	if got := viper.GetInt("fake_ttl"); got != 12 {
		t.Errorf("fake_ttl = %d, want 12 from the flag", got)
	}
}

// A default path that does not exist means "run on defaults", but a path the
// operator typed has to fail loudly.
func TestMissingConfigFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.yaml")

	viper.Reset()
	if err := readConfigFile(missing, false); err != nil {
		t.Errorf("missing default path should be tolerated, got %v", err)
	}

	viper.Reset()
	t.Cleanup(viper.Reset)
	if err := readConfigFile(missing, true); err == nil {
		t.Error("missing explicit path should error")
	}
}

func TestMalformedConfigFileAlwaysErrors(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	path := writeConfig(t, "ports: [443\nfake_ttl: nope\n")
	if err := readConfigFile(path, false); err == nil {
		t.Error("malformed config should error even when the path is the default")
	}
}

// The engine has to receive what the config file says, which is the whole
// point of the file existing.
func TestConfigFileReachesEngineConfig(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	body := `ports: [443, 8443]
interface: "eth0"
fake_ttl: 11
doh_enabled: false
doh_upstream: "https://8.8.8.8/dns-query"
mss: 64
restore_after_bytes: 900
restore_mss: 1460
cgroup_path: "/sys/fs/cgroup/unified"
`
	if err := readConfigFile(writeConfig(t, body), true); err != nil {
		t.Fatal(err)
	}

	got := engineConfigFromViper()
	want := engine.Config{
		MSS:               64,
		RestoreMSS:        1460,
		RestoreAfterBytes: 900,
		Ports:             []uint16{443, 8443},
		Interface:         "eth0",
		CgroupPath:        "/sys/fs/cgroup/unified",
		FakeTTL:           11,
		DoHEnabled:        false,
		DoHUpstream:       "https://8.8.8.8/dns-query",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("engine config = %+v, want %+v", got, want)
	}
}
