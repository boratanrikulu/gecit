package app

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/boratanrikulu/gecit/pkg/engine"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type fakeEngine struct {
	cfg      engine.Config
	events   *[]string
	startErr error
	stopErr  error
}

func (e *fakeEngine) Start(context.Context) error {
	*e.events = append(*e.events, "start:"+e.cfg.DoHUpstream)
	return e.startErr
}

func (e *fakeEngine) Stop() error {
	*e.events = append(*e.events, "stop:"+e.cfg.DoHUpstream)
	return e.stopErr
}

func (e *fakeEngine) Mode() string        { return "fake" }
func (e *fakeEngine) Stats() engine.Stats { return engine.Stats{Connections: 1} }

func testRunner(t *testing.T, cfg engine.Config) (*runner, *[]string) {
	t.Helper()

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	events := &[]string{}
	r := newRunner(cfg, logger)
	r.build = func(c engine.Config) (engine.Engine, error) {
		*events = append(*events, "build:"+c.DoHUpstream)
		return &fakeEngine{cfg: c, events: events}, nil
	}
	r.reload = func() (engine.Config, error) { return cfg, nil }
	r.readFile = func() (engine.Config, error) { return cfg, nil }
	r.publishSaved()
	return r, events
}

func config(upstream string) engine.Config {
	cfg := engine.DefaultConfig()
	cfg.DoHUpstream = upstream
	return cfg
}

func TestRunnerStartStopAreIdempotent(t *testing.T) {
	r, events := testRunner(t, config("cloudflare"))

	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	if !r.Status().Running {
		t.Error("runner should report running")
	}

	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if r.Status().Running {
		t.Error("runner should report stopped")
	}

	want := "build:cloudflare start:cloudflare stop:cloudflare"
	if got := strings.Join(*events, " "); got != want {
		t.Errorf("engine calls = %q, want %q", got, want)
	}
}

// Building an engine resolves the DoH upstream hostname through the system
// resolver, and while gecit runs that resolver is gecit. Building the new
// engine before the old one has let go of DNS sends the lookup into a resolver
// that is being torn down.
func TestApplyStopsBeforeItBuilds(t *testing.T) {
	r, events := testRunner(t, config("cloudflare"))
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	r.reload = func() (engine.Config, error) { return config("quad9"), nil }
	r.readFile = r.reload

	if err := r.Apply(); err != nil {
		t.Fatal(err)
	}

	want := "build:cloudflare start:cloudflare stop:cloudflare build:quad9 start:quad9"
	if got := strings.Join(*events, " "); got != want {
		t.Errorf("engine calls = %q,\n              want %q", got, want)
	}
	if got := r.live.Load().running.DoHUpstream; got != "quad9" {
		t.Errorf("the engine is still running %q", got)
	}
	if got := r.Config().Values.DoHUpstream; got != "quad9" {
		t.Errorf("the config view still reads %q", got)
	}
}

func TestApplyRollsBackWhenTheNewConfigFails(t *testing.T) {
	r, events := testRunner(t, config("cloudflare"))
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}

	r.reload = func() (engine.Config, error) { return config("broken"), nil }
	r.readFile = r.reload
	r.build = func(c engine.Config) (engine.Engine, error) {
		e := &fakeEngine{cfg: c, events: events}
		if c.DoHUpstream == "broken" {
			e.startErr = errors.New("create TUN: operation not permitted")
		}
		*events = append(*events, "build:"+c.DoHUpstream)
		return e, nil
	}

	err := r.Apply()
	if err == nil {
		t.Fatal("Apply should report that the new config did not start")
	}
	if !strings.Contains(err.Error(), "kept the previous one") {
		t.Errorf("error = %v, want it to say the previous config is back", err)
	}

	if !r.Status().Running {
		t.Fatal("the previous config should be running again")
	}
	if got := r.live.Load().running.DoHUpstream; got != "cloudflare" {
		t.Errorf("running config = %q, want the previous one", got)
	}
	// The file holds what was saved, and the panel's form edits the file. The
	// two disagreeing is the whole point of the rollback.
	if got := r.Config().Values.DoHUpstream; got != "broken" {
		t.Errorf("config view = %q, want what the file holds", got)
	}
	if r.Status().LastError == "" {
		t.Error("a rolled back apply should leave the reason in the status")
	}

	want := "build:cloudflare start:cloudflare stop:cloudflare build:broken start:broken build:cloudflare start:cloudflare"
	if got := strings.Join(*events, " "); got != want {
		t.Errorf("engine calls = %q,\n              want %q", got, want)
	}
}

func TestApplyLeavesTheEngineStoppedWhenRollbackAlsoFails(t *testing.T) {
	r, events := testRunner(t, config("cloudflare"))
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}

	r.reload = func() (engine.Config, error) { return config("quad9"), nil }
	r.readFile = r.reload
	r.build = func(c engine.Config) (engine.Engine, error) {
		*events = append(*events, "build:"+c.DoHUpstream)
		return &fakeEngine{cfg: c, events: events, startErr: errors.New("the NIC went away")}, nil
	}

	err := r.Apply()
	if err == nil {
		t.Fatal("Apply should report the failure")
	}
	if !strings.Contains(err.Error(), "no longer starts either") {
		t.Errorf("error = %v, want it to say the previous config failed too", err)
	}
	if r.Status().Running {
		t.Error("the runner should report stopped, not a state it is not in")
	}
}

// Apply on a stopped engine records the new config without starting anything:
// an operator who stopped gecit from the panel did not ask for it back.
func TestApplyOnAStoppedEngineDoesNotStartIt(t *testing.T) {
	r, events := testRunner(t, config("cloudflare"))
	r.reload = func() (engine.Config, error) { return config("quad9"), nil }
	r.readFile = r.reload

	if err := r.Apply(); err != nil {
		t.Fatal(err)
	}
	if r.Status().Running {
		t.Error("Apply should not have started a stopped engine")
	}
	if len(*events) != 0 {
		t.Errorf("engine calls = %v, want none", *events)
	}
	if r.Config().Values.DoHUpstream != "quad9" {
		t.Error("the new config should be the one a later Start uses")
	}
}

func TestApplyReportsABrokenConfigFile(t *testing.T) {
	r, events := testRunner(t, config("cloudflare"))
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	r.reload = func() (engine.Config, error) {
		return engine.Config{}, errors.New("unknown key: fake-ttl")
	}

	if err := r.Apply(); err == nil {
		t.Fatal("Apply should report the config error")
	}
	if !r.Status().Running {
		t.Error("a config that cannot be read must not take the running engine down")
	}
	if got := strings.Join(*events, " "); got != "build:cloudflare start:cloudflare" {
		t.Errorf("engine calls = %q, want the engine left alone", got)
	}
}

func TestStatsAreZeroWhileStopped(t *testing.T) {
	r, _ := testRunner(t, config("cloudflare"))

	if got := r.Stats(); got.Connections != 0 {
		t.Errorf("stats while stopped = %+v, want zeroes", got)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	if got := r.Stats(); got.Connections != 1 {
		t.Errorf("stats while running = %+v, want the engine's", got)
	}
}

func TestSetLogLevel(t *testing.T) {
	r, _ := testRunner(t, config("cloudflare"))

	if err := r.SetLogLevel("debug"); err != nil {
		t.Fatal(err)
	}
	if r.LogLevel() != "debug" {
		t.Errorf("log level = %q, want debug", r.LogLevel())
	}

	// trace and below would flood the ring with sing-tun internals, and panic
	// is not a level anything should be pinned to from a browser.
	for _, level := range []string{"trace", "panic", "warn", "nonsense"} {
		if err := r.SetLogLevel(level); err == nil {
			t.Errorf("SetLogLevel(%q) should be refused", level)
		}
	}
	if r.LogLevel() != "debug" {
		t.Errorf("a refused level changed the logger to %q", r.LogLevel())
	}
}

// The panel writes the file the CLI reads, so what it writes has to come back
// through the same loader.
func TestWriteConfigFileRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg := engine.DefaultConfig()
	cfg.FakeTTL = 14
	cfg.Ports = []uint16{443, 8443}
	cfg.DoHUpstream = "quad9"
	cfg.PanelAddr = "127.0.0.1:9100"

	if err := writeConfigFile(path, cfg); err != nil {
		t.Fatal(err)
	}

	v := viper.New()
	if err := readConfigFile(v, path, true); err != nil {
		t.Fatalf("the written file does not load: %v", err)
	}
	if v.GetInt("fake_ttl") != 14 || v.GetString("doh_upstream") != "quad9" {
		t.Errorf("values did not survive: ttl %d upstream %q", v.GetInt("fake_ttl"), v.GetString("doh_upstream"))
	}
	if v.GetString("panel_addr") != "127.0.0.1:9100" || !v.GetBool("panel_enabled") {
		t.Errorf("panel keys did not survive: %q %v", v.GetString("panel_addr"), v.GetBool("panel_enabled"))
	}
}

func TestWriteConfigFileReplacesAndLeavesNoTemporary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("fake_ttl: 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := writeConfigFile(path, engine.DefaultConfig()); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "fake_ttl: 3") {
		t.Error("the old contents are still there")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("directory holds %v, want only config.yaml", names)
	}
}

func TestSaveConfigRefusesWhatTheCLIWouldRefuse(t *testing.T) {
	r, _ := testRunner(t, config("cloudflare"))

	bad := engine.DefaultConfig()
	bad.FakeTTL = 0
	if err := r.SaveConfig(bad); err == nil {
		t.Error("a config the CLI rejects must not be written from the panel")
	}

	remote := engine.DefaultConfig()
	remote.PanelAddr = "0.0.0.0:8088"
	if err := r.SaveConfig(remote); err == nil {
		t.Error("a non-loopback panel address must not be writable from the panel")
	}
}

// Every key the panel shows has to name a flag that exists, or an override
// silently never reports itself.
func TestFlagForKeyNamesRealFlags(t *testing.T) {
	for key, name := range flagForKey {
		if lookupFlag(name) == nil {
			t.Errorf("config key %q maps to flag --%s, which no command defines", key, name)
		}
	}
	for _, key := range configKeys {
		if _, ok := flagForKey[key]; !ok {
			t.Errorf("config key %q has no flag mapping, so the panel cannot say when it is overridden", key)
		}
	}
}

func TestFlagOverridesReportsWhatWasPassed(t *testing.T) {
	if got := flagOverrides(); len(got) != 0 {
		t.Fatalf("no flag was passed, got overrides %v", got)
	}

	flag := rootCmd.PersistentFlags().Lookup("interface")
	if err := rootCmd.PersistentFlags().Set("interface", "en0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		rootCmd.PersistentFlags().Set("interface", "")
		flag.Changed = false
	})

	got := flagOverrides()
	if len(got) != 1 || got["interface"] != "interface" {
		t.Errorf("overrides = %v, want only interface mapped to its flag", got)
	}
}

// encoding/json reuses a slice that is long enough, so the panel's PUT handler
// decodes straight into whatever Config hands it. Sharing the backing array
// would let one request rewrite the ports in the live snapshot.
func TestConfigDoesNotShareItsPortsSlice(t *testing.T) {
	r, _ := testRunner(t, config("cloudflare"))

	view := r.Config()
	if len(view.Values.Ports) == 0 {
		t.Fatal("no ports to alias")
	}
	view.Values.Ports[0] = 9999

	if got := r.Config().Values.Ports[0]; got == 9999 {
		t.Error("writing to the returned slice changed the runner's own state")
	}
}

// The form edits the config file. Seeding it from the flag-merged values means
// the next save writes a flag's value into the file, on the same screen that
// says the flag wins over the file.
func TestConfigReportsTheFileNotTheFlags(t *testing.T) {
	merged := config("cloudflare")
	merged.FakeTTL = 4 // as if --fake-ttl 4 were passed

	r, _ := testRunner(t, merged)
	fromFile := config("cloudflare")
	fromFile.FakeTTL = 8
	r.readFile = func() (engine.Config, error) { return fromFile, nil }
	r.publishSaved()

	if got := r.Config().Values.FakeTTL; got != 8 {
		t.Errorf("config view reports fake_ttl %d, want the file's 8", got)
	}
}

// A file that will not read must not be papered over with the merged values:
// the next save would write a flag's value where the file has something else.
func TestConfigKeepsTheLastGoodValuesWhenTheFileWillNotRead(t *testing.T) {
	fromFile := config("quad9")
	fromFile.FakeTTL = 9
	r, _ := testRunner(t, config("cloudflare"))
	r.readFile = func() (engine.Config, error) { return fromFile, nil }
	r.publishSaved()

	r.readFile = func() (engine.Config, error) {
		return engine.Config{}, errors.New("panel_addr \"0.0.0.0:8088\" is not loopback")
	}
	r.publishSaved()

	if got := r.Config().Values.FakeTTL; got != 9 {
		t.Errorf("config view = %d, want the last values actually read from the file", got)
	}
	if !strings.Contains(r.Status().LastError, "not loopback") {
		t.Errorf("the panel is not told why the file was ignored: %q", r.Status().LastError)
	}
}

// An apply is the config file winning, including over a level set by hand in
// the panel while it was running.
func TestApplyPutsTheLoggerWhereTheFileSays(t *testing.T) {
	cfg := config("cloudflare")
	cfg.Verbose = true
	r, _ := testRunner(t, cfg)

	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	if r.LogLevel() != "debug" {
		t.Errorf("log level = %q, want debug from verbose: true", r.LogLevel())
	}

	quiet := config("cloudflare")
	r.reload = func() (engine.Config, error) { return quiet, nil }
	r.readFile = r.reload
	if err := r.Apply(); err != nil {
		t.Fatal(err)
	}
	if r.LogLevel() != "info" {
		t.Errorf("log level = %q, want info from verbose: false", r.LogLevel())
	}
}

// Stop, edit, save, start: the engine has to come up on what was saved, not on
// what it was running before it was stopped.
func TestStartPicksUpASaveMadeWhileStopped(t *testing.T) {
	r, events := testRunner(t, config("cloudflare"))

	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}

	r.reload = func() (engine.Config, error) { return config("quad9"), nil }
	r.readFile = r.reload
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}

	want := "build:cloudflare start:cloudflare stop:cloudflare build:quad9 start:quad9"
	if got := strings.Join(*events, " "); got != want {
		t.Errorf("engine calls = %q,\n              want %q", got, want)
	}
}

// The picker is built from what the resolver reports, so the page cannot drift
// from the names validateConfig will accept.
func TestConfigCarriesTheDoHPresets(t *testing.T) {
	r, _ := testRunner(t, config("cloudflare"))

	got := r.Config().DoHPresets
	if len(got) == 0 {
		t.Fatal("the config view offers no upstream presets")
	}
	for _, name := range got {
		cfg := engine.DefaultConfig()
		cfg.DoHUpstream = name
		if err := validateConfig(cfg); err != nil {
			t.Errorf("the panel offers %q, which validateConfig rejects: %v", name, err)
		}
	}
}
