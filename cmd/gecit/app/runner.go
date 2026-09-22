package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	gecitdns "github.com/boratanrikulu/gecit/pkg/dns"
	"github.com/boratanrikulu/gecit/pkg/engine"
	"github.com/boratanrikulu/gecit/pkg/panel"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// snapshot is everything the panel reads. It is replaced whole rather than
// mutated, so a reader never sees half a transition.
type snapshot struct {
	eng    engine.Engine
	cancel context.CancelFunc
	// running is the config the engine was built from, saved is what the config
	// file holds. They differ between a save and the apply that acts on it.
	running   engine.Config
	saved     engine.Config
	startedAt time.Time
	lastErr   string
}

// runner owns the engine so the panel can outlive it. Stopping and restarting
// the engine is a function call here rather than process management, which is
// the only form that works the same under the Windows service manager.
type runner struct {
	build    func(engine.Config) (engine.Engine, error)
	reload   func() (engine.Config, error)
	readFile func() (engine.Config, error)
	logger   *logrus.Logger

	// mu serializes lifecycle transitions and stays held across engine Start
	// and Stop, which take seconds. Readers go through live instead, so a poll
	// during a restart answers rather than queueing behind it.
	mu   sync.Mutex
	live atomic.Pointer[snapshot]
}

func newRunner(cfg engine.Config, logger *logrus.Logger) *runner {
	r := &runner{
		build:    func(c engine.Config) (engine.Engine, error) { return newPlatformEngine(c, logger) },
		reload:   reloadConfig,
		readFile: fileConfig,
		logger:   logger,
	}
	// Stored directly rather than through publish, which every other writer
	// reaches only under mu. Nothing else holds a reference to r yet.
	saved := cfg
	if fromFile, err := r.readFile(); err == nil {
		saved = fromFile
	}
	r.live.Store(&snapshot{running: cfg, saved: saved})
	return r
}

func (r *runner) Start() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.live.Load().eng != nil {
		return nil
	}

	// Start reads the config file rather than reusing what was loaded at
	// process start, so an edit saved while the engine was stopped is what
	// comes back up.
	cfg, err := r.reload()
	if err != nil {
		return err
	}
	r.publishSaved()
	r.applyLogLevel(cfg)
	return r.startLocked(cfg)
}

func (r *runner) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stopLocked()
}

// Apply rereads the config file and restarts the engine on it. Stopping has to
// complete before the new engine is built: building resolves the DoH upstream
// hostname through the system resolver, and while gecit runs that resolver is
// gecit itself.
func (r *runner) Apply() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	cfg, err := r.reload()
	if err != nil {
		return err
	}

	current := r.live.Load()
	previous := current.running
	wasRunning := current.eng != nil

	// Published before the stop: a teardown that reports a failure must not
	// leave the form showing values the file no longer holds.
	r.publishSaved()
	r.applyLogLevel(cfg)

	if err := r.stopLocked(); err != nil {
		return err
	}

	if !wasRunning {
		r.publish(func(s *snapshot) { s.running = cfg })
		return nil
	}

	startErr := r.startLocked(cfg)
	if startErr == nil {
		return nil
	}

	if rollbackErr := r.startLocked(previous); rollbackErr != nil {
		both := fmt.Errorf("the new config did not start (%w) and the previous one no longer starts either: %w",
			startErr, rollbackErr)
		r.publish(func(s *snapshot) { s.lastErr = both.Error() })
		return both
	}

	kept := fmt.Errorf("the new config did not start, kept the previous one: %w", startErr)
	r.publish(func(s *snapshot) { s.lastErr = kept.Error() })
	return kept
}

func (r *runner) startLocked(cfg engine.Config) error {
	eng, err := r.build(cfg)
	if err != nil {
		r.publish(func(s *snapshot) { s.lastErr = err.Error() })
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	if err := eng.Start(ctx); err != nil {
		cancel()
		r.publish(func(s *snapshot) { s.lastErr = err.Error() })
		return err
	}

	r.publish(func(s *snapshot) {
		s.eng = eng
		s.cancel = cancel
		s.running = cfg
		s.startedAt = time.Now()
		s.lastErr = ""
	})
	return nil
}

func (r *runner) stopLocked() error {
	current := r.live.Load()
	if current.eng == nil {
		return nil
	}

	err := current.eng.Stop()
	current.cancel()

	r.publish(func(s *snapshot) {
		s.eng = nil
		s.cancel = nil
		s.startedAt = time.Time{}
		if err != nil {
			s.lastErr = err.Error()
		}
	})
	return err
}

// publishSaved records what the config file holds, which is what the panel's
// form edits.
//
// A file it cannot read leaves the previous values in place and says why.
// Substituting the merged values would put a flag's value in the form, and the
// next save would write that over whatever the file actually holds. A missing
// file is not this case: it reads back as the built-in defaults.
func (r *runner) publishSaved() {
	saved, err := r.readFile()
	if err != nil {
		r.publish(func(s *snapshot) { s.lastErr = err.Error() })
		return
	}
	saved.Ports = slices.Clone(saved.Ports)
	r.publish(func(s *snapshot) { s.saved = saved })
}

// applyLogLevel puts the running logger where the config says, flags included:
// it is fed the same merged values the engine is built from. The panel's level
// selector is the runtime control, and an apply is the config winning, so a
// level set by hand goes back to what the config asks for.
func (r *runner) applyLogLevel(cfg engine.Config) {
	if cfg.Verbose {
		r.logger.SetLevel(logrus.DebugLevel)
		return
	}
	r.logger.SetLevel(logrus.InfoLevel)
}

// publish replaces the snapshot with a modified copy. Only called under mu.
func (r *runner) publish(mutate func(*snapshot)) {
	next := *r.live.Load()
	mutate(&next)
	r.live.Store(&next)
}

func (r *runner) Status() panel.Status {
	s := r.live.Load()

	status := panel.Status{Running: s.eng != nil, LastError: s.lastErr}
	if s.eng != nil {
		status.Mode = s.eng.Mode()
		status.StartedAt = s.startedAt
	}
	return status
}

func (r *runner) Stats() engine.Stats {
	s := r.live.Load()
	if s.eng == nil {
		return engine.Stats{}
	}
	return s.eng.Stats()
}

func (r *runner) Mode() string {
	s := r.live.Load()
	if s.eng == nil {
		return ""
	}
	return s.eng.Mode()
}

// Platform is computed once. The panel polls it every second, and on Windows
// the npcap probe enumerates every network device on the machine. Nothing it
// reports can usefully change while gecit runs: an engine that needs Npcap does
// not start without it.
func (r *runner) Platform() []panel.Fact { return cachedPlatformFacts() }

var cachedPlatformFacts = sync.OnceValue(platformFacts)

// Config reports what the config file holds, not what the engine is running and
// not the flag-merged values. The panel edits the file: handing it a flag's
// value would write that value into the file on the next save, on the same
// screen that says the flag wins over the file.
//
// Ports is cloned because the caller decodes a request body onto these values,
// and encoding/json reuses a slice that is long enough. Without the copy a PUT
// writes through into the snapshot every reader sees.
func (r *runner) Config() panel.ConfigView {
	values := r.live.Load().saved
	values.Ports = slices.Clone(values.Ports)

	return panel.ConfigView{
		Path:             resolveConfigPath(),
		Values:           values,
		OverriddenByFlag: flagOverrides(),
		DoHPresets:       gecitdns.PresetNames(),
	}
}

func (r *runner) SaveConfig(cfg engine.Config) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if err := writeConfigFile(resolveConfigPath(), cfg); err != nil {
		return err
	}
	cfg.Ports = slices.Clone(cfg.Ports)
	r.publish(func(s *snapshot) { s.saved = cfg })
	return nil
}

func (r *runner) LogLevel() string { return r.logger.GetLevel().String() }

// SetLogLevel is how the panel sees DNS resolutions, which are logged at debug.
// logrus checks the level before it fires a hook, so there is no way to feed the
// panel more than the logger is emitting.
func (r *runner) SetLogLevel(name string) error {
	level, err := logrus.ParseLevel(name)
	if err != nil {
		return fmt.Errorf("unknown log level %q", name)
	}
	if level != logrus.InfoLevel && level != logrus.DebugLevel {
		return errors.New("log level must be info or debug")
	}
	r.logger.SetLevel(level)
	return nil
}

// reloadConfig rereads the file under the flags already bound to viper, so a
// flag passed on the command line keeps winning over an edit made in the panel.
// This is what the engine runs on.
//
// It writes to the global viper, and the panel calls it from an HTTP goroutine.
// Both callers hold the runner's mutex, and nothing else reads that viper after
// startup: flagOverrides reads pflag, resolveConfigPath reads a var fixed at
// parse time, and panelFacts and fileConfig each use their own viper.
func reloadConfig() (engine.Config, error) {
	if err := loadConfig(); err != nil {
		return engine.Config{}, err
	}
	return engineConfigFromViper(viper.GetViper())
}

// fileConfig reads the config file on its own, with the built-in defaults under
// it and no flags over it. This is what the panel shows and writes back.
func fileConfig() (engine.Config, error) {
	defaults := engine.DefaultConfig()
	ports := make([]int, len(defaults.Ports))
	for i, p := range defaults.Ports {
		ports[i] = int(p)
	}

	v := viper.New()
	v.SetDefault("cgroup_path", defaults.CgroupPath)
	v.SetDefault("doh_enabled", defaults.DoHEnabled)
	v.SetDefault("doh_upstream", defaults.DoHUpstream)
	v.SetDefault("fake_ttl", defaults.FakeTTL)
	v.SetDefault("interface", defaults.Interface)
	v.SetDefault("mss", defaults.MSS)
	v.SetDefault("panel_addr", defaults.PanelAddr)
	v.SetDefault("panel_enabled", defaults.PanelEnabled)
	v.SetDefault("ports", ports)
	v.SetDefault("restore_after_bytes", defaults.RestoreAfterBytes)
	v.SetDefault("restore_mss", defaults.RestoreMSS)
	v.SetDefault("verbose", defaults.Verbose)

	if err := readConfigFile(v, resolveConfigPath(), configPath != ""); err != nil {
		return engine.Config{}, err
	}
	return engineConfigFromViper(v)
}

// writeConfigFile replaces the file in one step. The temporary lands in the
// same directory so it inherits the ACL that directory carries on Windows, and
// so the rename cannot cross a filesystem.
func writeConfigFile(path string, cfg engine.Config) error {
	if err := prepareConfigDir(path); err != nil {
		return err
	}

	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".config-*.yaml")
	if err != nil {
		return fmt.Errorf("create a temporary file in %s: %w", dir, err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)

	if _, err := f.WriteString(renderConfig(cfg)); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return fmt.Errorf("set permissions on %s: %w", tmp, err)
	}
	// The rename is atomic against a reader but not against a power cut, and
	// this is the file gecit reads at boot.
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("flush %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// flagForKey maps a config key to the flag that overrides it. A key an operator
// edits in the panel while the flag is set changes the file and nothing else,
// so the panel says which ones those are.
var flagForKey = map[string]string{
	"cgroup_path":         "cgroup",
	"doh_enabled":         "doh",
	"doh_upstream":        "doh-upstream",
	"fake_ttl":            "fake-ttl",
	"interface":           "interface",
	"mss":                 "mss",
	"panel_addr":          "panel-addr",
	"panel_enabled":       "panel",
	"ports":               "ports",
	"restore_after_bytes": "restore-after-bytes",
	"restore_mss":         "restore-mss",
	"verbose":             "verbose",
}

func flagOverrides() map[string]string {
	overrides := make(map[string]string)
	for key, name := range flagForKey {
		if f := lookupFlag(name); f != nil && f.Changed {
			overrides[key] = name
		}
	}
	return overrides
}

func lookupFlag(name string) *pflag.Flag {
	if f := runCmd.Flags().Lookup(name); f != nil {
		return f
	}
	return rootCmd.PersistentFlags().Lookup(name)
}
