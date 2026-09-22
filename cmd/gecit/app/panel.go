package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/boratanrikulu/gecit/pkg/engine"
	"github.com/boratanrikulu/gecit/pkg/panel"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// A few thousand lines is minutes of history on a busy machine and a couple of
// megabytes of memory. It holds the domains the machine resolved and connected
// to, so it never reaches disk and dies with the process.
const logRingSize = 2000

const panelShutdownTimeout = 5 * time.Second

func panelTokenPath() string { return filepath.Join(gecitDataDir(), "panel.token") }

// startPanel brings the panel up beside the engine. A bind failure is fatal
// when the panel was asked for and a warning when it is only the default: the
// engine is the point, and a panel nobody asked for must not keep gecit down.
func startPanel(r *runner, cfg engine.Config, logger *logrus.Logger) (*panel.Server, error) {
	// The ring holds the domains the machine resolved and connected to. With no
	// panel to read it there is no reason to keep them, so it is not built.
	if !cfg.PanelEnabled {
		return nil, nil
	}

	ring := panel.NewRing(logRingSize)
	panel.Capture(ring, logger)

	srv, err := buildPanel(r, cfg, ring, logger)
	if err == nil {
		err = srv.Start()
	}
	if err != nil {
		if panelWasAskedFor() {
			return nil, err
		}
		logger.WithError(err).
			Warn("web panel unavailable, set panel_addr to a free port; gecit is running without it")
		return nil, nil
	}

	announcePanel(srv, logger)
	return srv, nil
}

// announcePanel keeps the token off every durable sink. The logger feeds the
// panel's own log tab, and under the Windows service it feeds
// %ProgramData%\gecit\gecit.log, which operators can read. A terminal is the
// one place the URL can be printed without leaving a copy behind.
func announcePanel(srv *panel.Server, logger *logrus.Logger) {
	logger.WithField("addr", srv.Addr()).Info("web panel is listening")

	if !isTerminal(os.Stdout) {
		logger.Info("run `gecit status` to print the panel URL with its token")
		return
	}
	fmt.Println("web panel: " + srv.URL())
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func buildPanel(r *runner, cfg engine.Config, ring *panel.Ring, logger *logrus.Logger) (*panel.Server, error) {
	if err := createDataDir(gecitDataDir()); err != nil {
		return nil, err
	}
	token, err := panel.LoadOrCreateToken(panelTokenPath())
	if err != nil {
		return nil, err
	}

	return panel.New(panel.Options{
		Addr:   cfg.PanelAddr,
		Token:  token,
		Ctrl:   r,
		Ring:   ring,
		Logger: logger,
	})
}

func stopPanel(srv *panel.Server, logger *logrus.Logger) {
	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), panelShutdownTimeout)
	defer cancel()
	if err := srv.Stop(ctx); err != nil {
		logger.WithError(err).Warn("web panel did not shut down cleanly")
	}
}

// panelWasAskedFor separates "the operator wants the panel" from "the panel is
// on because that is the default".
func panelWasAskedFor() bool {
	if f := lookupFlag("panel"); f != nil && f.Changed {
		return true
	}
	if f := lookupFlag("panel-addr"); f != nil && f.Changed {
		return true
	}
	return viper.InConfig("panel_enabled") || viper.InConfig("panel_addr")
}

// panelFacts describes the panel for `gecit status`, which runs in a different
// process than the one serving it. The config file is read tolerantly on
// purpose: status has to keep working when that file is the broken thing, so a
// failure here falls back to the built-in default rather than reporting nothing.
func panelFacts() []panel.Fact {
	cfg := engine.DefaultConfig()
	if v := viper.New(); readConfigFile(v, resolveConfigPath(), false) == nil {
		if addr := v.GetString("panel_addr"); addr != "" {
			cfg.PanelAddr = addr
		}
		if v.IsSet("panel_enabled") {
			cfg.PanelEnabled = v.GetBool("panel_enabled")
		}
	}

	if !cfg.PanelEnabled {
		return []panel.Fact{{Name: "panel", Value: "disabled"}}
	}

	token, err := panel.ReadToken(panelTokenPath())
	if err != nil {
		return []panel.Fact{{Name: "panel", Value: panel.URL(cfg.PanelAddr, "") + " " + tokenHint(err)}}
	}

	return []panel.Fact{{Name: "panel", Value: panel.URL(cfg.PanelAddr, token)}}
}

func tokenHint(err error) string {
	if errors.Is(err, fs.ErrNotExist) {
		return "(the token is created the first time gecit runs)"
	}
	return "(" + err.Error() + ")"
}
