package app

import (
	"strings"
	"testing"

	"github.com/boratanrikulu/gecit/pkg/engine"
	"github.com/spf13/viper"
)

// A bind failure is fatal when the operator asked for the panel and a warning
// when it is only the default. Getting this backwards either takes gecit down
// over a busy port or runs it with no panel while the config asked for one.
func TestPanelWasAskedFor(t *testing.T) {
	if panelWasAskedFor() {
		t.Fatal("nothing asked for the panel, yet the default counts as a request")
	}

	flag := runCmd.Flags().Lookup("panel-addr")
	if err := runCmd.Flags().Set("panel-addr", "127.0.0.1:9999"); err != nil {
		t.Fatal(err)
	}
	if !panelWasAskedFor() {
		t.Error("--panel-addr on the command line is a request")
	}
	runCmd.Flags().Set("panel-addr", "127.0.0.1:8088")
	flag.Changed = false

	if panelWasAskedFor() {
		t.Fatal("clearing the flag should go back to the default")
	}

	// The config file naming the key counts too, and that is the only signal a
	// Windows service has: it never sees a command line.
	original := configPath
	configPath = writeConfig(t, "panel_addr: \"127.0.0.1:9100\"\n")
	t.Cleanup(func() {
		configPath = original
		viper.GetViper().SetConfigFile("")
	})
	if err := loadConfig(); err != nil {
		t.Fatal(err)
	}
	if !panelWasAskedFor() {
		t.Error("panel_addr in the config file is a request")
	}
}

// `gecit status` has to keep working when the config file is the broken thing:
// it is what an operator runs to find out why nothing else does.
func TestPanelFactsToleratesABrokenConfig(t *testing.T) {
	original := configPath
	t.Cleanup(func() { configPath = original })

	for name, body := range map[string]string{
		"malformed":   "ports: [443\nfake_ttl: nope\n",
		"unknown key": "fake-ttl: 44\n",
		"empty":       "",
	} {
		configPath = writeConfig(t, body)
		facts := panelFacts()
		if len(facts) != 1 || facts[0].Name != "panel" {
			t.Errorf("%s: facts = %+v, want one panel line", name, facts)
			continue
		}
		if !strings.Contains(facts[0].Value, "http://gecit.localhost:8088/") {
			t.Errorf("%s: value = %q, want the default address", name, facts[0].Value)
		}
	}

	configPath = writeConfig(t, "panel_enabled: false\n")
	if facts := panelFacts(); facts[0].Value != "disabled" {
		t.Errorf("a disabled panel reads %q", facts[0].Value)
	}

	configPath = writeConfig(t, "panel_addr: \"127.0.0.2:9100\"\n")
	if facts := panelFacts(); !strings.Contains(facts[0].Value, "127.0.0.2:9100") {
		t.Errorf("the configured address is not reported: %q", facts[0].Value)
	}
}

// renderConfig rewrites the whole file on every panel save, so a key it does
// not carry is a key the panel silently wipes.
func TestRenderConfigCarriesVerbose(t *testing.T) {
	cfg := engine.DefaultConfig()
	cfg.Verbose = true

	v := testViper(t, renderConfig(cfg))
	if !v.GetBool("verbose") {
		t.Error("verbose: true did not survive a save")
	}
}
