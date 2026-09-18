package app

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Stamped by the build with
// -ldflags "-X github.com/boratanrikulu/gecit/cmd/gecit/app.version=0.2.0".
// A plain `go build` leaves it at dev, which is the honest answer for a binary
// no release produced.
var version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the gecit version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Print(versionLine())
	},
}

func versionLine() string {
	return fmt.Sprintf("gecit %s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
}

func init() {
	// --version and `version` answer the same question, so they print the same
	// line. Cobra's default template says "gecit version X" instead.
	rootCmd.Version = version
	rootCmd.SetVersionTemplate(versionLine())
	rootCmd.AddCommand(versionCmd)
}
