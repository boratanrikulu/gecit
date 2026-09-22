package app

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show gecit status and system capabilities",
	RunE:  showStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func showStatus(cmd *cobra.Command, args []string) error {
	fmt.Printf("gecit status\n")
	fmt.Printf("  %-12s%s/%s\n", "platform:", runtime.GOOS, runtime.GOARCH)
	for _, f := range platformFacts() {
		fmt.Printf("  %-12s%s\n", f.Name+":", f.Value)
	}
	for _, f := range panelFacts() {
		fmt.Printf("  %-12s%s\n", f.Name+":", f.Value)
	}
	return nil
}

func boolStatus(ok bool) string {
	if ok {
		return "supported"
	}
	return "NOT supported"
}
