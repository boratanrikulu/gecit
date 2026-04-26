package app

import (
	"fmt"

	"github.com/spf13/cobra"
)

var cleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Restore system settings after a crash",
	Long:  `Removes stale routes and restores DNS settings left behind by a gecit crash or SIGKILL.`,
	RunE:  runCleanup,
}

func init() {
	rootCmd.AddCommand(cleanupCmd)
}

func runCleanup(cmd *cobra.Command, args []string) error {
	if err := checkPrivileges(); err != nil {
		return err
	}
	cleaned := platformCleanup()
	if cleaned {
		fmt.Println("cleanup complete — system settings restored")
	} else {
		fmt.Println("nothing to clean up")
	}
	return nil
}
