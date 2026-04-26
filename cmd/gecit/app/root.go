package app

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "gecit",
	Short: "gecit — DPI bypass via fake TLS ClientHello injection + DoH DNS",
	Long: `gecit injects fake TLS ClientHello packets to desynchronize DPI middleboxes.
Built-in DoH (DNS-over-HTTPS) resolver bypasses DNS poisoning.

Linux:         eBPF sock_ops (kernel-level, zero overhead)
macOS/Windows: TUN transparent proxy (all apps intercepted)`,
}

func init() {
	rootCmd.PersistentFlags().IntSlice("ports", []int{443}, "target destination ports")
	rootCmd.PersistentFlags().String("interface", "", "network interface, macOS/Windows only (auto-detect if empty)")

	mustBindPFlag("ports", rootCmd.PersistentFlags().Lookup("ports"))
	mustBindPFlag("interface", rootCmd.PersistentFlags().Lookup("interface"))
}

func Execute() error {
	return rootCmd.Execute()
}

func mustBindPFlag(key string, flag *pflag.Flag) {
	if err := viper.BindPFlag(key, flag); err != nil {
		panic(err)
	}
}
