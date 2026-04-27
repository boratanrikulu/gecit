package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"

	"github.com/boratanrikulu/gecit/pkg/router"
	"github.com/boratanrikulu/gecit/pkg/router/probe"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	routerCmd = &cobra.Command{
		Use:   "router",
		Short: "Experimental router-mode tooling",
	}
	routerRunCmd = &cobra.Command{
		Use:   "run",
		Short: "Start the router-mode worker",
		RunE:  runRouterEngine,
	}
	routerPlanCmd = &cobra.Command{
		Use:   "plan",
		Short: "Print nftables dry-run commands for router mode",
		RunE:  runRouterPlan,
	}
	routerProbeCmd = &cobra.Command{
		Use:   "probe",
		Short: "Print a blockcheck-style dry-run probe plan",
		RunE:  runRouterProbe,
	}
)

func init() {
	addRouterFlags(routerPlanCmd)
	addRouterFlags(routerProbeCmd)
	addRouterFlags(routerRunCmd)

	routerCmd.AddCommand(routerRunCmd)
	routerCmd.AddCommand(routerPlanCmd)
	routerCmd.AddCommand(routerProbeCmd)
	rootCmd.AddCommand(routerCmd)
}

func addRouterFlags(cmd *cobra.Command) {
	cmd.Flags().String("wan", "", "WAN interface name (required)")
	cmd.Flags().StringSlice("lan", nil, "LAN interface names")
	cmd.Flags().String("table", "", "nftables table name")
	cmd.Flags().String("backend", string(router.QueueBackendNFQueue), "router backend: nfqueue or dryrun")
	cmd.Flags().Uint("queue-num", 0, "NFQUEUE number")
	cmd.Flags().Uint32("mark", 0, "packet mark for generated packets")
	cmd.Flags().IntSlice("tcp-ports", []int{443}, "TCP ports to intercept")
	cmd.Flags().IntSlice("udp-ports", []int{443}, "UDP ports to intercept when QUIC is enabled")
	cmd.Flags().Bool("quic", false, "enable UDP/QUIC planning")
	cmd.Flags().Bool("postnat", true, "render post-NAT queue rules")
	cmd.Flags().Int("fake-ttl", 8, "TTL for generated fake packets")
	cmd.Flags().Int("max-flows", 4096, "maximum number of tracked flows")
	cmd.Flags().StringSlice("targets", nil, "probe target hostnames")
	cmd.Flags().BoolP("verbose", "v", false, "enable debug logging")
}

func runRouterPlan(cmd *cobra.Command, args []string) error {
	cfg, err := routerConfigFromFlags(cmd)
	if err != nil {
		return err
	}

	rules, err := router.BuildRuleSet(cfg)
	if err != nil {
		return err
	}

	_, err = fmt.Fprint(cmd.OutOrStdout(), rules.ShellScript())
	return err
}

func runRouterProbe(cmd *cobra.Command, args []string) error {
	cfg, err := routerConfigFromFlags(cmd)
	if err != nil {
		return err
	}

	dryRun, err := probe.BuildDryRun(cfg, probe.Plan{
		Targets: splitTargets(cmd),
	})
	if err != nil {
		return err
	}

	_, err = fmt.Fprint(cmd.OutOrStdout(), dryRun.Text())
	return err
}

func runRouterEngine(cmd *cobra.Command, args []string) error {
	cfg, err := routerConfigFromFlags(cmd)
	if err != nil {
		return err
	}
	cfg = cfg.Normalized()

	if cfg.Backend == router.QueueBackendNFQueue && runtime.GOOS != "linux" {
		return router.ErrRouterUnsupported
	}
	if cfg.Backend != router.QueueBackendDryRun {
		if err := checkPrivileges(); err != nil {
			return err
		}
	}

	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	if verbose, _ := cmd.Flags().GetBool("verbose"); verbose {
		logger.SetLevel(logrus.DebugLevel)
	}

	eng := router.NewWithLogger(cfg, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := eng.Start(ctx); err != nil {
		return err
	}

	logger.WithField("mode", eng.Mode()).Info("gecit router is running - press Ctrl+C to stop")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	<-sigCh
	cancel()
	return eng.Stop()
}

func routerConfigFromFlags(cmd *cobra.Command) (router.Config, error) {
	backendName, err := cmd.Flags().GetString("backend")
	if err != nil {
		return router.Config{}, err
	}
	queueNum, err := cmd.Flags().GetUint("queue-num")
	if err != nil {
		return router.Config{}, err
	}
	packetMark, err := cmd.Flags().GetUint32("mark")
	if err != nil {
		return router.Config{}, err
	}
	tcpPorts, err := cmd.Flags().GetIntSlice("tcp-ports")
	if err != nil {
		return router.Config{}, err
	}
	udpPorts, err := cmd.Flags().GetIntSlice("udp-ports")
	if err != nil {
		return router.Config{}, err
	}
	lanInterfaces, err := cmd.Flags().GetStringSlice("lan")
	if err != nil {
		return router.Config{}, err
	}
	enableQUIC, err := cmd.Flags().GetBool("quic")
	if err != nil {
		return router.Config{}, err
	}
	enablePostNAT, err := cmd.Flags().GetBool("postnat")
	if err != nil {
		return router.Config{}, err
	}
	fakeTTL, err := cmd.Flags().GetInt("fake-ttl")
	if err != nil {
		return router.Config{}, err
	}
	maxFlows, err := cmd.Flags().GetInt("max-flows")
	if err != nil {
		return router.Config{}, err
	}
	wanInterface, err := cmd.Flags().GetString("wan")
	if err != nil {
		return router.Config{}, err
	}
	tableName, err := cmd.Flags().GetString("table")
	if err != nil {
		return router.Config{}, err
	}

	return router.Config{
		WANInterface:  wanInterface,
		LANInterfaces: lanInterfaces,
		TableName:     tableName,
		Backend:       router.QueueBackend(strings.TrimSpace(strings.ToLower(backendName))),
		QueueNum:      uint16(queueNum),
		PacketMark:    packetMark,
		TCPPorts:      intSliceToPorts(tcpPorts),
		UDPPorts:      intSliceToPorts(udpPorts),
		FakeTTL:       fakeTTL,
		MaxFlows:      maxFlows,
		ProbeTargets:  splitTargets(cmd),
		EnableQUIC:    enableQUIC,
		EnablePostNAT: enablePostNAT,
	}, nil
}

func intSliceToPorts(values []int) []uint16 {
	out := make([]uint16, 0, len(values))
	for _, value := range values {
		if value <= 0 || value > 65535 {
			continue
		}
		out = append(out, uint16(value))
	}
	return out
}

func splitTargets(cmd *cobra.Command) []string {
	targets, err := cmd.Flags().GetStringSlice("targets")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		for _, part := range strings.Split(target, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			out = append(out, part)
		}
	}
	return out
}
