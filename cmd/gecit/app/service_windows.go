package app

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// The MSI registers the service from its own copy of these strings in
// packaging/windows/parameters.wxi. They have to stay identical, or the
// service these commands look for is not the one the installer created.
const (
	serviceName        = "gecit"
	serviceDisplayName = "gecit DPI bypass"
	serviceDescription = "Injects fake TLS ClientHello packets to desynchronize DPI middleboxes, and resolves DNS over HTTPS."
)

const serviceStateTimeout = 30 * time.Second

// underServiceManager reports whether the SCM started this process rather than
// an operator at a console. It decides where logs go and who drives shutdown.
func underServiceManager() bool {
	is, err := svc.IsWindowsService()
	return err == nil && is
}

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage the gecit Windows service",
}

var serviceInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Register the service with Windows",
	RunE:  runServiceInstall,
}

var serviceUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove the service from Windows",
	RunE:  runServiceUninstall,
}

var serviceStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the service",
	RunE:  runServiceStart,
}

var serviceStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the service",
	RunE:  runServiceStop,
}

var serviceRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the service",
	RunE:  runServiceRestart,
}

var serviceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the service state",
	RunE:  runServiceStatus,
}

var serviceSetStartCmd = &cobra.Command{
	Use:   "set-start",
	Short: "Change whether the service starts at boot",
	RunE:  runServiceSetStart,
}

func init() {
	serviceSetStartCmd.Flags().Bool("manual", false, "start only when asked, instead of at boot")

	serviceCmd.AddCommand(
		serviceInstallCmd,
		serviceUninstallCmd,
		serviceStartCmd,
		serviceStopCmd,
		serviceRestartCmd,
		serviceStatusCmd,
		serviceSetStartCmd,
	)
	rootCmd.AddCommand(serviceCmd)
}

func runServiceInstall(cmd *cobra.Command, args []string) error {
	if err := checkPrivileges(); err != nil {
		return err
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate gecit.exe: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service %s is already installed", serviceName)
	}

	// Delayed start because the engine needs a usable NIC, and an auto-start
	// service can otherwise race the network stack at boot.
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName:      serviceDisplayName,
		Description:      serviceDescription,
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
		ErrorControl:     mgr.ErrorNormal,
	}, "run")
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	if err := setRecoveryActions(s); err != nil {
		s.Delete()
		return err
	}

	// Ignored when the source is already registered, which is the common case
	// on a reinstall.
	_ = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)

	fmt.Printf("installed %s\n", serviceName)
	return nil
}

// A machine missing Npcap fails every start, so the actions stop after two
// retries instead of restarting forever.
func setRecoveryActions(s *mgr.Service) error {
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 120 * time.Second},
		{Type: mgr.NoAction},
	}
	if err := s.SetRecoveryActions(actions, uint32((24 * time.Hour).Seconds())); err != nil {
		return fmt.Errorf("set recovery actions: %w", err)
	}
	return nil
}

func runServiceUninstall(cmd *cobra.Command, args []string) error {
	if err := checkPrivileges(); err != nil {
		return err
	}

	m, s, err := openServiceForManage()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()

	// Leaving the process running would keep system DNS pointed at a resolver
	// that is about to disappear.
	if err := stopAndWait(s); err != nil {
		return err
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	_ = eventlog.Remove(serviceName)

	fmt.Printf("uninstalled %s\n", serviceName)
	return nil
}

func runServiceStart(cmd *cobra.Command, args []string) error {
	if err := checkPrivileges(); err != nil {
		return err
	}

	m, s, err := openServiceForManage()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()

	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	if err := waitForState(s, svc.Running); err != nil {
		return err
	}

	fmt.Printf("started %s\n", serviceName)
	return nil
}

func runServiceStop(cmd *cobra.Command, args []string) error {
	if err := checkPrivileges(); err != nil {
		return err
	}

	m, s, err := openServiceForManage()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()

	if err := stopAndWait(s); err != nil {
		return err
	}

	fmt.Printf("stopped %s\n", serviceName)
	return nil
}

func runServiceRestart(cmd *cobra.Command, args []string) error {
	if err := runServiceStop(cmd, args); err != nil {
		return err
	}
	return runServiceStart(cmd, args)
}

func runServiceStatus(cmd *cobra.Command, args []string) error {
	m, s, err := openServiceForQuery()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("query service: %w", err)
	}
	cfg, err := s.Config()
	if err != nil {
		return fmt.Errorf("read service config: %w", err)
	}

	fmt.Printf("%s: %s\n", serviceName, serviceStateName(status.State))
	fmt.Printf("  start:  %s\n", startTypeName(cfg.StartType, cfg.DelayedAutoStart))
	fmt.Printf("  binary: %s\n", cfg.BinaryPathName)
	return nil
}

func runServiceSetStart(cmd *cobra.Command, args []string) error {
	if err := checkPrivileges(); err != nil {
		return err
	}

	manual, _ := cmd.Flags().GetBool("manual")

	m, s, err := openServiceForManage()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()

	cfg, err := s.Config()
	if err != nil {
		return fmt.Errorf("read service config: %w", err)
	}
	if manual {
		cfg.StartType = mgr.StartManual
		cfg.DelayedAutoStart = false
	} else {
		cfg.StartType = mgr.StartAutomatic
		cfg.DelayedAutoStart = true
	}
	if err := s.UpdateConfig(cfg); err != nil {
		return fmt.Errorf("update service config: %w", err)
	}

	// Switching to manual means the operator does not want it running now
	// either, and the installer relies on that.
	if manual {
		if err := stopAndWait(s); err != nil {
			return err
		}
	}

	fmt.Printf("%s start set to %s\n", serviceName, startTypeName(cfg.StartType, cfg.DelayedAutoStart))
	return nil
}

// openServiceForManage takes the full access the SCM demands for install,
// start, stop and config changes. It needs elevation.
func openServiceForManage() (*mgr.Mgr, *mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil, fmt.Errorf("connect to service manager: %w", err)
	}
	s, err := m.OpenService(serviceName)
	if err != nil {
		m.Disconnect()
		return nil, nil, openError(err)
	}
	return m, s, nil
}

// openServiceForQuery asks for only what reading state needs. mgr.Connect and
// mgr.OpenService both demand full access, so reading state through them would
// need elevation for no reason.
func openServiceForQuery() (*mgr.Mgr, *mgr.Service, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to service manager: %w", err)
	}
	m := &mgr.Mgr{Handle: scm}

	namePointer, err := windows.UTF16PtrFromString(serviceName)
	if err != nil {
		m.Disconnect()
		return nil, nil, err
	}
	h, err := windows.OpenService(scm, namePointer, windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		m.Disconnect()
		return nil, nil, openError(err)
	}
	return m, &mgr.Service{Name: serviceName, Handle: h}, nil
}

func openError(err error) error {
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	return fmt.Errorf("open service %s: %w", serviceName, err)
}

func stopAndWait(s *mgr.Service) error {
	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("query service: %w", err)
	}
	if status.State == svc.Stopped {
		return nil
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
	return waitForState(s, svc.Stopped)
}

func waitForState(s *mgr.Service, want svc.State) error {
	deadline := time.Now().Add(serviceStateTimeout)
	for time.Now().Before(deadline) {
		status, err := s.Query()
		if err != nil {
			return fmt.Errorf("query service: %w", err)
		}
		if status.State == want {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("service %s did not reach %s within %s", serviceName, serviceStateName(want), serviceStateTimeout)
}

func serviceStateName(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "starting"
	case svc.StopPending:
		return "stopping"
	case svc.Running:
		return "running"
	case svc.Paused:
		return "paused"
	default:
		return fmt.Sprintf("state %d", s)
	}
}

func startTypeName(startType uint32, delayed bool) string {
	switch startType {
	case mgr.StartAutomatic:
		if delayed {
			return "automatic (delayed)"
		}
		return "automatic"
	case mgr.StartManual:
		return "manual"
	case mgr.StartDisabled:
		return "disabled"
	default:
		return fmt.Sprintf("type %d", startType)
	}
}
