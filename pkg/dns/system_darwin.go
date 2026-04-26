package dns

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"
)

const (
	breadcrumbDir  = "/var/db/gecit"
	breadcrumbFile = "/var/db/gecit/dns-backup"
)

type dnsBackup struct {
	Service string   `json:"service"`
	Servers []string `json:"servers,omitempty"`
	DHCP    bool     `json:"dhcp"`
}

var savedDNS string
var savedService string

func runNetworksetup(args ...string) ([]byte, error) {
	return exec.Command("/usr/sbin/networksetup", args...).CombinedOutput() // #nosec G204 -- absolute system binary; args are fixed internally or validated service/DNS values.
}

func runKillall(args ...string) ([]byte, error) {
	return exec.Command("/usr/bin/killall", args...).CombinedOutput() // #nosec G204 -- absolute system binary; args are fixed mDNSResponder controls.
}

// StopMDNSResponder unloads mDNSResponder from launchd so it releases port 53
// and doesn't respawn. ResumeMDNSResponder loads it back.
func StopMDNSResponder() {
	// Kill mDNSResponder repeatedly until port 53 is free.
	// launchd respawns it, so we keep killing until we can bind.
	for i := 0; i < 10; i++ {
		_, _ = runKillall("mDNSResponder")
		time.Sleep(200 * time.Millisecond)

		// Check if port 53 is free.
		conn, err := net.ListenPacket("udp", "127.0.0.1:53")
		if err == nil {
			_ = conn.Close()
			return // port is free
		}
	}
}

// ResumeMDNSResponder sends a HUP to restart mDNSResponder cleanly.
// If it was killed, launchd will have already respawned it.
func ResumeMDNSResponder() {
	_, _ = runKillall("-HUP", "mDNSResponder")
}

// SetSystemDNS sets macOS system DNS to 127.0.0.1 via networksetup.
// Saves the current DNS servers so they can be restored on stop.
func SetSystemDNS(networkService ...string) error {
	svc := "Wi-Fi"
	if len(networkService) > 0 && networkService[0] != "" {
		svc = networkService[0]
	}
	if err := validateService(svc); err != nil {
		return err
	}
	savedService = svc

	// If breadcrumb exists from a previous crash, restore it before writing
	// current state. The file is opened with O_NOFOLLOW under a root-owned dir.
	if prev, err := readBackup(); err == nil {
		if err := restoreBackup(prev); err != nil {
			return fmt.Errorf("restore previous DNS backup: %w", err)
		}
		if err := removeBackup(); err != nil {
			return fmt.Errorf("remove previous DNS backup: %w", err)
		}
	}

	out, err := runNetworksetup("-getdnsservers", svc)
	if err == nil {
		savedDNS = strings.TrimSpace(string(out))
		backup, err := parseDNSBackup(svc, savedDNS)
		if err != nil {
			return err
		}
		if err := writeBackup(backup); err != nil {
			return err
		}
	}

	out, err = runNetworksetup("-setdnsservers", svc, "127.0.0.1")
	if err != nil {
		return fmt.Errorf("set DNS: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// RestoreSystemDNS restores macOS DNS to the original servers (or DHCP if none).
func RestoreSystemDNS(networkService ...string) error {
	if backup, err := readBackup(); err == nil {
		if len(networkService) > 0 && networkService[0] != "" {
			if err := validateService(networkService[0]); err != nil {
				return err
			}
			backup.Service = networkService[0]
		}
		if err := restoreBackup(backup); err != nil {
			return err
		}
		if err := removeBackup(); err != nil {
			return err
		}
		ResumeMDNSResponder()
		return nil
	}

	svc := savedService
	if svc == "" {
		svc = "Wi-Fi"
	}
	if len(networkService) > 0 && networkService[0] != "" {
		svc = networkService[0]
	}
	backup, err := parseDNSBackup(svc, savedDNS)
	if err != nil {
		return err
	}
	if err := restoreBackup(backup); err != nil {
		return err
	}
	if err := removeBackup(); err != nil {
		return err
	}
	ResumeMDNSResponder()
	return nil
}

func HasSystemDNSBackup() bool {
	_, err := readBackup()
	return err == nil
}

func parseDNSBackup(svc, raw string) (dnsBackup, error) {
	if err := validateService(svc); err != nil {
		return dnsBackup{}, err
	}
	if raw == "" || strings.Contains(raw, "aren't any") {
		return dnsBackup{Service: svc, DHCP: true}, nil
	}
	servers := strings.Fields(raw)
	for _, server := range servers {
		if net.ParseIP(server) == nil {
			return dnsBackup{}, fmt.Errorf("invalid DNS server %q", server)
		}
	}
	return dnsBackup{Service: svc, Servers: servers}, nil
}

func restoreBackup(backup dnsBackup) error {
	if err := validateService(backup.Service); err != nil {
		return err
	}
	args := []string{"-setdnsservers", backup.Service}
	if backup.DHCP || len(backup.Servers) == 0 {
		args = append(args, "empty")
	} else {
		for _, server := range backup.Servers {
			if net.ParseIP(server) == nil {
				return fmt.Errorf("invalid DNS server %q", server)
			}
			args = append(args, server)
		}
	}
	out, err := runNetworksetup(args...)
	if err != nil {
		return fmt.Errorf("restore DNS: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func validateService(svc string) error {
	if strings.TrimSpace(svc) == "" || len(svc) > 128 || strings.ContainsAny(svc, "\x00\r\n") {
		return fmt.Errorf("invalid network service %q", svc)
	}
	if strings.HasPrefix(svc, "-") || strings.HasPrefix(svc, "/") {
		return fmt.Errorf("invalid network service %q", svc)
	}
	for _, r := range svc {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		switch r {
		case ' ', '.', '_', '-', '(', ')', '/':
			continue
		default:
			return fmt.Errorf("invalid network service %q", svc)
		}
	}
	return nil
}

func ensureBackupDir() error {
	if err := os.MkdirAll(breadcrumbDir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(breadcrumbDir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&022 != 0 {
		return fmt.Errorf("%s must be a private directory", breadcrumbDir)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 && stat.Uid != 0 {
		return fmt.Errorf("%s must be owned by root", breadcrumbDir)
	}
	return nil
}

func writeBackup(backup dnsBackup) error {
	if err := ensureBackupDir(); err != nil {
		return fmt.Errorf("prepare DNS backup dir: %w", err)
	}
	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp := filepath.Join(breadcrumbDir, "dns-backup.tmp")
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600) // #nosec G304 -- fixed root-owned directory, O_NOFOLLOW and O_EXCL.
	if err != nil {
		return fmt.Errorf("open DNS backup: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, breadcrumbFile); err != nil {
		return err
	}
	return nil
}

func readBackup() (dnsBackup, error) {
	f, err := os.OpenFile(breadcrumbFile, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return dnsBackup{}, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return dnsBackup{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&077 != 0 {
		return dnsBackup{}, fmt.Errorf("unsafe DNS backup permissions")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 && stat.Uid != 0 {
		return dnsBackup{}, fmt.Errorf("unsafe DNS backup owner")
	}

	var backup dnsBackup
	if err := json.NewDecoder(f).Decode(&backup); err != nil {
		return dnsBackup{}, err
	}
	if err := validateService(backup.Service); err != nil {
		return dnsBackup{}, err
	}
	for _, server := range backup.Servers {
		if net.ParseIP(server) == nil {
			return dnsBackup{}, fmt.Errorf("invalid DNS server %q", server)
		}
	}
	return backup, nil
}

func removeBackup() error {
	if err := os.Remove(breadcrumbFile); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
