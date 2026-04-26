package dns

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"
	"unsafe"

	"golang.org/x/sys/windows"
)

var breadcrumbFileWin = filepath.Join(`C:\ProgramData`, "gecit", "dns-backup.json")

var savedInterface string

const (
	windowsBackupDirSDDL  = "O:BAG:BAD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)"
	windowsBackupFileSDDL = "O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)"
)

type windowsDNSBackup struct {
	Interface string `json:"interface"`
	DNS       string `json:"dns"`
	DHCP      bool   `json:"dhcp"`
}

func system32Exe(name string) string {
	if dir, err := windows.GetSystemDirectory(); err == nil && dir != "" {
		return filepath.Join(dir, name)
	}
	return filepath.Join(`C:\Windows`, "System32", name)
}

func runNetsh(args ...string) ([]byte, error) {
	return exec.Command(system32Exe("netsh.exe"), args...).CombinedOutput() // #nosec G204 -- fixed System32 binary; arguments are fixed or validated interface/DNS values.
}

func runIPConfig(args ...string) ([]byte, error) {
	return exec.Command(system32Exe("ipconfig.exe"), args...).CombinedOutput() // #nosec G204 -- fixed System32 binary; arguments are fixed.
}

func SetSystemDNS(_ ...string) error {
	iface, err := detectWindowsInterface()
	if err != nil {
		return fmt.Errorf("detect interface: %w", err)
	}
	savedInterface = iface

	if backup, err := readWindowsBackup(); err == nil {
		if err := restoreWindowsBackup(backup); err != nil {
			return fmt.Errorf("restore previous DNS backup: %w", err)
		}
		if err := removeWindowsBackup(); err != nil {
			return fmt.Errorf("remove previous DNS backup: %w", err)
		}
	}

	currentDNS := getCurrentDNS(iface)
	if err := writeWindowsBackup(windowsDNSBackup{
		Interface: iface,
		DNS:       currentDNS,
		DHCP:      currentDNS == "" || currentDNS == "dhcp",
	}); err != nil {
		return err
	}

	out, err := runNetsh("interface", "ip", "set", "dns", iface, "static", "127.0.0.1")
	if err != nil {
		return fmt.Errorf("set DNS: %s: %w", strings.TrimSpace(string(out)), err)
	}

	_, _ = runIPConfig("/flushdns")
	return nil
}

func RestoreSystemDNS(_ ...string) error {
	backup, err := readWindowsBackup()
	if err != nil {
		iface := savedInterface
		if iface == "" {
			iface, _ = detectWindowsInterface()
		}
		if iface != "" {
			if out, err := runNetsh("interface", "ip", "set", "dns", iface, "dhcp"); err != nil {
				return fmt.Errorf("restore DNS: %s: %w", strings.TrimSpace(string(out)), err)
			}
		}
		return nil
	}

	if err := restoreWindowsBackup(backup); err != nil {
		return err
	}
	_, _ = runIPConfig("/flushdns")
	if err := removeWindowsBackup(); err != nil {
		return err
	}
	return nil
}

func HasSystemDNSBackup() bool {
	_, err := readWindowsBackup()
	return err == nil
}

func getCurrentDNS(iface string) string {
	out, err := runNetsh("interface", "ip", "show", "dns", iface)
	if err != nil {
		return "dhcp"
	}
	for _, line := range strings.Split(string(out), "\n") {
		for _, p := range strings.Fields(strings.TrimSpace(line)) {
			if ip := net.ParseIP(p); ip != nil && !ip.IsLoopback() {
				return p
			}
		}
	}
	return "dhcp"
}

func detectWindowsInterface() (string, error) {
	out, err := runNetsh("interface", "show", "interface")
	if err != nil {
		return "", fmt.Errorf("netsh: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Connected") && !strings.Contains(line, "Loopback") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				iface := strings.Join(fields[3:], " ")
				if err := validateWindowsInterfaceName(iface); err != nil {
					continue
				}
				return iface, nil
			}
		}
	}
	return "", fmt.Errorf("no connected network interface found")
}

func writeWindowsBackup(backup windowsDNSBackup) error {
	if err := validateWindowsBackup(backup, false); err != nil {
		return err
	}
	if err := ensureWindowsBackupDir(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_ = os.Remove(breadcrumbFileWin)
	if err := os.WriteFile(breadcrumbFileWin, data, 0600); err != nil {
		return err
	}
	return applyWindowsBackupSecurity(breadcrumbFileWin, windowsBackupFileSDDL)
}

func readWindowsBackup() (windowsDNSBackup, error) {
	if err := clampExistingWindowsBackupDir(); err != nil {
		return windowsDNSBackup{}, err
	}
	if err := verifyWindowsBackupSecurity(breadcrumbFileWin); err != nil {
		return windowsDNSBackup{}, err
	}
	data, err := os.ReadFile(breadcrumbFileWin) // #nosec G304 -- fixed ProgramData backup path.
	if err != nil {
		return windowsDNSBackup{}, err
	}
	var backup windowsDNSBackup
	if err := json.Unmarshal(data, &backup); err != nil {
		return windowsDNSBackup{}, err
	}
	if err := validateWindowsBackup(backup, true); err != nil {
		return windowsDNSBackup{}, err
	}
	return backup, nil
}

func restoreWindowsBackup(backup windowsDNSBackup) error {
	if backup.DHCP || backup.DNS == "" {
		out, err := runNetsh("interface", "ip", "set", "dns", backup.Interface, "dhcp")
		if err != nil {
			return fmt.Errorf("restore DNS: %s: %w", strings.TrimSpace(string(out)), err)
		}
		return nil
	}
	out, err := runNetsh("interface", "ip", "set", "dns", backup.Interface, "static", backup.DNS)
	if err != nil {
		return fmt.Errorf("restore DNS: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func removeWindowsBackup() error {
	if err := os.Remove(breadcrumbFileWin); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func validateWindowsBackup(backup windowsDNSBackup, requireExistingInterface bool) error {
	if err := validateWindowsInterfaceName(backup.Interface); err != nil {
		return err
	}
	if requireExistingInterface {
		ok, err := windowsInterfaceExists(backup.Interface)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("unknown interface %q", backup.Interface)
		}
	}
	if backup.DHCP || backup.DNS == "" {
		return nil
	}
	ip := net.ParseIP(backup.DNS)
	if ip == nil {
		return fmt.Errorf("invalid DNS server %q", backup.DNS)
	}
	if !isRestorableDNSServer(ip) {
		return fmt.Errorf("unsafe DNS server %q", backup.DNS)
	}
	return nil
}

func validateWindowsInterfaceName(iface string) error {
	if strings.TrimSpace(iface) == "" || len(iface) > 128 || strings.ContainsAny(iface, "\x00\r\n") {
		return fmt.Errorf("invalid interface %q", iface)
	}
	if strings.HasPrefix(iface, "-") || strings.HasPrefix(iface, "/") || strings.HasPrefix(iface, "=") {
		return fmt.Errorf("invalid interface %q", iface)
	}
	for _, r := range iface {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		switch r {
		case ' ', '.', '_', '-', '(', ')', '/':
			continue
		default:
			return fmt.Errorf("invalid interface %q", iface)
		}
	}
	return nil
}

func windowsInterfaceExists(iface string) (bool, error) {
	out, err := runNetsh("interface", "show", "interface")
	if err != nil {
		return false, fmt.Errorf("netsh: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 4 && strings.Join(fields[3:], " ") == iface {
			return true, nil
		}
	}
	return false, nil
}

func isRestorableDNSServer(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil && ip4.Equal(net.IPv4bcast) {
		return false
	}
	return !(ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast())
}

func ensureWindowsBackupDir() error {
	dir := filepath.Dir(breadcrumbFileWin)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return applyWindowsBackupSecurity(dir, windowsBackupDirSDDL)
}

func clampExistingWindowsBackupDir() error {
	dir := filepath.Dir(breadcrumbFileWin)
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return applyWindowsBackupSecurity(dir, windowsBackupDirSDDL)
}

func applyWindowsBackupSecurity(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	admins, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		admins,
		admins,
		dacl,
		nil,
	)
}

func verifyWindowsBackupSecurity(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	switch owner.String() {
	case "S-1-5-32-544", "S-1-5-18":
	default:
		return fmt.Errorf("unsafe DNS backup owner: %s", owner.String())
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("unsafe DNS backup ACL: inherited permissions are enabled")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return verifyWindowsBackupDACL(dacl)
}

func verifyWindowsBackupDACL(dacl *windows.ACL) error {
	if dacl == nil || dacl.AceCount != 2 {
		return fmt.Errorf("unsafe DNS backup ACL")
	}
	allowed := map[string]bool{
		"S-1-5-32-544": false, // BUILTIN\Administrators
		"S-1-5-18":     false, // NT AUTHORITY\SYSTEM
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask == 0 {
			return fmt.Errorf("unsafe DNS backup ACL")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String() // #nosec G103 -- Win32 ACE stores the SID inline after SidStart; read-only ACL validation.
		if _, ok := allowed[sid]; !ok {
			return fmt.Errorf("unsafe DNS backup ACL grants access to %s", sid)
		}
		allowed[sid] = true
	}
	for sid, seen := range allowed {
		if !seen {
			return fmt.Errorf("unsafe DNS backup ACL missing %s", sid)
		}
	}
	return nil
}
