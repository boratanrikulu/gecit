package dns

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const maxResolvConfBytes = 1 << 20

var (
	resolvConf        = "/etc/resolv.conf"
	allowedResolvDirs = []string{"/etc", "/run", "/var/run"}
)

// SetSystemDNS comments out existing nameservers and adds 127.0.0.1.
// Original lines are preserved as "# gecit-saved: ..." so they survive
// a crash — RestoreSystemDNS (or manual edit) can recover them.
func SetSystemDNS() error {
	orig, target, err := readResolvConf()
	if err != nil {
		return fmt.Errorf("read %s: %w", resolvConf, err)
	}

	var lines []string
	lines = append(lines, "# gecit: DoH DNS active — original lines commented below")
	lines = append(lines, "nameserver 127.0.0.1")

	for _, line := range strings.Split(string(orig), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "# gecit") {
			continue
		}
		if strings.HasPrefix(trimmed, "nameserver") {
			lines = append(lines, "# gecit-saved: "+trimmed)
		} else {
			lines = append(lines, line)
		}
	}

	return writeResolvConf(target, []byte(strings.Join(lines, "\n")+"\n"))
}

// RestoreSystemDNS uncomments the original nameservers and removes gecit lines.
func RestoreSystemDNS() error {
	data, target, err := readResolvConf()
	if err != nil {
		return err
	}

	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "# gecit-saved: ") {
			// Restore the original line.
			lines = append(lines, strings.TrimPrefix(trimmed, "# gecit-saved: "))
		} else if strings.HasPrefix(trimmed, "# gecit") {
			continue // remove gecit marker
		} else if trimmed == "nameserver 127.0.0.1" {
			continue // remove our nameserver
		} else if trimmed != "" {
			lines = append(lines, line)
		}
	}

	if len(lines) == 0 {
		lines = append(lines, "nameserver 8.8.8.8") // safe fallback
	}

	return writeResolvConf(target, []byte(strings.Join(lines, "\n")+"\n"))
}

func HasSystemDNSBackup() bool {
	data, _, err := readResolvConf()
	return err == nil && strings.Contains(string(data), "# gecit")
}

func readResolvConf() ([]byte, string, error) {
	target, err := resolveResolvConfPath()
	if err != nil {
		return nil, "", err
	}
	f, err := os.OpenFile(target, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- target is resolved to trusted resolv.conf dirs and opened without following symlinks.
	if err != nil {
		return nil, "", err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxResolvConfBytes+1))
	if err != nil {
		return nil, "", err
	}
	if len(data) > maxResolvConfBytes {
		return nil, "", fmt.Errorf("%s is too large", target)
	}
	return data, target, nil
}

func writeResolvConf(target string, data []byte) error {
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, ".gecit-resolv-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(data); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Chmod(0644); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Sync(); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		return err
	}
	if dirFile, err := os.Open(dir); err == nil { // #nosec G304 -- dir is derived from the validated resolv.conf target and only fsynced after atomic rename.
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}
	return nil
}

func resolveResolvConfPath() (string, error) {
	info, err := os.Lstat(resolvConf)
	if err != nil {
		return "", err
	}
	target := resolvConf
	if info.Mode()&os.ModeSymlink != 0 {
		resolved, err := filepath.EvalSymlinks(resolvConf)
		if err != nil {
			return "", err
		}
		if !isAllowedResolvTarget(resolved) {
			return "", fmt.Errorf("refusing resolv.conf symlink target outside trusted dirs: %s", resolved)
		}
		target = resolved
	}
	target, err = filepath.Abs(target)
	if err != nil {
		return "", err
	}
	if !isAllowedResolvTarget(target) {
		return "", fmt.Errorf("refusing resolv.conf target outside trusted dirs: %s", target)
	}
	return target, nil
}

func isAllowedResolvTarget(path string) bool {
	path = filepath.Clean(path)
	for _, dir := range allowedResolvDirs {
		dir = filepath.Clean(dir)
		if path == dir || strings.HasPrefix(path, dir+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}
