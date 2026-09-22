//go:build !windows

package panel

import (
	"fmt"
	"os"
)

// createTokenFile makes the file nobody else can read. The mode is applied by
// the kernel at creation, so there is no window where it is more open.
func createTokenFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

// secureToken refuses a token any local user can read. Whoever holds it can
// rewrite the config of a process running as root and restart the engine, so a
// loosened file is a privilege escalation, not an inconvenience.
func secureToken(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat panel token %s: %w", path, err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("panel token %s is readable by other users (mode %04o), delete it to generate a new one", path, mode)
	}
	return nil
}
