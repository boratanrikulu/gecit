package dns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withResolvConfPath(t *testing.T, path string, allowed []string) {
	t.Helper()

	oldResolvConf := resolvConf
	oldAllowed := allowedResolvDirs
	resolvConf = path
	allowedResolvDirs = allowed
	t.Cleanup(func() {
		resolvConf = oldResolvConf
		allowedResolvDirs = oldAllowed
	})
}

func TestSetSystemDNSUsesTrustedSymlinkTarget(t *testing.T) {
	tmp := t.TempDir()
	etcDir := filepath.Join(tmp, "etc")
	runDir := filepath.Join(tmp, "run", "systemd", "resolve")
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(runDir, 0755); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(runDir, "stub-resolv.conf")
	if err := os.WriteFile(target, []byte("nameserver 9.9.9.9\nsearch example.test\n"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(etcDir, "resolv.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	withResolvConfPath(t, link, []string{etcDir, filepath.Join(tmp, "run")})
	if err := SetSystemDNS(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !strings.Contains(got, "nameserver 127.0.0.1") || !strings.Contains(got, "# gecit-saved: nameserver 9.9.9.9") {
		t.Fatalf("unexpected rewritten resolv.conf:\n%s", got)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("resolv.conf symlink was not preserved: info=%v err=%v", info, err)
	}
}

func TestReadResolvConfRejectsUntrustedSymlinkTarget(t *testing.T) {
	tmp := t.TempDir()
	etcDir := filepath.Join(tmp, "etc")
	otherDir := filepath.Join(tmp, "other")
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(otherDir, 0755); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(otherDir, "resolv.conf")
	if err := os.WriteFile(target, []byte("nameserver 1.1.1.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(etcDir, "resolv.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	withResolvConfPath(t, link, []string{etcDir})
	if _, _, err := readResolvConf(); err == nil {
		t.Fatal("expected untrusted symlink target to be rejected")
	}
}

func TestReadResolvConfRejectsOversizedFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "resolv.conf")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxResolvConfBytes+1)), 0644); err != nil {
		t.Fatal(err)
	}

	withResolvConfPath(t, path, []string{tmp})
	if _, _, err := readResolvConf(); err == nil {
		t.Fatal("expected oversized resolv.conf to be rejected")
	}
}
