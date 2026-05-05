//go:build linux

package dns

import (
	"os"
	"path/filepath"
	"testing"
)

func withTestResolvConf(t *testing.T, contents string) string {
	t.Helper()

	origPath := resolvConfPath
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatalf("write test resolv.conf: %v", err)
	}

	resolvConfPath = path
	t.Cleanup(func() {
		resolvConfPath = origPath
	})

	return path
}

func TestRestoreSystemDNSRestoresGecitManagedState(t *testing.T) {
	path := withTestResolvConf(t, "nameserver 1.1.1.1\nsearch lan\n")

	if err := SetSystemDNS(); err != nil {
		t.Fatalf("SetSystemDNS: %v", err)
	}
	if !SystemDNSNeedsRestore() {
		t.Fatal("SystemDNSNeedsRestore() = false, want true")
	}

	if err := RestoreSystemDNS(); err != nil {
		t.Fatalf("RestoreSystemDNS: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read restored resolv.conf: %v", err)
	}
	want := "nameserver 1.1.1.1\nsearch lan\n"
	if string(got) != want {
		t.Fatalf("restored resolv.conf:\n got %q\nwant %q", string(got), want)
	}
	if SystemDNSNeedsRestore() {
		t.Fatal("SystemDNSNeedsRestore() = true after restore, want false")
	}
}

func TestRestoreSystemDNSNoopsWithoutGecitMarker(t *testing.T) {
	const original = "nameserver 127.0.0.1\nsearch local\n"
	path := withTestResolvConf(t, original)

	if err := RestoreSystemDNS(); err != nil {
		t.Fatalf("RestoreSystemDNS: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read resolv.conf: %v", err)
	}
	if string(got) != original {
		t.Fatalf("RestoreSystemDNS changed unmanaged file:\n got %q\nwant %q", string(got), original)
	}
}
