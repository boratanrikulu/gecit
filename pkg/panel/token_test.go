package panel

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func tokenPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "panel.token")
}

func TestLoadOrCreateTokenIsStableAndPrivate(t *testing.T) {
	path := tokenPath(t)

	first, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(first) < 40 {
		t.Errorf("token is only %d characters, want 32 random bytes worth", len(first))
	}

	// A restart has to accept the tokens already handed out.
	second, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if second != first {
		t.Errorf("reload returned a different token: %q then %q", first, second)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("token file mode is %04o, want 0600", mode)
		}
	}
}

func TestLoadOrCreateTokenIsRandom(t *testing.T) {
	a, err := LoadOrCreateToken(tokenPath(t))
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateToken(tokenPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("two fresh tokens are identical: %q", a)
	}
}

// Whoever holds the token can rewrite the config of a root process and restart
// the engine, so a file other users can read is refused rather than reused.
func TestLoadOrCreateTokenRejectsLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("access is carried by the directory DACL, not the mode bits")
	}
	path := tokenPath(t)
	if _, err := LoadOrCreateToken(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadOrCreateToken(path)
	if err == nil {
		t.Fatal("a world-readable token file should be refused")
	}
	if !strings.Contains(err.Error(), "readable by other users") {
		t.Errorf("error should say why, got %v", err)
	}
}

func TestLoadOrCreateTokenRejectsEmptyFile(t *testing.T) {
	path := tokenPath(t)
	if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateToken(path); err == nil {
		t.Fatal("an empty token file should be refused, not treated as a valid token")
	}
}

func TestTokenMatches(t *testing.T) {
	if !tokenMatches("abc", "abc") {
		t.Error("identical tokens should match")
	}
	for _, got := range []string{"", "ab", "abcd", "abd"} {
		if tokenMatches("abc", got) {
			t.Errorf("%q should not match %q", got, "abc")
		}
	}
}

func TestURL(t *testing.T) {
	for addr, want := range map[string]string{
		"127.0.0.1:8088": "http://gecit.localhost:8088/?t=secret",
		":8088":          "http://gecit.localhost:8088/?t=secret",
		"nonsense":       "http://gecit.localhost:8088/?t=secret",
		// A loopback address the operator picked is left alone: the name only
		// ever points at 127.0.0.1 and would miss it.
		"[::1]:8088":     "http://[::1]:8088/?t=secret",
		"127.0.0.2:8088": "http://127.0.0.2:8088/?t=secret",
	} {
		if got := URL(addr, "secret"); got != want {
			t.Errorf("URL(%q) = %q, want %q", addr, got, want)
		}
	}

	if got := URL("127.0.0.1:8088", ""); got != "http://gecit.localhost:8088/" {
		t.Errorf("URL with no token = %q", got)
	}
}
