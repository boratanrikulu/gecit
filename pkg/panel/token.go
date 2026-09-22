package panel

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"strings"
)

const tokenBytes = 32

// LoadOrCreateToken returns the panel's shared secret, generating it on first
// use. It is persisted rather than regenerated per run because a Windows
// service has no console to print a fresh one to, and an operator would have to
// dig it out of the log file after every restart.
func LoadOrCreateToken(path string) (string, error) {
	token, err := ReadToken(path)
	if err == nil {
		return token, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}

	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate panel token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)

	// Created exclusively so a token that appeared between the read and here is
	// never overwritten, which would lock out a panel already serving with it.
	f, err := createTokenFile(path)
	if err != nil {
		return "", fmt.Errorf("create panel token %s: %w", path, err)
	}
	if _, err := f.WriteString(token + "\n"); err != nil {
		f.Close()
		return "", fmt.Errorf("write panel token %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close panel token %s: %w", path, err)
	}
	return token, nil
}

// ReadToken returns the existing token without creating one, which is what
// `gecit status` needs: it reports the panel URL and must not write to a
// directory it may not own.
func ReadToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		return "", fmt.Errorf("read panel token %s: %w", path, err)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("panel token file %s is empty, delete it to generate a new one", path)
	}
	if err := secureToken(path); err != nil {
		return "", err
	}
	return token, nil
}

func tokenMatches(want, got string) bool {
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

// URL is the address an operator pastes into a browser. The default bind gets
// the name; a loopback address the operator chose keeps it, since the name only
// ever points at 127.0.0.1. The token rides in the query once and the page
// strips it from the address bar. An empty token yields the plain URL, which is
// what `gecit status` prints when it cannot read the token file.
func URL(addr, token string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = "127.0.0.1", "8088"
	}
	if host == "" || host == "::" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if host == "127.0.0.1" {
		host = PanelHost
	}
	base := "http://" + net.JoinHostPort(host, port) + "/"
	if token == "" {
		return base
	}
	return base + "?t=" + url.QueryEscape(token)
}
