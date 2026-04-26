package dns

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestValidateUpstreamsRejectsPlainHTTPByDefault(t *testing.T) {
	if err := ValidateUpstreams("http://127.0.0.1:8053/dns-query", false); err == nil {
		t.Fatal("plain HTTP upstream succeeded, want error")
	}
}

func TestValidateUpstreamsAllowsPlainHTTPWithOptIn(t *testing.T) {
	if err := ValidateUpstreams("http://127.0.0.1:8053/dns-query", true); err != nil {
		t.Fatalf("plain HTTP opt-in returned error: %v", err)
	}
}

func TestValidateUpstreamsAllowsPresetsAndHTTPS(t *testing.T) {
	if err := ValidateUpstreams("cloudflare,https://8.8.8.8/dns-query", false); err != nil {
		t.Fatalf("valid upstreams returned error: %v", err)
	}
}

func TestNewResolverRejectsPlainHTTPByDefault(t *testing.T) {
	resolver := NewResolver("http://127.0.0.1:8053/dns-query", nil)
	if _, err := resolver.Resolve([]byte("query")); err == nil {
		t.Fatal("plain HTTP resolver succeeded, want error")
	}
}

func TestNewResolverAllowsPlainHTTPWithOptIn(t *testing.T) {
	resolver := NewResolverWithOptions("http://127.0.0.1:8053/dns-query", nil, true)
	if resolver.Name() != "http://127.0.0.1:8053/dns-query" {
		t.Fatalf("resolver name = %q", resolver.Name())
	}
}

func TestDoHClientRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, maxDoHResponseBytes+1))
	}))
	defer server.Close()

	client := NewDoHClient(server.URL, "test", nil)
	if _, err := client.Resolve([]byte("query")); err == nil {
		t.Fatal("oversized DoH response succeeded, want error")
	}
}

func TestDoHClientDoesNotFollowRedirects(t *testing.T) {
	var finalHit atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			finalHit.Store(true)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		http.Redirect(w, r, "/final", http.StatusFound)
	}))
	defer server.Close()

	client := NewDoHClient(server.URL, "test", nil)
	if _, err := client.Resolve([]byte("query")); err == nil {
		t.Fatal("redirecting DoH response succeeded, want error")
	}
	if finalHit.Load() {
		t.Fatal("DoH client followed redirect")
	}
}
