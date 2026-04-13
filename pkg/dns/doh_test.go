package dns

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDoHClientRejectsNonHTTPSUpstream(t *testing.T) {
	c := NewDoHClient("http://1.1.1.1/dns-query", "test", nil)

	_, err := c.Resolve([]byte{0x00})
	if err == nil {
		t.Fatal("expected non-https upstream to be rejected")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Fatalf("expected https validation error, got %v", err)
	}
}

func TestDoHClientRejectsOversizedResponse(t *testing.T) {
	large := make([]byte, maxDoHResponseBytes+1)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(large)
	}))
	defer ts.Close()

	c := NewDoHClient(ts.URL, "test", nil)
	c.client = ts.Client()

	_, err := c.Resolve([]byte{0x00, 0x01})
	if err == nil {
		t.Fatal("expected oversized response to be rejected")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected size limit error, got %v", err)
	}
}

func TestDoHClientAcceptsBoundedResponse(t *testing.T) {
	want := []byte{0xde, 0xad, 0xbe, 0xef}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(want)
	}))
	defer ts.Close()

	c := NewDoHClient(ts.URL, "test", nil)
	c.client = ts.Client()

	got, err := c.Resolve([]byte{0x00, 0x01})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if !bytes.Equal(got.Data, want) {
		t.Fatalf("Resolve() data = %v, want %v", got.Data, want)
	}
	if got.Via != "test" {
		t.Fatalf("Resolve() via = %q, want %q", got.Via, "test")
	}
}

func TestDoHClientRejectsRedirectResponses(t *testing.T) {
	redirected := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/dns-query", http.StatusFound)
	}))
	defer redirected.Close()

	c := NewDoHClient(redirected.URL, "test", nil)
	client := redirected.Client()
	client.CheckRedirect = rejectRedirects
	c.client = client

	_, err := c.Resolve([]byte{0x00, 0x01})
	if err == nil {
		t.Fatal("expected redirect response to be rejected")
	}
	if !strings.Contains(err.Error(), "302") {
		t.Fatalf("expected 302 status error, got %v", err)
	}
}

func TestValidateUpstreamsRejectsUnsafeURLFeatures(t *testing.T) {
	tests := []string{
		"https://user:pass@example.com/dns-query",
		"https://example.com/dns-query#frag",
		"https://example.com:99999/dns-query",
	}

	for _, upstream := range tests {
		if err := ValidateUpstreams(upstream); err == nil {
			t.Fatalf("expected validation failure for %q", upstream)
		}
	}
}
