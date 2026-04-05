package dns

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DoHClient forwards raw DNS queries over HTTPS (RFC 8484).
// Handles all query types (A, AAAA, MX, CNAME, etc.) by forwarding
// the raw wire-format DNS packet.
type DoHClient struct {
	upstream string
	client   *http.Client
}

func NewDoHClient(upstream string) *DoHClient {
	return &DoHClient{
		upstream: upstream,
		client: &http.Client{
			Timeout: 5 * time.Second,
			// Bypass system proxy — DoH must go directly to the upstream.
			// Without this, the DoH request loops through our own HTTPS proxy
			// on macOS (where we set system proxy to 127.0.0.1:8443).
			Transport: &http.Transport{
				Proxy: nil,
			},
		},
	}
}

// Resolve sends a raw DNS query via DoH and returns the raw response.
func (d *DoHClient) Resolve(query []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", d.upstream, bytes.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read DoH response: %w", err)
	}

	return body, nil
}
