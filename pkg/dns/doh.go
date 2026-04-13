package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxDoHResponseBytes = 65535

type Preset struct {
	URL string
}

var Presets = map[string]Preset{
	"cloudflare": {URL: "https://1.1.1.1/dns-query"},
	"google":     {URL: "https://8.8.8.8/dns-query"},
	"quad9":      {URL: "https://9.9.9.9:5053/dns-query"},
	"nextdns":    {URL: "https://dns.nextdns.io/dns-query"},
	"adguard":    {URL: "https://dns.adguard-dns.com/dns-query"},
}

type ResolveResult struct {
	Data []byte
	Via  string
}

type Resolver interface {
	Resolve(query []byte) (ResolveResult, error)
	Name() string
}

// DialFunc is used to bind DoH connections to a specific interface,
// preventing TUN routing loops.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type DoHClient struct {
	upstream string
	name     string
	client   *http.Client
	initErr  error
}

func NewDoHClient(upstream string, name string, dial DialFunc) *DoHClient {
	transport := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	if dial != nil {
		transport.DialContext = dial
	}

	client := &DoHClient{
		upstream: upstream,
		name:     name,
		client: &http.Client{
			Timeout:       5 * time.Second,
			Transport:     transport,
			CheckRedirect: rejectRedirects,
		},
	}

	// If upstream has a hostname (not IP), resolve it now before gecit
	// takes over system DNS. Replace hostname with IP in URL, set TLS SNI.
	parsed, err := validateDoHURL(upstream)
	if err != nil {
		client.initErr = err
		return client
	}
	host := parsed.Hostname()
	if net.ParseIP(host) == nil {
		if ips, err := net.LookupIP(host); err == nil {
			for _, ip := range ips {
				if ip4 := ip.To4(); ip4 != nil {
					port := parsed.Port()
					if port == "" {
						port = "443"
					}
					parsed.Host = net.JoinHostPort(ip4.String(), port)
					client.upstream = parsed.String()
					transport.TLSClientConfig.ServerName = host
					break
				}
			}
		}
	}
	return client
}

func (d *DoHClient) Name() string { return d.name }

func (d *DoHClient) Resolve(query []byte) (ResolveResult, error) {
	if d.initErr != nil {
		return ResolveResult{}, d.initErr
	}

	req, err := http.NewRequest("POST", d.upstream, bytes.NewReader(query))
	if err != nil {
		return ResolveResult{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := d.client.Do(req)
	if err != nil {
		return ResolveResult{}, fmt.Errorf("DoH request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ResolveResult{}, fmt.Errorf("DoH status: %d", resp.StatusCode)
	}

	if resp.ContentLength > maxDoHResponseBytes {
		return ResolveResult{}, fmt.Errorf("DoH response too large: %d bytes", resp.ContentLength)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDoHResponseBytes+1))
	if err != nil {
		return ResolveResult{}, err
	}
	if len(data) > maxDoHResponseBytes {
		return ResolveResult{}, fmt.Errorf("DoH response too large")
	}
	return ResolveResult{Data: data, Via: d.name}, nil
}

type fallbackResolver struct {
	clients []Resolver
}

func (r *fallbackResolver) Name() string {
	var names []string
	for _, c := range r.clients {
		names = append(names, c.Name())
	}
	return strings.Join(names, ",")
}

func (r *fallbackResolver) Resolve(query []byte) (ResolveResult, error) {
	var lastErr error
	for _, c := range r.clients {
		result, err := c.Resolve(query)
		if err == nil {
			return result, nil
		}
		lastErr = err
	}
	return ResolveResult{}, lastErr
}

// NewResolver parses a comma-separated list of preset names or URLs.
// dial is optional — if provided, DoH connections bypass TUN routing.
func NewResolver(upstreams string, dial DialFunc) Resolver {
	var clients []Resolver
	for _, u := range strings.Split(upstreams, ",") {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if p, ok := Presets[u]; ok {
			clients = append(clients, NewDoHClient(p.URL, u, dial))
		} else {
			clients = append(clients, NewDoHClient(u, u, dial))
		}
	}
	if len(clients) == 0 {
		return NewDoHClient("", "", dial)
	}
	if len(clients) == 1 {
		return clients[0]
	}
	return &fallbackResolver{clients: clients}
}

func ValidateUpstreams(upstreams string) error {
	seen := 0
	for _, u := range strings.Split(upstreams, ",") {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if p, ok := Presets[u]; ok {
			u = p.URL
		}
		if _, err := validateDoHURL(u); err != nil {
			return err
		}
		seen++
	}
	if seen == 0 {
		return fmt.Errorf("at least one DoH upstream is required")
	}
	return nil
}

func validateDoHURL(upstream string) (*url.URL, error) {
	parsed, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("parse DoH upstream %q: %w", upstream, err)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("DoH upstream must use https: %q", upstream)
	}
	if parsed.Hostname() == "" {
		return nil, fmt.Errorf("DoH upstream host is empty: %q", upstream)
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("DoH upstream must not include userinfo: %q", upstream)
	}
	if parsed.Fragment != "" {
		return nil, fmt.Errorf("DoH upstream must not include fragments: %q", upstream)
	}
	if port := parsed.Port(); port != "" {
		num, err := strconv.Atoi(port)
		if err != nil || num < 1 || num > 65535 {
			return nil, fmt.Errorf("DoH upstream port is invalid: %q", upstream)
		}
	}
	return parsed, nil
}

func rejectRedirects(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}
