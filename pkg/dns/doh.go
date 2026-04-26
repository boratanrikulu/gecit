package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Preset struct {
	URL string
}

const maxDoHResponseBytes = 64 << 10

var Presets = map[string]Preset{
	// Presets intentionally use IP literals where possible so bootstrap does
	// not depend on the system resolver that gecit is about to replace.
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

func ValidateUpstreams(upstreams string, allowPlainHTTP bool) error {
	if strings.TrimSpace(upstreams) == "" {
		return fmt.Errorf("DoH upstream must not be empty")
	}
	for _, u := range strings.Split(upstreams, ",") {
		u = strings.TrimSpace(u)
		if u == "" {
			return fmt.Errorf("DoH upstream list contains an empty entry")
		}
		if _, ok := Presets[u]; ok {
			continue
		}
		parsed, err := url.Parse(u)
		if err != nil {
			return fmt.Errorf("parse DoH upstream %q: %w", u, err)
		}
		if parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("DoH upstream %q must be a preset name or absolute URL", u)
		}
		switch parsed.Scheme {
		case "https":
		case "http":
			if !allowPlainHTTP {
				return fmt.Errorf("plain HTTP DoH upstream %q is unsafe; use HTTPS or pass --allow-plain-doh", u)
			}
		default:
			return fmt.Errorf("DoH upstream %q must use https", u)
		}
	}
	return nil
}

// DialFunc is used to bind DoH connections to a specific interface,
// preventing TUN routing loops.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type DoHClient struct {
	upstream string
	name     string
	client   *http.Client
}

func NewDoHClient(upstream string, name string, dial DialFunc) *DoHClient {
	transport := &http.Transport{Proxy: nil}
	if dial != nil {
		transport.DialContext = dial
	}
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}

	// If upstream has a hostname (not IP), resolve it now before gecit
	// takes over system DNS. Replace hostname with IP in URL, set TLS SNI.
	parsed, err := url.Parse(upstream)
	if err == nil {
		host := parsed.Hostname()
		if net.ParseIP(host) == nil {
			if ips, err := net.LookupIP(host); err == nil {
				for _, ip := range ips {
					if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {
						continue
					}
					if ip4 := ip.To4(); ip4 != nil {
						port := parsed.Port()
						if port == "" {
							port = defaultPort(parsed.Scheme)
						}
						parsed.Host = net.JoinHostPort(ip4.String(), port)
						upstream = parsed.String()
						transport.TLSClientConfig = &tls.Config{
							ServerName: host,
							MinVersion: tls.VersionTLS12,
							NextProtos: []string{"h2", "http/1.1"},
						}
						break
					}
					if ip16 := ip.To16(); ip16 != nil {
						port := parsed.Port()
						if port == "" {
							port = defaultPort(parsed.Scheme)
						}
						parsed.Host = net.JoinHostPort(ip16.String(), port)
						upstream = parsed.String()
						transport.TLSClientConfig = &tls.Config{
							ServerName: host,
							MinVersion: tls.VersionTLS12,
							NextProtos: []string{"h2", "http/1.1"},
						}
						break
					}
				}
			}
		}
	}

	return &DoHClient{
		upstream: upstream,
		name:     name,
		client: &http.Client{
			Timeout:   5 * time.Second,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func defaultPort(scheme string) string {
	if scheme == "http" {
		return "80"
	}
	return "443"
}

func (d *DoHClient) Name() string { return d.name }

func (d *DoHClient) Resolve(query []byte) (ResolveResult, error) {
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
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ResolveResult{}, fmt.Errorf("DoH status: %d", resp.StatusCode)
	}
	if resp.ContentLength > maxDoHResponseBytes {
		return ResolveResult{}, fmt.Errorf("DoH response too large: %d > %d", resp.ContentLength, maxDoHResponseBytes)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDoHResponseBytes+1))
	if err != nil {
		return ResolveResult{}, err
	}
	if len(data) > maxDoHResponseBytes {
		return ResolveResult{}, errors.New("DoH response too large")
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

type invalidResolver struct {
	name string
	err  error
}

func (r *invalidResolver) Name() string { return r.name }

func (r *invalidResolver) Resolve(_ []byte) (ResolveResult, error) {
	return ResolveResult{}, r.err
}

// NewResolver parses a comma-separated list of preset names or URLs.
// dial is optional — if provided, DoH connections bypass TUN routing.
func NewResolver(upstreams string, dial DialFunc) Resolver {
	return NewResolverWithOptions(upstreams, dial, false)
}

func NewResolverWithOptions(upstreams string, dial DialFunc, allowPlainHTTP bool) Resolver {
	if err := ValidateUpstreams(upstreams, allowPlainHTTP); err != nil {
		return &invalidResolver{name: "invalid", err: err}
	}

	var clients []Resolver
	for _, u := range strings.Split(upstreams, ",") {
		u = strings.TrimSpace(u)
		if p, ok := Presets[u]; ok {
			clients = append(clients, NewDoHClient(p.URL, u, dial))
		} else {
			clients = append(clients, NewDoHClient(u, u, dial))
		}
	}
	if len(clients) == 1 {
		return clients[0]
	}
	return &fallbackResolver{clients: clients}
}
