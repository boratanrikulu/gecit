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
	"sort"
	"strings"
	"time"
)

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
}

func NewDoHClient(upstream string, name string, dial DialFunc) *DoHClient {
	transport := &http.Transport{Proxy: nil}
	if dial != nil {
		transport.DialContext = dial
	}

	// If upstream has a hostname (not IP), resolve it now before gecit
	// takes over system DNS. Replace hostname with IP in URL, set TLS SNI.
	parsed, err := url.Parse(upstream)
	if err == nil {
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
						upstream = parsed.String()
						transport.TLSClientConfig = &tls.Config{ServerName: host}
						break
					}
				}
			}
		}
	}

	return &DoHClient{
		upstream: upstream,
		name:     name,
		client:   &http.Client{Timeout: 5 * time.Second, Transport: transport},
	}
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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ResolveResult{}, fmt.Errorf("DoH status: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return ResolveResult{}, err
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

// ValidateUpstreams rejects upstreams that would resolve names in cleartext.
// gecit points the system resolver at itself, so an upstream that is not
// HTTPS hands every lookup on the machine to whoever is on the path.
func ValidateUpstreams(upstreams string) error {
	if strings.TrimSpace(upstreams) == "" {
		return errors.New("no upstream given")
	}
	for _, u := range strings.Split(upstreams, ",") {
		u = strings.TrimSpace(u)
		if u == "" {
			return errors.New("empty upstream in list")
		}
		if _, ok := Presets[u]; ok {
			continue
		}
		parsed, err := url.Parse(u)
		if err != nil {
			return fmt.Errorf("%q is not a preset or a URL: %w", u, err)
		}
		if parsed.Scheme != "https" {
			return fmt.Errorf("%q must use https, or name a preset (%s)", u, presetNames())
		}
		if parsed.Host == "" {
			return fmt.Errorf("%q has no host", u)
		}
	}
	return nil
}

// PresetNames lists the upstream names an operator can use in place of a URL,
// sorted so a form built from them keeps a stable order.
func PresetNames() []string {
	names := make([]string, 0, len(Presets))
	for name := range Presets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func presetNames() string { return strings.Join(PresetNames(), ", ") }
