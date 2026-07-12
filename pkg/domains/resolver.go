package domains

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type LookupFunc func(host string) ([]net.IP, error)

type Resolver struct {
	domains   []string
	ips       map[string]bool
	mu        sync.RWMutex
	logger    *logrus.Logger
	resolved  bool
	lookupFn  LookupFunc
}

func New(domains []string, logger *logrus.Logger) *Resolver {
	return &Resolver{
		domains:  domains,
		ips:      make(map[string]bool),
		logger:   logger,
		lookupFn: net.LookupIP,
	}
}

func NewWithLookup(domains []string, logger *logrus.Logger, lookup LookupFunc) *Resolver {
	return &Resolver{
		domains:  domains,
		ips:      make(map[string]bool),
		logger:   logger,
		lookupFn: lookup,
	}
}

// Resolve performs DNS lookups for all domains.
// Requires system DNS to be redirected to DoH server first.
func (r *Resolver) Resolve() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.ips = make(map[string]bool)
	var unresolved []string

	for _, domain := range r.domains {
		ips, err := r.lookupFn(domain)
		if err != nil {
			unresolved = append(unresolved, domain)
			r.logger.WithError(err).WithField("domain", domain).Debug("DNS lookup failed")
			continue
		}
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				r.ips[ipv4.String()] = true
			}
		}
	}

	r.resolved = true

	if len(unresolved) > 0 {
		return fmt.Errorf("failed to resolve %d domains: %v", len(unresolved), unresolved)
	}
	return nil
}

func (r *Resolver) ContainsIP(ip string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ips[ip]
}

func (r *Resolver) IPs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ips := make([]string, 0, len(r.ips))
	for ip := range r.ips {
		ips = append(ips, ip)
	}
	return ips
}

// StartRefresh periodically re-resolves domains (Domain IP's can change).
func (r *Resolver) StartRefresh(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			if err := r.Resolve(); err != nil {
				r.logger.WithError(err).Debug("domain refresh failed")
			} else {
				r.logger.WithField("count", len(r.ips)).Debug("domains refreshed")
			}
		}
	}()
}
