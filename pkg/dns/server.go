package dns

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type Server struct {
	resolver Resolver
	upstream string
	server   *dns.Server
	logger   *logrus.Logger
	mu       sync.Mutex
	ipQueue  map[string][]queuedDomain
}

var globalDNS *Server

func GetDNSServer() *Server { return globalDNS }

const (
	ipQueueEntryTTL    = 30 * time.Second
	ipQueueMaxPerIP    = 16
	ipQueueMaxDistinct = 4096 // upper bound on distinct IPs tracked
)

type queuedDomain struct {
	domain  string
	addedAt time.Time
}

func (s *Server) PopDomain(ip string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	q := pruneQueuedDomains(s.ipQueue[ip], time.Now())
	if len(q) == 0 {
		delete(s.ipQueue, ip)
		return ""
	}
	domain := q[0].domain
	if len(q) == 1 {
		delete(s.ipQueue, ip)
	} else {
		s.ipQueue[ip] = q[1:]
	}
	return domain
}

func NewServer(upstream string, logger *logrus.Logger, dial DialFunc) *Server {
	s := &Server{
		resolver: NewResolver(upstream, dial),
		upstream: upstream,
		logger:   logger,
		ipQueue:  make(map[string][]queuedDomain),
	}
	globalDNS = s
	return s
}

func (s *Server) Start() error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleQuery)

	s.server = &dns.Server{
		Addr:    "127.0.0.1:53",
		Net:     "udp",
		Handler: mux,
	}

	started := make(chan error, 1)
	s.server.NotifyStartedFunc = func() {
		started <- nil
	}

	go func() {
		if err := s.server.ListenAndServe(); err != nil {
			s.logger.WithError(err).Error("DNS server failed")
			select {
			case started <- err:
			default:
			}
		}
	}()

	if err := <-started; err != nil {
		return fmt.Errorf("DNS server: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"addr":     "127.0.0.1:53",
		"upstream": s.upstream,
	}).Info("DNS server started")
	return nil
}

func (s *Server) Stop() error {
	if s.server != nil {
		return s.server.Shutdown()
	}
	return nil
}

func (s *Server) handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	queryBytes, err := r.Pack()
	if err != nil {
		s.sendError(w, r, dns.RcodeServerFailure)
		return
	}

	result, err := s.resolver.Resolve(queryBytes)
	if err != nil {
		s.logger.WithError(err).Debug("DNS resolve failed")
		s.sendError(w, r, dns.RcodeServerFailure)
		return
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(result.Data); err != nil {
		s.sendError(w, r, dns.RcodeServerFailure)
		return
	}

	resp.Id = r.Id

	if err := w.WriteMsg(resp); err != nil {
		s.logger.WithError(err).Debug("failed to write DNS response")
	}

	if len(r.Question) > 0 && len(resp.Answer) > 0 {
		q := r.Question[0]
		if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
			var ips []string
			for _, a := range resp.Answer {
				if aRec, ok := a.(*dns.A); ok {
					ips = append(ips, aRec.A.String())
				}
				if aaaaRec, ok := a.(*dns.AAAA); ok {
					ips = append(ips, aaaaRec.AAAA.String())
				}
			}
			domain := strings.TrimSuffix(q.Name, ".")
			s.logger.WithFields(logrus.Fields{
				"domain": domain,
				"ips":    strings.Join(ips, ","),
				"via":    result.Via,
			}).Debug("DNS resolved")
			s.mu.Lock()
			now := time.Now()
			for _, ip := range ips {
				q := pruneQueuedDomains(s.ipQueue[ip], now)
				q = append(q, queuedDomain{domain: domain, addedAt: now})
				if len(q) > ipQueueMaxPerIP {
					q = q[len(q)-ipQueueMaxPerIP:]
				}
				// If the map already has too many distinct IPs and this
				// is a brand-new key, skip it to bound memory growth.
				if _, exists := s.ipQueue[ip]; !exists && len(s.ipQueue) >= ipQueueMaxDistinct {
					continue
				}
				s.ipQueue[ip] = q
			}
			s.mu.Unlock()
		}
	}
}

func pruneQueuedDomains(q []queuedDomain, now time.Time) []queuedDomain {
	if len(q) == 0 {
		return nil
	}

	out := q[:0]
	for _, entry := range q {
		if now.Sub(entry.addedAt) <= ipQueueEntryTTL {
			out = append(out, entry)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *Server) sendError(w dns.ResponseWriter, r *dns.Msg, rcode int) {
	resp := new(dns.Msg)
	resp.SetRcode(r, rcode)
	w.WriteMsg(resp)
}
