package dns

import (
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type Server struct {
	resolver Resolver
	upstream string
	server   *dns.Server
	logger   *logrus.Logger
	mu       sync.Mutex
	ipQueue  map[string][]string
}

const (
	maxTrackedIPs      = 1024
	maxDomainsPerIP    = 16
	maxTrackedIPLogKey = "tracked_ips"
)

var globalDNS *Server

func GetDNSServer() *Server { return globalDNS }

func (s *Server) PopDomain(ip string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.ipQueue[ip]
	if len(q) == 0 {
		return ""
	}
	domain := q[0]
	if len(q) == 1 {
		delete(s.ipQueue, ip)
	} else {
		s.ipQueue[ip] = q[1:]
	}
	return domain
}

func NewServer(upstream string, logger *logrus.Logger, dial DialFunc) *Server {
	return NewServerWithOptions(upstream, logger, dial, false)
}

func NewServerWithOptions(upstream string, logger *logrus.Logger, dial DialFunc, allowPlainHTTP bool) *Server {
	s := &Server{
		resolver: NewResolverWithOptions(upstream, dial, allowPlainHTTP),
		upstream: upstream,
		logger:   logger,
		ipQueue:  make(map[string][]string),
	}
	globalDNS = s
	return s
}

func (s *Server) pushDomain(ip, domain string) {
	if ip == "" || domain == "" {
		return
	}
	if _, ok := s.ipQueue[ip]; !ok && len(s.ipQueue) >= maxTrackedIPs {
		if s.logger != nil {
			s.logger.WithFields(logrus.Fields{
				maxTrackedIPLogKey: len(s.ipQueue),
				"max":              maxTrackedIPs,
			}).Debug("DNS attribution cache full; dropping domain mapping")
		}
		return
	}
	q := s.ipQueue[ip]
	if len(q) > 0 && q[len(q)-1] == domain {
		return
	}
	if len(q) >= maxDomainsPerIP {
		q = q[len(q)-maxDomainsPerIP+1:]
	}
	s.ipQueue[ip] = append(q, domain)
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
			for _, ip := range ips {
				s.pushDomain(ip, domain)
			}
			s.mu.Unlock()
		}
	}
}

func (s *Server) sendError(w dns.ResponseWriter, r *dns.Msg, rcode int) {
	resp := new(dns.Msg)
	resp.SetRcode(r, rcode)
	if err := w.WriteMsg(resp); err != nil && s.logger != nil {
		s.logger.WithError(err).Debug("failed to write DNS error response")
	}
}
