package dns

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/boratanrikulu/gecit/pkg/engine"
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

	queries atomic.Uint64
	errors  atomic.Uint64
}

func (s *Server) Stats() engine.Stats {
	return engine.Stats{
		DNSQueries: s.queries.Load(),
		DNSErrors:  s.errors.Load(),
	}
}

// The server is replaced whenever the engine restarts, which the panel can do
// while injector goroutines are calling GetDNSServer.
var globalDNS atomic.Pointer[Server]

func GetDNSServer() *Server { return globalDNS.Load() }

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
	s := &Server{
		resolver: NewResolver(upstream, dial),
		upstream: upstream,
		logger:   logger,
		ipQueue:  make(map[string][]string),
	}
	globalDNS.Store(s)
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
	s.queries.Add(1)

	queryBytes, err := r.Pack()
	if err != nil {
		s.errors.Add(1)
		s.sendError(w, r, dns.RcodeServerFailure)
		return
	}

	result, err := s.resolver.Resolve(queryBytes)
	if err != nil {
		s.errors.Add(1)
		s.logger.WithError(err).Debug("DNS resolve failed")
		s.sendError(w, r, dns.RcodeServerFailure)
		return
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(result.Data); err != nil {
		s.errors.Add(1)
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
				"event":  "dns",
				"domain": domain,
				"ips":    strings.Join(ips, ","),
				"via":    result.Via,
			}).Debug("DNS resolved")
			s.mu.Lock()
			for _, ip := range ips {
				s.ipQueue[ip] = append(s.ipQueue[ip], domain)
			}
			s.mu.Unlock()
		}
	}
}

func (s *Server) sendError(w dns.ResponseWriter, r *dns.Msg, rcode int) {
	resp := new(dns.Msg)
	resp.SetRcode(r, rcode)
	w.WriteMsg(resp)
}
