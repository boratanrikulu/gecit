package dns

import (
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// Server is a local DNS server that forwards queries via DoH.
type Server struct {
	doh     *DoHClient
	server  *dns.Server
	logger  *logrus.Logger
	mu      sync.Mutex
	ipQueue map[string][]string // IP → FIFO queue of domains
}

var globalDNS *Server

// GetDNSServer returns the global DNS server instance (for domain lookup).
func GetDNSServer() *Server { return globalDNS }

// PopDomain returns and removes the next domain for this IP.
// DNS resolution pushes, connection pops — FIFO order.
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

func NewServer(dohUpstream string, logger *logrus.Logger) *Server {
	s := &Server{
		doh:     NewDoHClient(dohUpstream),
		logger:  logger,
		ipQueue: make(map[string][]string),
	}
	globalDNS = s
	return s
}

// Start begins listening for DNS queries on 127.0.0.1:53.
func (s *Server) Start() error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleQuery)

	s.server = &dns.Server{
		Addr:    "127.0.0.1:53",
		Net:     "udp",
		Handler: mux,
	}

	// Use NotifyStartedFunc to confirm the server actually bound the port.
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

	// Wait for actual bind or failure.
	if err := <-started; err != nil {
		return fmt.Errorf("DNS server: %w", err)
	}

	s.logger.WithField("addr", "127.0.0.1:53").Info("DoH DNS server started")
	return nil
}

// Stop shuts down the DNS server.
func (s *Server) Stop() error {
	if s.server != nil {
		return s.server.Shutdown()
	}
	return nil
}

func (s *Server) handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	// Pack the query to raw wire format.
	queryBytes, err := r.Pack()
	if err != nil {
		s.sendError(w, r, dns.RcodeServerFailure)
		return
	}

	// Forward via DoH.
	respBytes, err := s.doh.Resolve(queryBytes)
	if err != nil {
		s.logger.WithError(err).Debug("DoH resolve failed")
		s.sendError(w, r, dns.RcodeServerFailure)
		return
	}

	// Unpack the DoH response.
	resp := new(dns.Msg)
	if err := resp.Unpack(respBytes); err != nil {
		s.sendError(w, r, dns.RcodeServerFailure)
		return
	}

	// Match the query ID (DoH might return a different ID).
	resp.Id = r.Id

	if err := w.WriteMsg(resp); err != nil {
		s.logger.WithError(err).Debug("failed to write DNS response")
	}

	// Log A/AAAA queries for visibility.
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
			// Cache IP→domain for log display (FIFO queue).
			domain := strings.TrimSuffix(q.Name, ".")
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
