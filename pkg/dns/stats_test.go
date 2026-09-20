package dns

import (
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type stubResolver struct {
	answer []byte
	err    error
}

func (r stubResolver) Resolve([]byte) (ResolveResult, error) {
	if r.err != nil {
		return ResolveResult{}, r.err
	}
	return ResolveResult{Data: r.answer, Via: "stub"}, nil
}

func (r stubResolver) Name() string { return "stub" }

// discardWriter is the minimum dns.ResponseWriter handleQuery touches.
type discardWriter struct{}

func (discardWriter) LocalAddr() net.Addr       { return &net.UDPAddr{} }
func (discardWriter) RemoteAddr() net.Addr      { return &net.UDPAddr{} }
func (discardWriter) WriteMsg(*dns.Msg) error   { return nil }
func (discardWriter) Write([]byte) (int, error) { return 0, nil }
func (discardWriter) Close() error              { return nil }
func (discardWriter) TsigStatus() error         { return nil }
func (discardWriter) TsigTimersOnly(bool)       {}
func (discardWriter) Hijack()                   {}
func (discardWriter) Network() string           { return "udp" }

func query(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return m
}

func answerFor(t *testing.T, name, ip string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetReply(query(name))
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP(ip).To4(),
	}}
	packed, err := m.Pack()
	if err != nil {
		t.Fatalf("pack answer: %v", err)
	}
	return packed
}

func TestStatsCountsQueriesAndErrors(t *testing.T) {
	s := newTestServer()
	s.resolver = stubResolver{answer: answerFor(t, "example.com", "93.184.216.34")}

	s.handleQuery(discardWriter{}, query("example.com"))
	s.handleQuery(discardWriter{}, query("example.org"))

	if got := s.Stats(); got.DNSQueries != 2 || got.DNSErrors != 0 {
		t.Fatalf("after two answers: queries=%d errors=%d, want 2 and 0", got.DNSQueries, got.DNSErrors)
	}

	s.resolver = stubResolver{err: errors.New("upstream down")}
	s.handleQuery(discardWriter{}, query("example.net"))

	if got := s.Stats(); got.DNSQueries != 3 || got.DNSErrors != 1 {
		t.Fatalf("after a failure: queries=%d errors=%d, want 3 and 1", got.DNSQueries, got.DNSErrors)
	}
}

// handleQuery runs on one goroutine per query while the panel's HTTP handler
// reads Stats, so the counters have to hold up under -race.
func TestStatsConcurrentWithReader(t *testing.T) {
	s := newTestServer()
	s.resolver = stubResolver{answer: answerFor(t, "example.com", "93.184.216.34")}

	stop := make(chan struct{})
	var reader sync.WaitGroup
	reader.Add(1)
	go func() {
		defer reader.Done()
		for {
			select {
			case <-stop:
				return
			default:
				s.Stats()
			}
		}
	}()

	var writers sync.WaitGroup
	for i := 0; i < 20; i++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for j := 0; j < 25; j++ {
				s.handleQuery(discardWriter{}, query("example.com"))
			}
		}()
	}
	writers.Wait()
	close(stop)
	reader.Wait()

	if got := s.Stats(); got.DNSQueries != 500 {
		t.Fatalf("queries = %d, want 500", got.DNSQueries)
	}
}

// The panel can restart the engine, which builds a new Server and stores it in
// the global while injector goroutines are reading it.
func TestGlobalServerSwapIsRaceFree(t *testing.T) {
	// The last NewServer below leaves a throwaway in the global. Later tests
	// must not inherit it.
	t.Cleanup(func() { globalDNS.Store(nil) })

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 2000; j++ {
				if s := GetDNSServer(); s != nil {
					s.PopDomain("1.2.3.4")
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			NewServer("cloudflare", logrus.New(), nil)
		}
	}()

	wg.Wait()
}
