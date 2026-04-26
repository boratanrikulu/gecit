package dns

import (
	"fmt"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
)

func newTestServer() *Server {
	return &Server{
		ipQueue: make(map[string][]string),
		logger:  logrus.New(),
	}
}

func TestPopDomain_Empty(t *testing.T) {
	s := newTestServer()
	if got := s.PopDomain("1.2.3.4"); got != "" {
		t.Fatalf("PopDomain on empty queue: got %q, want \"\"", got)
	}
}

func TestPopDomain_Single(t *testing.T) {
	s := newTestServer()
	s.ipQueue["1.2.3.4"] = []string{"example.com"}

	got := s.PopDomain("1.2.3.4")
	if got != "example.com" {
		t.Fatalf("got %q, want %q", got, "example.com")
	}

	// Queue should be deleted after popping the last item.
	if _, exists := s.ipQueue["1.2.3.4"]; exists {
		t.Fatal("queue entry should be deleted after popping last item")
	}
}

func TestPopDomain_FIFO(t *testing.T) {
	s := newTestServer()
	s.ipQueue["10.0.0.1"] = []string{"first.com", "second.com", "third.com"}

	order := []string{"first.com", "second.com", "third.com"}
	for i, want := range order {
		got := s.PopDomain("10.0.0.1")
		if got != want {
			t.Fatalf("pop %d: got %q, want %q", i, got, want)
		}
	}

	// Queue should be empty now.
	if got := s.PopDomain("10.0.0.1"); got != "" {
		t.Fatalf("queue should be empty, got %q", got)
	}
}

func TestPopDomain_IndependentIPs(t *testing.T) {
	s := newTestServer()
	s.ipQueue["1.1.1.1"] = []string{"cloudflare.com"}
	s.ipQueue["8.8.8.8"] = []string{"google.com"}

	got1 := s.PopDomain("1.1.1.1")
	got2 := s.PopDomain("8.8.8.8")

	if got1 != "cloudflare.com" {
		t.Fatalf("IP 1.1.1.1: got %q, want %q", got1, "cloudflare.com")
	}
	if got2 != "google.com" {
		t.Fatalf("IP 8.8.8.8: got %q, want %q", got2, "google.com")
	}
}

func TestPopDomain_Concurrent(t *testing.T) {
	s := newTestServer()

	// Push 1000 domains for one IP.
	domains := make([]string, 1000)
	for i := range domains {
		domains[i] = "domain.com"
	}
	s.ipQueue["10.0.0.1"] = domains

	// Pop from multiple goroutines — must not panic or corrupt.
	var wg sync.WaitGroup
	count := make(chan int, 10)

	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n := 0
			for s.PopDomain("10.0.0.1") != "" {
				n++
			}
			count <- n
		}()
	}
	wg.Wait()
	close(count)

	total := 0
	for n := range count {
		total += n
	}
	if total != 1000 {
		t.Fatalf("total pops: got %d, want 1000", total)
	}
}

func TestPushDomainBoundsPerIPQueue(t *testing.T) {
	s := newTestServer()
	for i := 0; i < maxDomainsPerIP+10; i++ {
		s.pushDomain("10.0.0.1", fmt.Sprintf("domain-%d.com", i))
	}
	if got := len(s.ipQueue["10.0.0.1"]); got != maxDomainsPerIP {
		t.Fatalf("queue length got %d, want %d", got, maxDomainsPerIP)
	}
}

func TestPushDomainBoundsTrackedIPs(t *testing.T) {
	s := newTestServer()
	for i := 0; i < maxTrackedIPs+10; i++ {
		s.pushDomain(string(rune(i+1)), "domain.com")
	}
	if got := len(s.ipQueue); got != maxTrackedIPs {
		t.Fatalf("tracked IPs got %d, want %d", got, maxTrackedIPs)
	}
}

func TestPushDomainDeduplicatesConsecutiveDomains(t *testing.T) {
	s := newTestServer()
	s.pushDomain("10.0.0.1", "domain.com")
	s.pushDomain("10.0.0.1", "domain.com")
	s.pushDomain("10.0.0.1", "other.com")

	if got := s.ipQueue["10.0.0.1"]; len(got) != 2 || got[0] != "domain.com" || got[1] != "other.com" {
		t.Fatalf("queue got %v, want [domain.com other.com]", got)
	}
}

func TestNewServer_SetsGlobal(t *testing.T) {
	globalDNS = nil
	s := NewServer("cloudflare", logrus.New(), nil)

	if GetDNSServer() != s {
		t.Fatal("GetDNSServer() should return the server set by NewServer()")
	}
}
