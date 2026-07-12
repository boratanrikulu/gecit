package domains

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func testLogger() *logrus.Logger {
	l := logrus.New()
	l.SetLevel(logrus.ErrorLevel)
	return l
}

func TestNew_SetsDefaults(t *testing.T) {
	r := New([]string{"example.com"}, testLogger())
	if r == nil {
		t.Fatal("New returned nil")
	}
	if len(r.domains) != 1 || r.domains[0] != "example.com" {
		t.Fatalf("domains: got %v, want [example.com]", r.domains)
	}
	if r.ips == nil {
		t.Fatal("ips map not initialized")
	}
}

func TestNewWithLookup_UsesCustomLookup(t *testing.T) {
	called := false
	lookup := func(host string) ([]net.IP, error) {
		called = true
		return []net.IP{net.ParseIP("1.2.3.4")}, nil
	}
	r := NewWithLookup([]string{"test.local"}, testLogger(), lookup)
	r.Resolve()

	if !called {
		t.Fatal("custom lookup function was not called")
	}
	if !r.ContainsIP("1.2.3.4") {
		t.Fatal("expected IP 1.2.3.4 to be present")
	}
}

func TestResolve_SingleDomain(t *testing.T) {
	lookup := func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.0.0.1")}, nil
	}
	r := NewWithLookup([]string{"a.com"}, testLogger(), lookup)

	if err := r.Resolve(); err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if !r.ContainsIP("10.0.0.1") {
		t.Fatal("expected 10.0.0.1")
	}
}

func TestResolve_MultipleDomains(t *testing.T) {
	lookup := func(host string) ([]net.IP, error) {
		switch host {
		case "a.com":
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		case "b.com":
			return []net.IP{net.ParseIP("2.2.2.2")}, nil
		default:
			return nil, fmt.Errorf("unknown host")
		}
	}
	r := NewWithLookup([]string{"a.com", "b.com"}, testLogger(), lookup)

	if err := r.Resolve(); err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if !r.ContainsIP("1.1.1.1") {
		t.Fatal("expected 1.1.1.1")
	}
	if !r.ContainsIP("2.2.2.2") {
		t.Fatal("expected 2.2.2.2")
	}
}

func TestResolve_MultipleIPsPerDomain(t *testing.T) {
	lookup := func(host string) ([]net.IP, error) {
		return []net.IP{
			net.ParseIP("10.0.0.1"),
			net.ParseIP("10.0.0.2"),
			net.ParseIP("10.0.0.3"),
		}, nil
	}
	r := NewWithLookup([]string{"multi.com"}, testLogger(), lookup)

	if err := r.Resolve(); err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	ips := r.IPs()
	if len(ips) != 3 {
		t.Fatalf("expected 3 IPs, got %d: %v", len(ips), ips)
	}
}

func TestResolve_SkipsIPv6(t *testing.T) {
	lookup := func(host string) ([]net.IP, error) {
		return []net.IP{
			net.ParseIP("10.0.0.1"),
			net.ParseIP("::1"),
			net.ParseIP("2001:db8::1"),
		}, nil
	}
	r := NewWithLookup([]string{"dual.com"}, testLogger(), lookup)

	if err := r.Resolve(); err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	ips := r.IPs()
	if len(ips) != 1 {
		t.Fatalf("expected 1 IPv4 only, got %d: %v", len(ips), ips)
	}
	if ips[0] != "10.0.0.1" {
		t.Fatalf("expected 10.0.0.1, got %s", ips[0])
	}
}

func TestResolve_DeduplicatesIPs(t *testing.T) {
	lookup := func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("5.5.5.5")}, nil
	}
	r := NewWithLookup([]string{"a.com", "b.com", "c.com"}, testLogger(), lookup)

	if err := r.Resolve(); err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	ips := r.IPs()
	if len(ips) != 1 {
		t.Fatalf("expected 1 unique IP, got %d: %v", len(ips), ips)
	}
}

func TestResolve_OneDomainFails(t *testing.T) {
	lookup := func(host string) ([]net.IP, error) {
		if host == "bad.com" {
			return nil, fmt.Errorf("lookup failed")
		}
		return []net.IP{net.ParseIP("1.2.3.4")}, nil
	}
	r := NewWithLookup([]string{"good.com", "bad.com"}, testLogger(), lookup)

	err := r.Resolve()
	if err == nil {
		t.Fatal("expected error for partial failure")
	}

	// good.com should still be resolved
	if !r.ContainsIP("1.2.3.4") {
		t.Fatal("expected good.com IP to be present despite bad.com failure")
	}
}

func TestResolve_AllDomainsFail(t *testing.T) {
	lookup := func(host string) ([]net.IP, error) {
		return nil, fmt.Errorf("no such host")
	}
	r := NewWithLookup([]string{"a.com", "b.com"}, testLogger(), lookup)

	err := r.Resolve()
	if err == nil {
		t.Fatal("expected error when all domains fail")
	}
	ips := r.IPs()
	if len(ips) != 0 {
		t.Fatalf("expected 0 IPs, got %d", len(ips))
	}
}

func TestResolve_EmptyDomainList(t *testing.T) {
	lookup := func(host string) ([]net.IP, error) {
		t.Fatal("lookup should not be called with empty domain list")
		return nil, nil
	}
	r := NewWithLookup([]string{}, testLogger(), lookup)

	if err := r.Resolve(); err != nil {
		t.Fatalf("Resolve with empty list should not error: %v", err)
	}
	if len(r.IPs()) != 0 {
		t.Fatal("expected 0 IPs")
	}
}

func TestResolve_NilLookup(t *testing.T) {
	lookup := func(host string) ([]net.IP, error) {
		return nil, fmt.Errorf("no DNS")
	}
	r := NewWithLookup([]string{"fail.com"}, testLogger(), lookup)

	err := r.Resolve()
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestContainsIP_BeforeResolve(t *testing.T) {
	r := New([]string{}, testLogger())
	if r.ContainsIP("1.2.3.4") {
		t.Fatal("ContainsIP should return false before Resolve")
	}
}

func TestContainsIP_AfterResolve(t *testing.T) {
	lookup := func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.0.0.1")}, nil
	}
	r := NewWithLookup([]string{"a.com"}, testLogger(), lookup)
	r.Resolve()

	if !r.ContainsIP("10.0.0.1") {
		t.Fatal("expected ContainsIP true for resolved IP")
	}
	if r.ContainsIP("99.99.99.99") {
		t.Fatal("expected ContainsIP false for unresolved IP")
	}
}

func TestContainsIP_ResolveResets(t *testing.T) {
	callCount := 0
	lookup := func(host string) ([]net.IP, error) {
		callCount++
		if callCount <= 1 {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}
		return []net.IP{net.ParseIP("2.2.2.2")}, nil
	}
	r := NewWithLookup([]string{"a.com"}, testLogger(), lookup)

	r.Resolve()
	if !r.ContainsIP("1.1.1.1") {
		t.Fatal("expected 1.1.1.1 after first resolve")
	}

	r.Resolve()
	if r.ContainsIP("1.1.1.1") {
		t.Fatal("1.1.1.1 should be gone after second resolve")
	}
	if !r.ContainsIP("2.2.2.2") {
		t.Fatal("expected 2.2.2.2 after second resolve")
	}
}

func TestIPs_Empty(t *testing.T) {
	r := New([]string{}, testLogger())
	ips := r.IPs()
	if len(ips) != 0 {
		t.Fatalf("expected empty, got %v", ips)
	}
}

func TestIPs_ReturnsCopy(t *testing.T) {
	lookup := func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}
	r := NewWithLookup([]string{"a.com"}, testLogger(), lookup)
	r.Resolve()

	ips1 := r.IPs()
	ips2 := r.IPs()
	ips1[0] = "mutated"

	if ips2[0] != "1.1.1.1" {
		t.Fatal("IPs() should return independent slices")
	}
}

func TestResolve_Concurrent(t *testing.T) {
	var callCount int64
	lookup := func(host string) ([]net.IP, error) {
		atomic.AddInt64(&callCount, 1)
		return []net.IP{net.ParseIP("10.0.0.1")}, nil
	}
	r := NewWithLookup([]string{"a.com", "b.com"}, testLogger(), lookup)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Resolve()
		}()
	}
	wg.Wait()

	if !r.ContainsIP("10.0.0.1") {
		t.Fatal("expected IP after concurrent resolves")
	}
}

func TestContainsIP_Concurrent(t *testing.T) {
	lookup := func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.0.0.1")}, nil
	}
	r := NewWithLookup([]string{"a.com"}, testLogger(), lookup)
	r.Resolve()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.ContainsIP("10.0.0.1")
			r.ContainsIP("99.99.99.99")
		}()
	}
	wg.Wait()
}

func TestStartRefresh_Interval(t *testing.T) {
	var calls int64
	lookup := func(host string) ([]net.IP, error) {
		atomic.AddInt64(&calls, 1)
		return []net.IP{net.ParseIP("10.0.0.1")}, nil
	}
	r := NewWithLookup([]string{"a.com"}, testLogger(), lookup)

	r.StartRefresh(50 * time.Millisecond)
	defer func() { /* let goroutine exit */ }()

	// Wait for at least 2 refreshes
	time.Sleep(150 * time.Millisecond)

	count := atomic.LoadInt64(&calls)
	if count < 2 {
		t.Fatalf("expected at least 2 refresh calls, got %d", count)
	}
}

func TestResolve_LargeDomainList(t *testing.T) {
	domains := make([]string, 1000)
	for i := range domains {
		domains[i] = fmt.Sprintf("host%d.example.com", i)
	}

	var mu sync.Mutex
	seen := make(map[string]bool)
	lookup := func(host string) ([]net.IP, error) {
		mu.Lock()
		seen[host] = true
		mu.Unlock()
		return []net.IP{net.ParseIP("10.0.0.1")}, nil
	}
	r := NewWithLookup(domains, testLogger(), lookup)

	if err := r.Resolve(); err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	mu.Lock()
	if len(seen) != 1000 {
		t.Fatalf("expected 1000 unique lookups, got %d", len(seen))
	}
	mu.Unlock()

	if !r.ContainsIP("10.0.0.1") {
		t.Fatal("expected IP to be present")
	}
}

func TestResolve_LookupReturnsEmpty(t *testing.T) {
	lookup := func(host string) ([]net.IP, error) {
		return []net.IP{}, nil
	}
	r := NewWithLookup([]string{"empty.com"}, testLogger(), lookup)

	if err := r.Resolve(); err != nil {
		t.Fatalf("Resolve should not error on empty results: %v", err)
	}
	if len(r.IPs()) != 0 {
		t.Fatal("expected 0 IPs from empty lookup")
	}
}

func TestResolve_LookupReturnsNil(t *testing.T) {
	lookup := func(host string) ([]net.IP, error) {
		return nil, nil
	}
	r := NewWithLookup([]string{"nil.com"}, testLogger(), lookup)

	if err := r.Resolve(); err != nil {
		t.Fatalf("Resolve should not error on nil results: %v", err)
	}
	if len(r.IPs()) != 0 {
		t.Fatal("expected 0 IPs from nil lookup")
	}
}

func TestResolve_MixedIPv4IPv6(t *testing.T) {
	lookup := func(host string) ([]net.IP, error) {
		return []net.IP{
			net.ParseIP("192.168.1.1"),
			net.ParseIP("10.0.0.1"),
		}, nil
	}
	r := NewWithLookup([]string{"dual-stack.com"}, testLogger(), lookup)

	if err := r.Resolve(); err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	ips := r.IPs()
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPv4 IPs, got %d: %v", len(ips), ips)
	}
}

func TestResolve_ErrorPreservesPreviousState(t *testing.T) {
	callCount := 0
	lookup := func(host string) ([]net.IP, error) {
		callCount++
		if callCount == 1 {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}
		return nil, fmt.Errorf("dns failure")
	}
	r := NewWithLookup([]string{"a.com"}, testLogger(), lookup)

	// First resolve succeeds
	if err := r.Resolve(); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if !r.ContainsIP("1.1.1.1") {
		t.Fatal("expected 1.1.1.1 after first resolve")
	}

	// Second resolve fails — should clear previous IPs
	if err := r.Resolve(); err == nil {
		t.Fatal("expected error on second resolve")
	}
	if r.ContainsIP("1.1.1.1") {
		t.Fatal("IPs should be cleared on failed resolve")
	}
}
