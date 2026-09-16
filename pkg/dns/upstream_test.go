package dns

import "testing"

func TestValidateUpstreams(t *testing.T) {
	valid := []string{
		"cloudflare",
		"quad9",
		"cloudflare,quad9",
		"https://8.8.8.8/dns-query",
		"https://dns.example/dns-query,google",
	}
	for _, u := range valid {
		if err := ValidateUpstreams(u); err != nil {
			t.Errorf("ValidateUpstreams(%q) = %v, want nil", u, err)
		}
	}

	// gecit points the system resolver at itself, so a cleartext upstream
	// hands every lookup on the machine to whoever is on the path.
	invalid := []string{
		"",
		"   ",
		"http://attacker.example/dns-query",
		"cloudflare,http://attacker.example/dns",
		"ftp://example/dns",
		"https://",
		"cloudflare,",
		"not-a-preset",
	}
	for _, u := range invalid {
		if err := ValidateUpstreams(u); err == nil {
			t.Errorf("ValidateUpstreams(%q) = nil, want an error", u)
		}
	}
}
