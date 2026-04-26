package dns

import (
	"strings"
	"testing"
)

func FuzzValidateUpstreams(f *testing.F) {
	f.Add("cloudflare", uint8(0))
	f.Add("https://1.1.1.1/dns-query", uint8(0))
	f.Add("http://127.0.0.1:8053/dns-query", uint8(0))
	f.Add("http://127.0.0.1:8053/dns-query", uint8(1))
	f.Add("cloudflare,,google", uint8(0))
	f.Add("file:///tmp/dns-query", uint8(0))

	f.Fuzz(func(t *testing.T, upstreams string, allowByte uint8) {
		if len(upstreams) > 2048 {
			upstreams = upstreams[:2048]
		}
		allowPlainHTTP := allowByte%2 == 1
		err := ValidateUpstreams(upstreams, allowPlainHTTP)
		if !allowPlainHTTP && err == nil {
			for _, upstream := range strings.Split(upstreams, ",") {
				if strings.HasPrefix(strings.TrimSpace(upstream), "http://") {
					t.Fatalf("plain HTTP upstream accepted without opt-in: %q", upstreams)
				}
			}
		}
	})
}
