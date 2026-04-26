package dns

import (
	"fmt"
	"io"
	"testing"

	"github.com/sirupsen/logrus"
)

func FuzzPushDomainBounds(f *testing.F) {
	f.Add([]byte("example.com"))
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2, 3, 'a', 'b', 'c', 'd'})

	f.Fuzz(func(t *testing.T, data []byte) {
		logger := logrus.New()
		logger.SetOutput(io.Discard)
		s := &Server{
			ipQueue: make(map[string][]string),
			logger:  logger,
		}

		if len(data) > 8192 {
			data = data[:8192]
		}
		for i := 0; i < len(data); i += 8 {
			end := i + 8
			if end > len(data) {
				end = len(data)
			}
			chunk := data[i:end]
			ip := fmt.Sprintf("%d.%d.%d.%d", byteAt(chunk, 0), byteAt(chunk, 1), byteAt(chunk, 2), byteAt(chunk, 3))
			domain := string(chunk)
			s.pushDomain(ip, domain)
		}

		if len(s.ipQueue) > maxTrackedIPs {
			t.Fatalf("tracked IP count got %d, max %d", len(s.ipQueue), maxTrackedIPs)
		}
		for ip, domains := range s.ipQueue {
			if len(domains) > maxDomainsPerIP {
				t.Fatalf("queue for %s got %d domains, max %d", ip, len(domains), maxDomainsPerIP)
			}
		}
	})
}

func byteAt(data []byte, idx int) byte {
	if idx >= len(data) {
		return 0
	}
	return data[idx]
}
