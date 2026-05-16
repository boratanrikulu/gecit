package capture

import (
	"fmt"
	"strings"

	"github.com/boratanrikulu/gecit/pkg/rawsock"
)

// ConnectionEvent is emitted when a new TLS connection is detected.
type ConnectionEvent = rawsock.ConnInfo

// Callback is called for each new TLS connection detected.
type Callback func(evt ConnectionEvent)

// Detector detects new TLS connections and emits events.
// Linux uses eBPF sock_ops (not this interface).
// macOS uses BPF device capture.
// Windows will use WinDivert.
type Detector interface {
	// Start begins capturing and calls cb for each new connection.
	Start(cb Callback) error
	// Stop stops capturing.
	Stop() error
}

func synAckFilter(ports []uint16) string {
	if len(ports) == 0 {
		ports = []uint16{443}
	}
	portExprs := make([]string, 0, len(ports))
	for _, port := range ports {
		portExprs = append(portExprs, fmt.Sprintf("tcp src port %d", port))
	}
	return fmt.Sprintf("(%s) and tcp[tcpflags] & (tcp-syn|tcp-ack) = (tcp-syn|tcp-ack)", strings.Join(portExprs, " or "))
}
