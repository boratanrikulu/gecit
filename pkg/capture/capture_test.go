package capture

import "testing"

func TestSynAckFilterUsesConfiguredPorts(t *testing.T) {
	got := synAckFilter([]uint16{443, 8443})
	want := "(tcp src port 443 or tcp src port 8443) and tcp[tcpflags] & (tcp-syn|tcp-ack) = (tcp-syn|tcp-ack)"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSynAckFilterDefaultsTo443(t *testing.T) {
	got := synAckFilter(nil)
	want := "(tcp src port 443) and tcp[tcpflags] & (tcp-syn|tcp-ack) = (tcp-syn|tcp-ack)"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
