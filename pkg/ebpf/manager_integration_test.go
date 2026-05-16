//go:build integration

package ebpf

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestManagerStartStop(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(&bytes.Buffer{})

	mgr := NewManager(Config{
		Ports:   []uint16{443},
		FakeTTL: 8,
		MSS:     88,
	}, logger)

	ctx := context.Background()
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestManagerPerfEvent(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.DebugLevel)

	mgr := NewManager(Config{
		Ports:   []uint16{443},
		FakeTTL: 8,
		MSS:     88,
	}, logger)

	ctx := context.Background()
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.Stop()

	// TCP connect to trigger eBPF sock_ops event.
	conn, err := net.DialTimeout("tcp", "google.com:443", 5*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	// Wait for perf event processing + fake injection.
	time.Sleep(500 * time.Millisecond)
	conn.Close()

	logs := buf.String()
	if !strings.Contains(logs, "fake ClientHello injected") {
		t.Fatalf("expected fake injection log entry, got:\n%s", logs)
	}
}

func TestManagerMultipleConnections(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)

	mgr := NewManager(Config{
		Ports:   []uint16{443},
		FakeTTL: 8,
		MSS:     88,
	}, logger)

	ctx := context.Background()
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.Stop()

	// Multiple connections should each trigger a perf event.
	for i := 0; i < 3; i++ {
		conn, err := net.DialTimeout("tcp", "google.com:443", 5*time.Second)
		if err != nil {
			t.Fatalf("Dial %d: %v", i, err)
		}
		conn.Close()
	}

	time.Sleep(time.Second)

	logs := buf.String()
	count := strings.Count(logs, "fake ClientHello injected")
	if count < 3 {
		t.Fatalf("expected at least 3 fake injections, got %d:\n%s", count, logs)
	}
}
