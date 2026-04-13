package router

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

type fakeLifecycleRunner struct {
	start func(context.Context) error
	stop  func() error
}

func (f *fakeLifecycleRunner) Start(ctx context.Context) error {
	return f.start(ctx)
}

func (f *fakeLifecycleRunner) Stop() error {
	if f.stop != nil {
		return f.stop()
	}
	return nil
}

func TestEngineStartStopAppliesRulesAndRunsWorker(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WANInterface = "wan"

	eng := New(cfg)
	eng.startupGracePeriod = 5 * time.Millisecond

	var mu sync.Mutex
	var applied []string
	stopped := 0
	eng.applyBatch = func(ctx context.Context, batch string) error {
		mu.Lock()
		applied = append(applied, batch)
		mu.Unlock()
		return nil
	}
	eng.newRunner = func(cfg Config, _ *logrus.Logger) (lifecycleRunner, error) {
		return &fakeLifecycleRunner{
			start: func(ctx context.Context) error {
				<-ctx.Done()
				return ctx.Err()
			},
			stop: func() error {
				stopped++
				return nil
			},
		}, nil
	}

	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := eng.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(applied) != 2 {
		t.Fatalf("expected setup+teardown batches, got %d", len(applied))
	}
	if !strings.Contains(applied[0], "add table inet gecit_router") {
		t.Fatalf("setup batch missing add table: %s", applied[0])
	}
	if !strings.Contains(applied[1], "delete table inet gecit_router") {
		t.Fatalf("teardown batch missing delete table: %s", applied[1])
	}
	if stopped == 0 {
		t.Fatal("expected runner.Stop to be called")
	}
}

func TestEngineStartRollsBackOnImmediateRunnerFailure(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WANInterface = "wan"

	eng := New(cfg)
	eng.startupGracePeriod = 5 * time.Millisecond

	var mu sync.Mutex
	var applied []string
	eng.applyBatch = func(ctx context.Context, batch string) error {
		mu.Lock()
		applied = append(applied, batch)
		mu.Unlock()
		return nil
	}
	eng.newRunner = func(cfg Config, _ *logrus.Logger) (lifecycleRunner, error) {
		return &fakeLifecycleRunner{
			start: func(ctx context.Context) error {
				return errors.New("boom")
			},
		}, nil
	}

	err := eng.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected startup failure, got %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(applied) != 2 {
		t.Fatalf("expected setup+rollback batches, got %d", len(applied))
	}
	if !strings.Contains(applied[1], "delete table inet gecit_router") {
		t.Fatalf("rollback batch missing delete table: %s", applied[1])
	}
}

func TestEngineDryRunBackendStartsWithoutSystemHooks(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WANInterface = "wan"
	cfg.Backend = QueueBackendDryRun

	eng := New(cfg)
	eng.startupGracePeriod = 5 * time.Millisecond

	if got := eng.Mode(); got != "router-dryrun" {
		t.Fatalf("Mode() = %q, want router-dryrun", got)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := eng.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}
