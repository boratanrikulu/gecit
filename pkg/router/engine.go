package router

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	ErrAlreadyRunning    = errors.New("router engine already running")
	ErrRouterUnsupported = errors.New("router nfqueue backend is only supported on Linux")
)

type lifecycleRunner interface {
	Start(context.Context) error
	Stop() error
}

type runnerFactory func(Config, *logrus.Logger) (lifecycleRunner, error)
type batchApplier func(context.Context, string) error

type idleRunner struct{}

func (idleRunner) Start(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (idleRunner) Stop() error { return nil }

func dryRunRunnerFactory(_ Config, _ *logrus.Logger) (lifecycleRunner, error) {
	return idleRunner{}, nil
}

func dryRunBatchApplier(_ context.Context, _ string) error {
	return nil
}

// Engine manages router-mode lifecycle: either the Linux NFQUEUE data path
// or a cross-platform dry-run backend that avoids touching system state.
type Engine struct {
	cfg                Config
	logger             *logrus.Logger
	newRunner          runnerFactory
	applyBatch         batchApplier
	startupGracePeriod time.Duration

	mu             sync.Mutex
	runner         lifecycleRunner
	cancel         context.CancelFunc
	doneCh         chan error
	rules          RuleSet
	rulesInstalled bool
}

// New constructs a router engine with a default logger.
func New(cfg Config) *Engine {
	return NewWithLogger(cfg, nil)
}

// NewWithLogger constructs a router engine and reuses the provided logger.
func NewWithLogger(cfg Config, logger *logrus.Logger) *Engine {
	if logger == nil {
		logger = logrus.New()
	}
	cfg = cfg.Normalized()

	eng := &Engine{
		cfg:                cfg,
		logger:             logger,
		newRunner:          defaultRunnerFactory,
		applyBatch:         defaultBatchApplier,
		startupGracePeriod: 150 * time.Millisecond,
	}
	if cfg.Backend == QueueBackendDryRun {
		eng.newRunner = dryRunRunnerFactory
		eng.applyBatch = dryRunBatchApplier
	}
	return eng
}

// Start validates config, installs nftables state, and launches the NFQUEUE worker.
func (e *Engine) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := e.cfg.Validate(); err != nil {
		return err
	}

	rules, err := BuildRuleSet(e.cfg)
	if err != nil {
		return err
	}

	e.mu.Lock()
	if e.runner != nil {
		e.mu.Unlock()
		return ErrAlreadyRunning
	}
	newRunner := e.newRunner
	applyBatch := e.applyBatch
	logger := e.logger
	grace := e.startupGracePeriod
	e.mu.Unlock()

	runner, err := newRunner(e.cfg, logger)
	if err != nil {
		return err
	}
	if err := applyBatch(ctx, rules.SetupBatch()); err != nil {
		return fmt.Errorf("install nftables rules: %w", err)
	}

	childCtx, cancel := context.WithCancel(ctx)
	doneCh := make(chan error, 1)

	e.mu.Lock()
	e.runner = runner
	e.cancel = cancel
	e.doneCh = doneCh
	e.rules = rules
	e.rulesInstalled = true
	e.mu.Unlock()

	go func() {
		doneCh <- runner.Start(childCtx)
	}()

	select {
	case err := <-doneCh:
		rollbackErr := e.rollbackStartup(runner, applyBatch, rules)
		if rollbackErr != nil {
			if err != nil {
				return fmt.Errorf("%w; rollback failed: %v", err, rollbackErr)
			}
			return rollbackErr
		}
		return err
	case <-time.After(grace):
		fields := logrus.Fields{
			"backend": e.cfg.Backend,
			"wan":     e.cfg.WANInterface,
			"table":   rules.TableName,
		}
		if e.cfg.Backend == QueueBackendNFQueue {
			fields["queue"] = e.cfg.QueueNum
			e.logger.WithFields(fields).Info("router mode active")
		} else {
			e.logger.WithFields(fields).Info("router dry run active")
		}
		return nil
	}
}

func (e *Engine) rollbackStartup(runner lifecycleRunner, applyBatch batchApplier, rules RuleSet) error {
	e.mu.Lock()
	e.runner = nil
	e.cancel = nil
	e.doneCh = nil
	e.rulesInstalled = false
	e.mu.Unlock()

	var firstErr error
	if err := runner.Stop(); err != nil {
		firstErr = err
	}
	if err := applyBatch(context.Background(), rules.TeardownBatch()); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("remove nftables rules after startup failure: %w", err)
	}
	return firstErr
}

// Stop tears down the worker and removes the nftables table that Start installed.
func (e *Engine) Stop() error {
	e.mu.Lock()
	runner := e.runner
	cancel := e.cancel
	doneCh := e.doneCh
	rules := e.rules
	rulesInstalled := e.rulesInstalled
	applyBatch := e.applyBatch
	e.runner = nil
	e.cancel = nil
	e.doneCh = nil
	e.rulesInstalled = false
	e.mu.Unlock()

	var firstErr error
	if cancel != nil {
		cancel()
	}
	if runner != nil {
		if err := runner.Stop(); err != nil {
			firstErr = err
		}
	}
	if doneCh != nil {
		if err := <-doneCh; err != nil && !errors.Is(err, context.Canceled) && firstErr == nil {
			firstErr = err
		}
	}
	if rulesInstalled {
		if err := applyBatch(context.Background(), rules.TeardownBatch()); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("remove nftables rules: %w", err)
		}
	}
	return firstErr
}

// Mode returns the router backend name.
func (e *Engine) Mode() string {
	return "router-" + string(e.cfg.Backend)
}

// Config exposes the current normalized config.
func (e *Engine) Config() Config {
	return e.cfg
}

// Validate checks whether the current router-mode config is renderable.
func (e *Engine) Validate() error {
	return e.cfg.Validate()
}

// RuleSet returns the current nftables dry-run output for this engine.
func (e *Engine) RuleSet() (RuleSet, error) {
	return BuildRuleSet(e.cfg)
}
