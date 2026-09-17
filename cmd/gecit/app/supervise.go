package app

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/boratanrikulu/gecit/pkg/engine"
	"github.com/sirupsen/logrus"
)

func runInteractive(eng engine.Engine, logger *logrus.Logger) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := eng.Start(ctx); err != nil {
		return err
	}

	logger.WithField("mode", eng.Mode()).Info("gecit is running, press Ctrl+C to stop")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Info("shutting down...")
	return eng.Stop()
}
