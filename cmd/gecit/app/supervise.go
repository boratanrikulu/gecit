package app

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
)

func runInteractive(r *runner, logger *logrus.Logger) error {
	if err := r.Start(); err != nil {
		return err
	}

	logger.WithField("mode", r.Mode()).Info("gecit is running, press Ctrl+C to stop")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Info("shutting down...")
	return r.Stop()
}
