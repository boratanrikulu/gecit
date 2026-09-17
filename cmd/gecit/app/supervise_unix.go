//go:build !windows

package app

import (
	"github.com/boratanrikulu/gecit/pkg/engine"
	"github.com/sirupsen/logrus"
)

func supervise(eng engine.Engine, logger *logrus.Logger) error {
	return runInteractive(eng, logger)
}
