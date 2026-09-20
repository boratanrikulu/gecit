//go:build !windows

package app

import "github.com/sirupsen/logrus"

func supervise(r *runner, logger *logrus.Logger) error {
	return runInteractive(r, logger)
}
