//go:build !windows

package app

import "github.com/sirupsen/logrus"

// logrus already writes to stderr, which is where an operator looking at a
// foreground process expects it.
func setLogOutput(*logrus.Logger) {}
