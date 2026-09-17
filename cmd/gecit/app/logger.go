package app

import "github.com/sirupsen/logrus"

func newLogger(verbose bool) *logrus.Logger {
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	if verbose {
		logger.SetLevel(logrus.DebugLevel)
	}
	setLogOutput(logger)
	return logger
}
