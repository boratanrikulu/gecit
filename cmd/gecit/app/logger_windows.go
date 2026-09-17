package app

import (
	"path/filepath"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc/eventlog"
	"gopkg.in/natefinch/lumberjack.v2"
)

func logFilePath() string { return filepath.Join(gecitDataDir(), "gecit.log") }

// A service has no console, so stderr goes nowhere. ProgramData is somewhere
// an operator can find without being told.
func setLogOutput(logger *logrus.Logger) {
	if !underServiceManager() {
		return
	}
	// Same directory the config lives in, so it needs the same ACL. A log
	// nobody can read is better than a service a standard user can steer.
	if err := createDataDir(gecitDataDir()); err != nil {
		logger.WithError(err).Warn("could not secure the gecit data directory")
	}

	logger.SetFormatter(&logrus.TextFormatter{FullTimestamp: true, DisableColors: true})
	logger.SetOutput(&lumberjack.Logger{
		Filename:   logFilePath(),
		MaxSize:    10,
		MaxBackups: 3,
	})
}

// openEventLog returns a handle to the Application event log, registering the
// source first in case the service was installed by something that did not.
// A nil result is not fatal: lifecycle events then live in the log file only.
func openEventLog() *eventlog.Log {
	// Registration fails when the key already exists, which is the common case.
	_ = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)

	elog, err := eventlog.Open(serviceName)
	if err != nil {
		return nil
	}
	return elog
}
