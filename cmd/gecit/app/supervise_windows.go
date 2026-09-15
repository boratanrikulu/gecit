package app

import (
	"context"

	"github.com/boratanrikulu/gecit/pkg/engine"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

// Event log ids. They only have to be stable and distinct.
const (
	eventStarted     = 1
	eventStopped     = 2
	eventStartFailed = 3
)

// Starting the TUN device and installing routes takes a few seconds, and the
// SCM kills a service that goes quiet for too long while pending.
const (
	startWaitHintMS = 30000
	stopWaitHintMS  = 20000
)

func supervise(eng engine.Engine, logger *logrus.Logger) error {
	if !underServiceManager() {
		return runInteractive(eng, logger)
	}
	return svc.Run(serviceName, &serviceHandler{
		eng:    eng,
		logger: logger,
		elog:   openEventLog(),
	})
}

type serviceHandler struct {
	eng    engine.Engine
	logger *logrus.Logger
	elog   *eventlog.Log
}

func (h *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending, WaitHint: startWaitHintMS}

	// A previous run that was killed rather than stopped leaves system DNS
	// pointing at a resolver that is no longer listening. Clear that before
	// taking the machine's DNS again, so a reboot recovers on its own.
	platformCleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := h.eng.Start(ctx); err != nil {
		h.logger.WithError(err).Error("engine failed to start")
		h.eventError(eventStartFailed, "gecit failed to start: "+err.Error())
		// A service-specific exit code is what makes the SCM run the
		// configured recovery actions instead of recording a clean stop.
		return true, 1
	}

	// Report Running only once the engine is actually up, so the SCM and
	// anyone reading `sc query` see the truth.
	changes <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPreShutdown,
	}
	h.logger.WithField("mode", h.eng.Mode()).Info("gecit is running as a service")
	h.eventInfo(eventStarted, "gecit started in "+h.eng.Mode()+" mode")

loop:
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown, svc.PreShutdown:
			break loop
		default:
			h.logger.WithField("cmd", c.Cmd).Debug("unexpected service control request")
		}
	}

	// AcceptPreShutdown buys roughly 180 seconds at OS shutdown instead of the
	// few seconds AcceptShutdown alone would give, which is what restoring DNS
	// and tearing down routes needs.
	changes <- svc.Status{State: svc.StopPending, WaitHint: stopWaitHintMS}

	if err := h.eng.Stop(); err != nil {
		h.logger.WithError(err).Error("engine failed to stop cleanly")
		h.eventError(eventStopped, "gecit stopped with an error: "+err.Error())
		return true, 1
	}

	h.logger.Info("gecit stopped")
	h.eventInfo(eventStopped, "gecit stopped")
	return false, 0
}

func (h *serviceHandler) eventInfo(id uint32, msg string) {
	if h.elog != nil {
		h.elog.Info(id, msg)
	}
}

func (h *serviceHandler) eventError(id uint32, msg string) {
	if h.elog != nil {
		h.elog.Error(id, msg)
	}
}
