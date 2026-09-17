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

// A pending state whose checkpoint stops moving within its wait hint is taken
// for hung. Creating the TUN device and installing routes takes seconds, and
// tearing them down again while restoring DNS takes longer than it looks.
const (
	startWaitHintMS = 30000
	stopWaitHintMS  = 45000
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
	changes <- svc.Status{State: svc.StartPending, CheckPoint: 0, WaitHint: startWaitHintMS}

	// A previous run that was killed rather than stopped leaves system DNS
	// pointing at a resolver that is no longer listening. Clear that before
	// taking the machine's DNS again, so a reboot recovers on its own.
	platformCleanup()

	// Cleanup is done, which is real progress, and it buys the engine a fresh
	// wait hint for the slower half. Checkpoints only ever move after a step
	// has actually finished: a timer that reports progress the work is not
	// making would leave a hung start looking healthy forever.
	changes <- svc.Status{State: svc.StartPending, CheckPoint: 1, WaitHint: startWaitHintMS}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := h.eng.Start(ctx)

	if err != nil {
		h.logger.WithError(err).Error("engine failed to start")
		h.eventError(eventStartFailed, "gecit failed to start: "+err.Error())
		// Reported as a service-specific exit code so this reads as a
		// failure rather than a clean stop. The SCM only turns that into a
		// restart because install sets the non-crash failure flag.
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
	changes <- svc.Status{State: svc.StopPending, CheckPoint: 0, WaitHint: stopWaitHintMS}
	err = h.eng.Stop()

	if err != nil {
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
