package app

import (
	"context"
	"time"

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

	// Comfortably inside the shorter of the two hints, so the SCM always sees
	// progress before it gives up.
	progressInterval = 5 * time.Second
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
	stopProgress := h.reportProgress(changes, svc.StartPending, startWaitHintMS)

	// A previous run that was killed rather than stopped leaves system DNS
	// pointing at a resolver that is no longer listening. Clear that before
	// taking the machine's DNS again, so a reboot recovers on its own.
	platformCleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := h.eng.Start(ctx)
	stopProgress()

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
	stopProgress = h.reportProgress(changes, svc.StopPending, stopWaitHintMS)
	err = h.eng.Stop()
	stopProgress()

	if err != nil {
		h.logger.WithError(err).Error("engine failed to stop cleanly")
		h.eventError(eventStopped, "gecit stopped with an error: "+err.Error())
		return true, 1
	}

	h.logger.Info("gecit stopped")
	h.eventInfo(eventStopped, "gecit stopped")
	return false, 0
}

// reportProgress sends the pending status and then keeps incrementing its
// checkpoint until the returned function is called. A pending state whose
// checkpoint stops moving within WaitHint is treated as hung and killed, and
// creating the TUN device and installing routes can outlast a single hint on
// a slow boot.
func (h *serviceHandler) reportProgress(changes chan<- svc.Status, state svc.State, waitHint uint32) func() {
	changes <- svc.Status{State: state, CheckPoint: 0, WaitHint: waitHint}

	done := make(chan struct{})
	stopped := make(chan struct{})

	go func() {
		defer close(stopped)
		ticker := time.NewTicker(progressInterval)
		defer ticker.Stop()

		for checkpoint := uint32(1); ; checkpoint++ {
			select {
			case <-done:
				return
			case <-ticker.C:
				changes <- svc.Status{State: state, CheckPoint: checkpoint, WaitHint: waitHint}
			}
		}
	}()

	return func() {
		close(done)
		<-stopped
	}
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
