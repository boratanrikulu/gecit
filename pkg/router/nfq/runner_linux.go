//go:build linux

package nfq

import (
	"context"

	"github.com/boratanrikulu/gecit/pkg/rawsock"
	"github.com/boratanrikulu/gecit/pkg/router"
	"github.com/florianl/go-nfqueue/v2"
	"github.com/sirupsen/logrus"
)

type socketMarker interface {
	SetMark(mark uint32) error
}

// Runner consumes packets from an NFQUEUE and asks a router processor whether to inject.
type Runner struct {
	cfg       router.Config
	processor *router.Processor
	rawSock   rawsock.RawSocket
	queue     *nfqueue.Nfqueue
	logger    *logrus.Logger
}

// NewRunner creates the experimental Linux NFQUEUE data-plane worker.
func NewRunner(cfg router.Config, logger *logrus.Logger) (*Runner, error) {
	processor, err := router.NewProcessor(cfg)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = logrus.New()
	}

	return &Runner{
		cfg:       cfg.Normalized(),
		processor: processor,
		logger:    logger,
	}, nil
}

// Start opens NFQUEUE and processes packets until the context is canceled.
func (r *Runner) Start(ctx context.Context) error {
	if err := r.openRawSocket(); err != nil {
		return err
	}

	queue, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      r.cfg.QueueNum,
		MaxQueueLen:  uint32(r.cfg.MaxFlows),
		MaxPacketLen: 0xffff,
		Copymode:     nfqueue.NfQnlCopyPacket,
		Flags:        nfqueue.NfQaCfgFlagFailOpen,
	})
	if err != nil {
		r.rawSock.Close()
		r.rawSock = nil
		return err
	}
	r.queue = queue

	return r.queue.RegisterWithErrorFunc(ctx, r.handlePacket, r.handleError)
}

// Stop closes the queue and the raw socket. Both resources are always
// closed even if one of them returns an error.
func (r *Runner) Stop() error {
	var firstErr error
	if r.queue != nil {
		if err := r.queue.Close(); err != nil {
			firstErr = err
		}
		r.queue = nil
	}
	if r.rawSock != nil {
		if err := r.rawSock.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		r.rawSock = nil
	}
	return firstErr
}

func (r *Runner) openRawSocket() error {
	rs, err := rawsock.New()
	if err != nil {
		return err
	}
	if marker, ok := rs.(socketMarker); ok {
		if err := marker.SetMark(r.cfg.PacketMark); err != nil {
			rs.Close()
			return err
		}
	}
	r.rawSock = rs
	return nil
}

func (r *Runner) handlePacket(attr nfqueue.Attribute) int {
	if attr.PacketID == nil {
		return 0
	}
	if attr.Payload == nil {
		r.accept(*attr.PacketID)
		return 0
	}

	var mark uint32
	if attr.Mark != nil {
		mark = *attr.Mark
	}

	action, err := r.processor.ProcessPacket(*attr.Payload, mark)
	if err != nil {
		r.logger.WithError(err).Debug("router processor could not parse queued packet")
	}
	if action.Inject {
		if err := r.rawSock.SendFake(action.Conn, action.FakePayload, r.cfg.FakeTTL); err != nil {
			r.logger.WithError(err).Warn("router mode fake injection failed")
		} else {
			r.logger.WithFields(logrus.Fields{
				"dst":    action.Conn.DstIP.String(),
				"port":   action.Conn.DstPort,
				"reason": action.Reason,
			}).Debug("router mode injected fake clienthello")
		}
	}

	r.accept(*attr.PacketID)
	return 0
}

func (r *Runner) handleError(err error) int {
	if err != nil {
		r.logger.WithError(err).Warn("nfqueue read error")
	}
	return 0
}

func (r *Runner) accept(id uint32) {
	if err := r.queue.SetVerdict(id, nfqueue.NfAccept); err != nil {
		r.logger.WithError(err).Warn("failed to accept queued packet")
	}
}
