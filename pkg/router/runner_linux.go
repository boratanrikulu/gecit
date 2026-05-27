//go:build linux

package router

import (
	"context"

	"github.com/boratanrikulu/gecit/pkg/rawsock"
	"github.com/florianl/go-nfqueue/v2"
	"github.com/sirupsen/logrus"
)

type socketMarker interface {
	SetMark(mark uint32) error
}

type nfqRunner struct {
	cfg       Config
	processor *Processor
	rawSock   rawsock.RawSocket
	queue     *nfqueue.Nfqueue
	logger    *logrus.Logger
}

func newNFQRunner(cfg Config, logger *logrus.Logger) (*nfqRunner, error) {
	processor, err := NewProcessor(cfg)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = logrus.New()
	}

	return &nfqRunner{
		cfg:       cfg.Normalized(),
		processor: processor,
		logger:    logger,
	}, nil
}

func (r *nfqRunner) Start(ctx context.Context) error {
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
		_ = r.rawSock.Close()
		r.rawSock = nil
		return err
	}
	r.queue = queue

	return r.queue.RegisterWithErrorFunc(ctx, r.handlePacket, r.handleError)
}

func (r *nfqRunner) Stop() error {
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

func (r *nfqRunner) openRawSocket() error {
	rs, err := rawsock.New()
	if err != nil {
		return err
	}
	if marker, ok := rs.(socketMarker); ok {
		if err := marker.SetMark(r.cfg.PacketMark); err != nil {
			_ = rs.Close()
			return err
		}
	}
	r.rawSock = rs
	return nil
}

func (r *nfqRunner) handlePacket(attr nfqueue.Attribute) int {
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

func (r *nfqRunner) handleError(err error) int {
	if err != nil {
		r.logger.WithError(err).Warn("nfqueue read error")
	}
	return 0
}

func (r *nfqRunner) accept(id uint32) {
	if err := r.queue.SetVerdict(id, nfqueue.NfAccept); err != nil {
		r.logger.WithError(err).Warn("failed to accept queued packet")
	}
}
