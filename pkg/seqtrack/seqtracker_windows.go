package seqtrack

import (
	"net"
	"sync"
	"time"

	"github.com/boratanrikulu/gecit/pkg/capture"
	"github.com/sirupsen/logrus"
)

type SeqTracker struct {
	detector capture.Detector
	conns    sync.Map
}

func NewSeqTracker(iface string, ports []uint16) (*SeqTracker, error) {
	det, err := capture.NewCapture(iface, ports)
	if err != nil {
		return nil, err
	}

	st := &SeqTracker{detector: det}
	det.Start(func(evt capture.ConnectionEvent) {
		st.conns.Store(evt.SrcPort, evt)
	})

	return st, nil
}

func (st *SeqTracker) WaitForSeqAck(localPort uint16, timeout time.Duration) *capture.ConnectionEvent {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if val, ok := st.conns.LoadAndDelete(localPort); ok {
			evt := val.(capture.ConnectionEvent)
			return &evt
		}
		time.Sleep(1 * time.Millisecond)
	}
	return nil
}

func (st *SeqTracker) Stop() {
	if st.detector != nil {
		st.detector.Stop()
	}
}

var globalSeqTracker *SeqTracker

func SetSeqTracker(st *SeqTracker) {
	globalSeqTracker = st
}

func GetSeqAck(conn net.Conn, defaultTTL uint8) (seq, ack uint32, fakeTTL uint8) {
	// fallback to default TTL in all non-successful cases
	if globalSeqTracker == nil {
		return 1, 1, defaultTTL
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return 1, 1, defaultTTL
	}

	localPort := uint16(tcpConn.LocalAddr().(*net.TCPAddr).Port)

	evt := globalSeqTracker.WaitForSeqAck(localPort, 500*time.Millisecond)
	if evt == nil {
		logrus.WithField("port", localPort).Warn("seq/ack fallback — Npcap may not be capturing")
		return 1, 1, defaultTTL
	}

	if evt.ServerTTL == 0 {
		return 1, 1, defaultTTL
	}
	return evt.Seq, evt.Ack, CalculateFakeTTL(evt.ServerTTL)
}
