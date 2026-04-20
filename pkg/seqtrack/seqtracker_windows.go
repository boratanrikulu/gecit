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
var fallbackWarnOnce sync.Once

func SetSeqTracker(st *SeqTracker) {
	globalSeqTracker = st
}

func GetSeqAck(conn net.Conn) (seq, ack uint32) {
	if globalSeqTracker == nil {
		return 1, 1
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return 1, 1
	}

	localPort := uint16(tcpConn.LocalAddr().(*net.TCPAddr).Port)

	evt := globalSeqTracker.WaitForSeqAck(localPort, 500*time.Millisecond)
	if evt == nil {
		fallbackWarnOnce.Do(func() {
			logrus.Warn("seq/ack fallback active — Windows capture path missed SYN/ACK, using default sequence numbers")
		})
		logrus.WithField("port", localPort).Debug("seq/ack fallback used for this flow")
		return 1, 1
	}

	return evt.Seq, evt.Ack
}
