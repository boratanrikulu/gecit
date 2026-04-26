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
	if err := det.Start(func(evt capture.ConnectionEvent) {
		st.conns.Store(evt.SrcPort, evt)
	}); err != nil {
		_ = det.Stop()
		return nil, err
	}

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
		_ = st.detector.Stop()
	}
}

var globalSeqTracker *SeqTracker

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

	localAddr, ok := tcpConn.LocalAddr().(*net.TCPAddr)
	if !ok || localAddr.Port <= 0 || localAddr.Port > 65535 {
		return 1, 1
	}
	localPort := uint16(localAddr.Port) // #nosec G115 -- range checked above.

	evt := globalSeqTracker.WaitForSeqAck(localPort, 500*time.Millisecond)
	if evt == nil {
		logrus.WithField("port", localPort).Warn("seq/ack fallback — Npcap may not be capturing")
		return 1, 1
	}

	return evt.Seq, evt.Ack
}
