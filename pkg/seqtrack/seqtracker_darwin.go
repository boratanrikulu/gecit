package seqtrack

import (
	"net"
	"sync"
	"time"

	"github.com/boratanrikulu/gecit/pkg/capture"
	"github.com/sirupsen/logrus"
)

// SeqTracker uses pcap to capture SYN-ACKs from our proxy's outgoing
// connections and extract real TCP seq/ack numbers.
type SeqTracker struct {
	detector capture.Detector
	conns    sync.Map // map[uint16]capture.ConnectionEvent keyed by local port
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

// GetSeqAck returns the real TCP seq/ack for a connection by waiting for
// pcap to capture the SYN-ACK.
func GetSeqAck(conn net.Conn) (seq, ack uint32) {
	if globalSeqTracker == nil {
		return 1, 1
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return 1, 1
	}

	localPort := uint16(tcpConn.LocalAddr().(*net.TCPAddr).Port)

	// Wait for pcap to capture our SYN-ACK. Returns immediately when found
	// (typically <10ms after Dial). 500ms is a safe upper bound.
	evt := globalSeqTracker.WaitForSeqAck(localPort, 500*time.Millisecond)
	if evt == nil {
		logrus.WithField("port", localPort).Warn("seq/ack capture unavailable — fake may be rejected by DPI")
		return 1, 1
	}

	return evt.Seq, evt.Ack
}
