//go:build darwin || windows

package seqtrack

import (
	"net"
	"sync"
	"testing"
)

// The panel can stop and start the engine, and both call SetSeqTracker while
// connection goroutines are in GetSeqAck.
func TestSetSeqTrackerIsRaceFree(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 2000; j++ {
				// A pipe is not a *net.TCPConn, so this returns the
				// placeholder without waiting on a capture.
				if seq, ack := GetSeqAck(client); seq != 1 || ack != 1 {
					t.Errorf("got seq %d ack %d, want the 1/1 placeholder", seq, ack)
					return
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			SetSeqTracker(&SeqTracker{})
			SetSeqTracker(nil)
		}
	}()

	wg.Wait()
}
