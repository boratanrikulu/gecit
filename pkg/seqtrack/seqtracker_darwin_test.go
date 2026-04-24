package seqtrack

import (
	"net"
	"testing"

	"github.com/boratanrikulu/gecit/pkg/capture"
)

// mockConn implements net.Conn but is not *net.TCPConn.
// This is only used to exercise the type-assertion guard in GetSeqAck.
type mockConn struct{ net.Conn }

func TestGetSeqAck_NilTracker(t *testing.T) {
	old := globalSeqTracker
	defer func() { globalSeqTracker = old }()

	globalSeqTracker = nil

	seq, ack, fakeTTL := GetSeqAck(&mockConn{}, 42)
	if seq != 1 || ack != 1 || fakeTTL != 42 {
		t.Errorf("GetSeqAck(nil tracker) = (%d, %d, %d), want (1, 1, 42)", seq, ack, fakeTTL)
	}
}

func TestGetSeqAck_NonTCPConn(t *testing.T) {
	old := globalSeqTracker
	defer func() { globalSeqTracker = old }()

	globalSeqTracker = &SeqTracker{} // non-nil, but conn fails type assertion here.

	seq, ack, fakeTTL := GetSeqAck(&mockConn{}, 99)
	if seq != 1 || ack != 1 || fakeTTL != 99 {
		t.Errorf("GetSeqAck(non-TCPConn) = (%d, %d, %d), want (1, 1, 99)", seq, ack, fakeTTL)
	}
}

func TestGetSeqAck_EventFound_WithServerTTL(t *testing.T) {
	old := globalSeqTracker
	defer func() { globalSeqTracker = old }()

	// establish a loopback TCP connection first, so we have a real *net.TCPConn
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	localPort := uint16(conn.LocalAddr().(*net.TCPAddr).Port)

	// fill the tracker as if pcap had captured the SYN-ACK.
	// serverTTL=60 -> hops=4 -> CalculateFakeTTL=3
	st := &SeqTracker{}
	st.conns.Store(localPort, capture.ConnectionEvent{
		SrcPort:   localPort,
		Seq:       9999,
		Ack:       1111,
		ServerTTL: 60,
	})
	globalSeqTracker = st

	// defaultTTL=0 → auto mode: CalculateFakeTTL(serverTTL=60) = 3
	seq, ack, fakeTTL := GetSeqAck(conn, 0)

	if seq != 9999 {
		t.Errorf("seq: got %d, want 9999", seq)
	}
	if ack != 1111 {
		t.Errorf("ack: got %d, want 1111", ack)
	}
	if fakeTTL != 3 {
		t.Errorf("fakeTTL: got %d, want 3 (CalculateFakeTTL(60))", fakeTTL)
	}
}

func TestGetSeqAck_UserOverride_SkipsAutoCalc(t *testing.T) {
	old := globalSeqTracker
	defer func() { globalSeqTracker = old }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	localPort := uint16(conn.LocalAddr().(*net.TCPAddr).Port)

	st := &SeqTracker{}
	st.conns.Store(localPort, capture.ConnectionEvent{
		SrcPort:   localPort,
		Seq:       9999,
		Ack:       1111,
		ServerTTL: 60, // CalculateFakeTTL would give 3, but override wins
	})
	globalSeqTracker = st

	// non-zero defaultTTL = user override: auto-calculation must be skipped
	seq, ack, fakeTTL := GetSeqAck(conn, 64)

	if seq != 9999 {
		t.Errorf("seq: got %d, want 9999", seq)
	}
	if ack != 1111 {
		t.Errorf("ack: got %d, want 1111", ack)
	}
	if fakeTTL != 64 {
		t.Errorf("fakeTTL: got %d, want 64 (user override)", fakeTTL)
	}
}

func TestGetSeqAck_EventFound_ZeroServerTTL(t *testing.T) {
	old := globalSeqTracker
	defer func() { globalSeqTracker = old }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	localPort := uint16(conn.LocalAddr().(*net.TCPAddr).Port)

	// serverTTL=0 means unknown. GetSeqAck must fall back to defaults.
	st := &SeqTracker{}
	st.conns.Store(localPort, capture.ConnectionEvent{
		SrcPort:   localPort,
		Seq:       9999,
		Ack:       1111,
		ServerTTL: 0,
	})
	globalSeqTracker = st

	seq, ack, fakeTTL := GetSeqAck(conn, 55)

	if seq != 1 || ack != 1 || fakeTTL != 55 {
		t.Errorf("GetSeqAck(ServerTTL=0) = (%d, %d, %d), want (1, 1, 55)", seq, ack, fakeTTL)
	}
}

func TestGetSeqAck_NoEvent_FallsBack(t *testing.T) {
	old := globalSeqTracker
	defer func() { globalSeqTracker = old }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// İf the tracker exists but has no event for this port, WaitForSeqAck times out.
	// we shorten the wait by not pre-populating the map,
	// but the 500 ms timeout in GetSeqAck will still fire. that's why this test is slow.
	// if this becomes a problem, extract the timeout as a parameter.
	globalSeqTracker = &SeqTracker{}

	seq, ack, fakeTTL := GetSeqAck(conn, 77)

	if seq != 1 || ack != 1 || fakeTTL != 77 {
		t.Errorf("GetSeqAck(no event) = (%d, %d, %d), want (1, 1, 77)", seq, ack, fakeTTL)
	}
}
