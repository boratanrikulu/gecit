package seqtrack

import (
	"fmt"
	"net"
)

type SeqTracker struct{}

func NewSeqTracker(_ string, _ []uint16) (*SeqTracker, error) {
	return nil, fmt.Errorf("not used on Linux (eBPF provides seq/ack)")
}

func SetSeqTracker(_ *SeqTracker) {}

func GetSeqAck(_ net.Conn, _ uint8) (seq, ack uint32, fakeTTL uint8) { return 1, 1, 1 }

func (st *SeqTracker) Stop() {}
