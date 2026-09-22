package panel

import (
	"sync"
	"time"
)

// Entry is one captured log line.
type Entry struct {
	Seq    uint64            `json:"seq"`
	Time   time.Time         `json:"time"`
	Level  string            `json:"level"`
	Msg    string            `json:"msg"`
	Fields map[string]string `json:"fields,omitempty"`
}

// Ring holds the last N log entries in memory and nothing on disk. The entries
// carry the domains a machine resolved and connected to, which is the most
// sensitive thing gecit ever handles, so they live for the process lifetime and
// no longer.
type Ring struct {
	mu  sync.Mutex
	buf []Entry
	// n counts every entry ever appended, so it is also the sequence number
	// the next one gets. Clients poll with the last sequence they saw.
	n uint64
}

func NewRing(capacity int) *Ring {
	if capacity < 1 {
		capacity = 1
	}
	return &Ring{buf: make([]Entry, capacity)}
}

func (r *Ring) Append(e Entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e.Seq = r.n
	r.buf[r.n%uint64(len(r.buf))] = e
	r.n++
}

// Since returns every entry from seq onwards that has not been overwritten,
// along with the sequence to ask for next time. A caller that fell behind gets
// the oldest entry still held rather than a gap it cannot detect.
//
// Both come from one locked read on purpose. Taking the sequence separately
// lets an entry land in between, and the caller then asks for it again and
// renders it twice.
func (r *Ring) Since(seq uint64) ([]Entry, uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	size := uint64(len(r.buf))
	oldest := uint64(0)
	if r.n > size {
		oldest = r.n - size
	}
	if seq < oldest {
		seq = oldest
	}
	if seq >= r.n {
		return nil, r.n
	}

	out := make([]Entry, 0, r.n-seq)
	for i := seq; i < r.n; i++ {
		out = append(out, r.buf[i%size])
	}
	return out, r.n
}

// Latest is the sequence the next entry will get.
func (r *Ring) Latest() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

// Activity returns up to limit entries carrying an event field, newest first.
// That field is set at the injection and resolution call sites, so the feed
// does not have to match on message text.
func (r *Ring) Activity(limit int) []Entry {
	if limit < 1 {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	size := uint64(len(r.buf))
	oldest := uint64(0)
	if r.n > size {
		oldest = r.n - size
	}

	out := make([]Entry, 0, limit)
	for i := r.n; i > oldest && len(out) < limit; i-- {
		e := r.buf[(i-1)%size]
		if e.Fields["event"] != "" {
			out = append(out, e)
		}
	}
	return out
}
