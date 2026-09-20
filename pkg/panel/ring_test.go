package panel

import (
	"io"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
)

func appendMsgs(r *Ring, msgs ...string) {
	for _, m := range msgs {
		r.Append(Entry{Msg: m})
	}
}

// Capture hooks the shared standard logger, so a test that calls it has to put
// that logger back or it keeps feeding a dead ring for the rest of the run.
func restoreStandardHooks(t *testing.T) {
	t.Helper()
	std := logrus.StandardLogger()
	hooks := std.ReplaceHooks(make(logrus.LevelHooks))
	t.Cleanup(func() { std.ReplaceHooks(hooks) })
}

func since(r *Ring, seq uint64) []Entry {
	entries, _ := r.Since(seq)
	return entries
}

func msgs(entries []Entry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Msg
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestSinceReturnsOnlyNewEntries(t *testing.T) {
	r := NewRing(10)
	appendMsgs(r, "a", "b", "c")

	if got := msgs(since(r, 0)); !equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("Since(0) = %v, want [a b c]", got)
	}
	if got := msgs(since(r, 2)); !equal(got, []string{"c"}) {
		t.Fatalf("Since(2) = %v, want [c]", got)
	}
	if got := since(r, r.Latest()); got != nil {
		t.Fatalf("Since(Latest()) = %v, want nil", got)
	}
	if got := since(r, 999); got != nil {
		t.Fatalf("Since past the end = %v, want nil", got)
	}

	// The sequence has to come from the same locked read as the entries, or a
	// line landing in between is handed out twice.
	entries, latest := r.Since(0)
	if latest != uint64(len(entries)) {
		t.Errorf("Since returned %d entries but latest %d", len(entries), latest)
	}
}

// Sequence numbers keep counting past the buffer size, so a client that polls
// with the sequence it last saw must not be handed entries it already has.
func TestSequenceSurvivesWrapAround(t *testing.T) {
	r := NewRing(3)
	appendMsgs(r, "a", "b", "c", "d", "e")

	if got := r.Latest(); got != 5 {
		t.Fatalf("Latest() = %d, want 5", got)
	}
	if got := msgs(since(r, 0)); !equal(got, []string{"c", "d", "e"}) {
		t.Fatalf("Since(0) after wrap = %v, want the last three", got)
	}
	if got := msgs(since(r, 4)); !equal(got, []string{"e"}) {
		t.Fatalf("Since(4) = %v, want [e]", got)
	}

	for _, e := range since(r, 0) {
		if e.Seq < 2 {
			t.Errorf("entry %q kept sequence %d after being overwritten", e.Msg, e.Seq)
		}
	}
}

// A client that fell behind further than the buffer holds gets the oldest
// entry still in memory. Returning nothing would look like "no new logs".
func TestSinceClampsToOldestHeld(t *testing.T) {
	r := NewRing(2)
	appendMsgs(r, "a", "b", "c", "d")

	if got := msgs(since(r, 0)); !equal(got, []string{"c", "d"}) {
		t.Fatalf("Since(0) = %v, want [c d]", got)
	}
}

func TestActivityFiltersOnEventField(t *testing.T) {
	r := NewRing(10)
	r.Append(Entry{Msg: "loading BPF sock_ops program"})
	r.Append(Entry{Msg: "resolved", Fields: map[string]string{"event": "dns", "domain": "example.com"}})
	r.Append(Entry{Msg: "noise"})
	r.Append(Entry{Msg: "injected", Fields: map[string]string{"event": "inject", "dst": "example.com:443"}})

	got := msgs(r.Activity(10))
	if !equal(got, []string{"injected", "resolved"}) {
		t.Fatalf("Activity = %v, want newest first [injected resolved]", got)
	}

	if got := r.Activity(1); len(got) != 1 || got[0].Msg != "injected" {
		t.Fatalf("Activity(1) = %v, want just the newest", msgs(got))
	}
}

func TestActivitySkipsOverwrittenEntries(t *testing.T) {
	r := NewRing(2)
	r.Append(Entry{Msg: "old", Fields: map[string]string{"event": "inject"}})
	appendMsgs(r, "a", "b")

	if got := r.Activity(10); len(got) != 0 {
		t.Fatalf("Activity = %v, want nothing after the event was overwritten", msgs(got))
	}
}

func TestNewRingRejectsEmptyCapacity(t *testing.T) {
	r := NewRing(0)
	r.Append(Entry{Msg: "a"})
	if got := msgs(since(r, 0)); !equal(got, []string{"a"}) {
		t.Fatalf("Since(0) = %v, want [a]", got)
	}
}

// The hook fires on logging goroutines while the panel's HTTP handler reads,
// so both sides have to hold up under -race.
func TestRingConcurrentAppendAndRead(t *testing.T) {
	r := NewRing(64)

	stop := make(chan struct{})
	var reader sync.WaitGroup
	reader.Add(1)
	go func() {
		defer reader.Done()
		for {
			select {
			case <-stop:
				return
			default:
				since(r, 0)
				r.Activity(10)
				r.Latest()
			}
		}
	}()

	var writers sync.WaitGroup
	for i := 0; i < 10; i++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for j := 0; j < 100; j++ {
				r.Append(Entry{Msg: "line", Fields: map[string]string{"event": "inject"}})
			}
		}()
	}
	writers.Wait()
	close(stop)
	reader.Wait()

	if got := r.Latest(); got != 1000 {
		t.Fatalf("Latest() = %d, want 1000", got)
	}
}

func TestCaptureRecordsLevelMessageAndFields(t *testing.T) {
	r := NewRing(10)
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	restoreStandardHooks(t)
	Capture(r, logger)

	logger.WithFields(logrus.Fields{"event": "inject", "ttl": 8}).Info("fake ClientHello injected")

	entries := since(r, 0)
	if len(entries) != 1 {
		t.Fatalf("captured %d entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Level != "info" || e.Msg != "fake ClientHello injected" {
		t.Errorf("got level %q msg %q", e.Level, e.Msg)
	}
	if e.Fields["event"] != "inject" || e.Fields["ttl"] != "8" {
		t.Errorf("fields = %v, want event=inject ttl=8", e.Fields)
	}
	if e.Time.IsZero() {
		t.Error("entry has no timestamp")
	}
}

// Below the logger's level logrus never fires hooks, which is why the panel
// offers a level toggle instead of trying to capture more than the logger emits.
func TestCaptureFollowsLoggerLevel(t *testing.T) {
	r := NewRing(10)
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	restoreStandardHooks(t)
	Capture(r, logger)

	logger.Debug("invisible")
	if got := r.Latest(); got != 0 {
		t.Fatalf("captured %d entries at Info level, want 0", got)
	}

	logger.SetLevel(logrus.DebugLevel)
	logger.Debug("visible")
	if got := r.Latest(); got != 1 {
		t.Fatalf("captured %d entries at Debug level, want 1", got)
	}
}

// pkg/seqtrack writes its seq/ack fallback warning to the logrus standard
// logger rather than the app's, and that warning is one an operator wants in
// the panel.
func TestCaptureAlsoTakesTheStandardLogger(t *testing.T) {
	r := NewRing(10)
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	restoreStandardHooks(t)
	std := logrus.StandardLogger()
	stdOut := std.Out
	std.SetOutput(io.Discard)
	t.Cleanup(func() { std.SetOutput(stdOut) })

	Capture(r, logger)
	logrus.WithField("port", 54321).Warn("seq/ack fallback to placeholder")

	entries := since(r, 0)
	if len(entries) != 1 || entries[0].Fields["port"] != "54321" {
		t.Fatalf("the standard logger's warning did not reach the ring: %+v", entries)
	}
}
