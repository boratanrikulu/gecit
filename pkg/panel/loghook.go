package panel

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

type logHook struct {
	ring *Ring
}

func (h *logHook) Levels() []logrus.Level { return logrus.AllLevels }

func (h *logHook) Fire(e *logrus.Entry) error {
	var fields map[string]string
	if len(e.Data) > 0 {
		fields = make(map[string]string, len(e.Data))
		for k, v := range e.Data {
			fields[k] = fmt.Sprint(v)
		}
	}

	h.ring.Append(Entry{
		Time:   e.Time,
		Level:  e.Level.String(),
		Msg:    e.Message,
		Fields: fields,
	})
	return nil
}

// Capture feeds every line the logger emits into the ring. pkg/seqtrack writes
// its seq/ack fallback warning to the logrus standard logger rather than the
// app's, and that warning is one an operator wants to see, so the standard
// logger is captured too.
func Capture(ring *Ring, logger *logrus.Logger) {
	h := &logHook{ring: ring}
	logger.AddHook(h)
	if std := logrus.StandardLogger(); std != logger {
		std.AddHook(h)
	}
}
