package panel

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"

	"github.com/boratanrikulu/gecit/pkg/engine"
)

const activityLimit = 100

type stateResponse struct {
	Status   Status       `json:"status"`
	Stats    engine.Stats `json:"stats"`
	Platform []Fact       `json:"platform"`
	LogLevel string       `json:"log_level"`
	Activity []Entry      `json:"activity"`
	Config   ConfigView   `json:"config"`
}

type logsResponse struct {
	Latest  uint64  `json:"latest"`
	Entries []Entry `json:"entries"`
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, stateResponse{
		Status:   s.opts.Ctrl.Status(),
		Stats:    s.opts.Ctrl.Stats(),
		Platform: s.opts.Ctrl.Platform(),
		LogLevel: s.opts.Ctrl.LogLevel(),
		Activity: s.opts.Ring.Activity(activityLimit),
		Config:   s.opts.Ctrl.Config(),
	})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	var since uint64
	if raw := r.URL.Query().Get("since"); raw != "" {
		n, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "since must be a number")
			return
		}
		since = n
	}

	entries, latest := s.opts.Ring.Since(since)
	writeJSON(w, http.StatusOK, logsResponse{Latest: latest, Entries: entries})
}

func (s *Server) handleConfigGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.opts.Ctrl.Config())
}

func (s *Server) handleConfigPut(w http.ResponseWriter, r *http.Request) {
	// Decoding onto the current values rather than a zero struct: a body that
	// omits a key means "leave it alone", not "set it to zero". Written into an
	// empty Config, a request naming only fake_ttl would turn the panel off and
	// blank the cgroup path on the way past.
	//
	// Ports is copied first. encoding/json writes into a slice that is long
	// enough rather than allocating, so without this the decode reaches through
	// into whatever the controller handed back.
	cfg := s.opts.Ctrl.Config().Values
	cfg.Ports = slices.Clone(cfg.Ports)

	if err := decodeJSON(w, r, &cfg); err != nil {
		return
	}
	if err := s.opts.Ctrl.SaveConfig(cfg); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.opts.Ctrl.Config())
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	if err := s.opts.Ctrl.Apply(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.opts.Ctrl.Status())
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	if err := s.opts.Ctrl.Start(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.opts.Ctrl.Status())
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	if err := s.opts.Ctrl.Stop(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.opts.Ctrl.Status())
}

func (s *Server) handleLogLevel(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Level string `json:"level"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		return
	}
	if err := s.opts.Ctrl.SetLogLevel(body.Level); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"log_level": s.opts.Ctrl.LogLevel()})
}

// decodeJSON reports its own error to the client and returns it so the caller
// can stop. The body is capped because it arrives before any authorisation
// decision has been acted on.
func decodeJSON(w http.ResponseWriter, r *http.Request, into any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request body: "+err.Error())
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
