package panel

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/boratanrikulu/gecit/pkg/engine"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/netutil"
)

// PanelHost is the name the panel is opened under. Anything below .localhost is
// reserved by RFC 6761 and mapped to loopback by the browser itself, so it needs
// no DNS record, no resolver of gecit's and nothing to clean up. It resolves the
// same with --doh=false, and in a browser that does its own DoH.
const PanelHost = "gecit.localhost"

// Fact is one capability line, the same set `gecit status` prints.
type Fact struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Status struct {
	Running   bool      `json:"running"`
	Mode      string    `json:"mode"`
	StartedAt time.Time `json:"started_at,omitempty"`
	LastError string    `json:"last_error,omitempty"`
}

// ConfigView is the config file as the panel presents it: the values in effect,
// where they are written, and which of them a command-line flag is currently
// overriding. Without that last part an operator edits a value, applies, and
// nothing changes because a flag outranks the file.
type ConfigView struct {
	Path   string        `json:"path"`
	Values engine.Config `json:"values"`
	// OverriddenByFlag maps a config key to the flag currently outranking it,
	// so the panel can name the flag to drop rather than say one exists.
	OverriddenByFlag map[string]string `json:"overridden_by_flag"`
	// DoHPresets are the upstream names accepted in place of a URL. They come
	// from the resolver rather than being repeated in the page, so the two
	// cannot drift.
	DoHPresets []string `json:"doh_presets"`
}

// Controller is what the panel drives. cmd/gecit/app's runner implements it, so
// every decision that needs to know about gecit stays there and this package
// stays an HTTP layer.
type Controller interface {
	Status() Status
	Stats() engine.Stats
	Platform() []Fact

	Start() error
	Stop() error

	Config() ConfigView
	SaveConfig(engine.Config) error
	Apply() error

	LogLevel() string
	SetLogLevel(string) error
}

type Options struct {
	Addr   string
	Token  string
	Ctrl   Controller
	Ring   *Ring
	Logger *logrus.Logger
}

// No WriteTimeout: POST /api/apply legitimately takes as long as an engine
// restart, and a deadline there would cut the reply the operator is waiting on.
const maxPanelConns = 32

type Server struct {
	opts Options
	srv  *http.Server
	ln   net.Listener
}

func New(opts Options) (*Server, error) {
	if err := ValidateAddr(opts.Addr); err != nil {
		return nil, err
	}
	if opts.Token == "" {
		return nil, errors.New("panel needs a token")
	}
	if opts.Ctrl == nil || opts.Ring == nil || opts.Logger == nil {
		return nil, errors.New("panel needs a controller, a ring and a logger")
	}
	return &Server{opts: opts}, nil
}

// Start binds before returning so a port already in use is the caller's error
// to report, not a warning that scrolls past in a goroutine.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.opts.Addr, err)
	}
	// One browser tab is the whole client. The cap is what stops a local
	// process that has no token from holding sockets open until the root
	// process runs out of descriptors and the engine starts failing. It does
	// not stop that process taking all 32 slots and keeping the operator out:
	// everything here is loopback, so there is nothing to tell the two apart.
	s.ln = netutil.LimitListener(ln, maxPanelConns)
	s.srv = &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		if err := s.srv.Serve(s.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.opts.Logger.WithError(err).Error("panel stopped serving")
		}
	}()
	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}

func (s *Server) Addr() string {
	if s.ln != nil {
		return s.ln.Addr().String()
	}
	return s.opts.Addr
}

func (s *Server) URL() string { return URL(s.Addr(), s.opts.Token) }

// ValidateAddr refuses anything but a loopback bind. Reaching the panel means
// rewriting the config of a process running as root and restarting its engine,
// so it has to mean already being on the machine. Remote access is an SSH
// tunnel.
func ValidateAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("panel_addr %q must be host:port", addr)
	}
	// Port 0 asks the kernel for a free one. gecit logs the URL it actually
	// bound, so the panel is still reachable, but `gecit status` runs in a
	// different process and can only report the port that was configured.
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("panel_addr %q must end in a port between 0 and 65535", addr)
	}
	if host == "" {
		return fmt.Errorf("panel_addr %q has no host, write it as 127.0.0.1:%s", addr, port)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("panel_addr %q must use an IP address, got %q", addr, host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("panel_addr %q is not loopback, the panel is reachable from this machine only", addr)
	}
	return nil
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /", s.assets())
	mux.Handle("GET /api/state", s.auth(s.handleState))
	mux.Handle("GET /api/logs", s.auth(s.handleLogs))
	mux.Handle("GET /api/config", s.auth(s.handleConfigGet))
	mux.Handle("PUT /api/config", s.auth(s.handleConfigPut))
	mux.Handle("POST /api/apply", s.auth(s.handleApply))
	mux.Handle("POST /api/start", s.auth(s.handleStart))
	mux.Handle("POST /api/stop", s.auth(s.handleStop))
	mux.Handle("POST /api/loglevel", s.auth(s.handleLogLevel))

	return s.secure(mux)
}

// secure sets the headers every response carries and drops requests whose Host
// is not the loopback address the panel was opened on. That second part is what
// stops a page on the wider internet from pointing a rebound hostname at this
// port and talking to it as same-origin.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

		if !s.allowedHost(r.Host) {
			http.Error(w, "unexpected Host header", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allowedHost(host string) bool {
	_, wantPort, err := net.SplitHostPort(s.Addr())
	if err != nil {
		return false
	}
	name, port, err := net.SplitHostPort(host)
	if err != nil {
		// A browser leaves the port out when it is the scheme's default.
		name, port = host, "80"
	}
	if port != wantPort {
		return false
	}
	if name == "localhost" || name == PanelHost {
		return true
	}
	// An IPv6 literal arrives bracketed, and only SplitHostPort strips them.
	ip := net.ParseIP(strings.Trim(name, "[]"))
	return ip != nil && ip.IsLoopback()
}

// auth gates every API route on the token. The JSON content type required for
// mutations is the second lock: a cross-site form cannot set it, so a page in
// another tab cannot drive the panel even if it somehow learned the token.
func (s *Server) auth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !tokenMatches(s.opts.Token, bearerToken(r)) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="gecit"`)
			writeError(w, http.StatusUnauthorized, "invalid or missing panel token")
			return
		}
		if r.Method != http.MethodGet && !isJSON(r.Header.Get("Content-Type")) {
			writeError(w, http.StatusUnsupportedMediaType, "this request needs Content-Type: application/json")
			return
		}
		h(w, r)
	})
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

func isJSON(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && mediaType == "application/json"
}
