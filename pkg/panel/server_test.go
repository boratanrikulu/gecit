package panel

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/boratanrikulu/gecit/pkg/engine"
	"github.com/sirupsen/logrus"
)

type fakeController struct {
	status    Status
	stats     engine.Stats
	platform  []Fact
	config    ConfigView
	logLevel  string
	saved     []engine.Config
	saveErr   error
	applyErr  error
	startErr  error
	stopErr   error
	applied   int
	started   int
	stopped   int
	levelSets []string
}

func (c *fakeController) Status() Status      { return c.status }
func (c *fakeController) Stats() engine.Stats { return c.stats }
func (c *fakeController) Platform() []Fact    { return c.platform }
func (c *fakeController) Config() ConfigView  { return c.config }
func (c *fakeController) LogLevel() string    { return c.logLevel }

func (c *fakeController) Start() error {
	c.started++
	return c.startErr
}

func (c *fakeController) Stop() error {
	c.stopped++
	return c.stopErr
}

func (c *fakeController) Apply() error {
	c.applied++
	return c.applyErr
}

func (c *fakeController) SaveConfig(cfg engine.Config) error {
	if c.saveErr != nil {
		return c.saveErr
	}
	c.saved = append(c.saved, cfg)
	c.config.Values = cfg
	return nil
}

func (c *fakeController) SetLogLevel(level string) error {
	if level != "info" && level != "debug" {
		return errors.New("log level must be info or debug")
	}
	c.levelSets = append(c.levelSets, level)
	c.logLevel = level
	return nil
}

const testToken = "test-token"

func newTestServer(t *testing.T) (*Server, *fakeController, *Ring) {
	t.Helper()

	ctrl := &fakeController{
		status:   Status{Running: true, Mode: "tun", StartedAt: time.Now()},
		stats:    engine.Stats{Connections: 3, FakesInjected: 3, DNSQueries: 7},
		platform: []Fact{{Name: "engine", Value: "tun"}},
		config: ConfigView{
			Path:             "/etc/gecit/config.yaml",
			Values:           engine.DefaultConfig(),
			OverriddenByFlag: map[string]string{"fake_ttl": "fake-ttl"},
		},
		logLevel: "info",
	}

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	srv, err := New(Options{
		Addr:   "127.0.0.1:0",
		Token:  testToken,
		Ctrl:   ctrl,
		Ring:   NewRing(64),
		Logger: logger,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { srv.Stop(t.Context()) })

	return srv, ctrl, srv.opts.Ring
}

func do(t *testing.T, srv *Server, method, path, body string, edit func(*http.Request)) *http.Response {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "http://"+srv.Addr()+path, reader)
	req.Host = srv.Addr()
	req.Header.Set("Authorization", "Bearer "+testToken)
	if body != "" || method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}
	if edit != nil {
		edit(req)
	}

	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	return rec.Result()
}

func TestAPIRequiresTheToken(t *testing.T) {
	srv, _, _ := newTestServer(t)

	for name, edit := range map[string]func(*http.Request){
		"no header":    func(r *http.Request) { r.Header.Del("Authorization") },
		"wrong token":  func(r *http.Request) { r.Header.Set("Authorization", "Bearer nope") },
		"empty bearer": func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") },
		"basic auth":   func(r *http.Request) { r.Header.Set("Authorization", "Basic dGVzdDp0ZXN0") },
		"raw token":    func(r *http.Request) { r.Header.Set("Authorization", testToken) },
	} {
		resp := do(t, srv, http.MethodGet, "/api/state", "", edit)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, resp.StatusCode)
		}
	}

	if resp := do(t, srv, http.MethodGet, "/api/state", "", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("the right token: status %d, want 200", resp.StatusCode)
	}
}

// A page anywhere on the internet can point a hostname it controls at this
// port. The Host header is what tells the two apart.
func TestForeignHostIsRefused(t *testing.T) {
	srv, _, _ := newTestServer(t)
	_, port, _ := strings.Cut(srv.Addr(), ":")

	// gecit.local is not gecit.localhost: only the reserved suffix is resolved
	// to loopback by the browser, so only that one is allowed through.
	for _, host := range []string{
		"evil.example:" + port,
		"gecit.local:" + port,
		"gecit.localhost.evil.example:" + port,
		"127.0.0.1:1",
		"",
	} {
		resp := do(t, srv, http.MethodGet, "/api/state", "", func(r *http.Request) { r.Host = host })
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Host %q: status %d, want 403", host, resp.StatusCode)
		}
	}

	for _, host := range []string{
		"127.0.0.1:" + port,
		"localhost:" + port,
		"[::1]:" + port,
		"gecit.localhost:" + port,
	} {
		resp := do(t, srv, http.MethodGet, "/api/state", "", func(r *http.Request) { r.Host = host })
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Host %q: status %d, want 200", host, resp.StatusCode)
		}
	}
}

// A cross-site form post cannot set this content type, which is what keeps
// another tab from driving the panel.
func TestMutationsNeedJSONContentType(t *testing.T) {
	srv, ctrl, _ := newTestServer(t)

	resp := do(t, srv, http.MethodPost, "/api/stop", "", func(r *http.Request) {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	})
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("status %d, want 415", resp.StatusCode)
	}
	if ctrl.stopped != 0 {
		t.Fatalf("the controller was called %d times despite the refusal", ctrl.stopped)
	}

	if resp := do(t, srv, http.MethodPost, "/api/stop", "", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if ctrl.stopped != 1 {
		t.Fatalf("stop was called %d times, want 1", ctrl.stopped)
	}
}

func TestSecurityHeaders(t *testing.T) {
	srv, _, _ := newTestServer(t)
	resp := do(t, srv, http.MethodGet, "/api/state", "", nil)

	for header, want := range map[string]string{
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP = %q, want it to confine the page to self", csp)
	}
}

func TestPageIsServedWithoutAToken(t *testing.T) {
	srv, _, _ := newTestServer(t)

	resp := do(t, srv, http.MethodGet, "/", "", func(r *http.Request) { r.Header.Del("Authorization") })
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200: the page carries no data, only the API does", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "<html") {
		t.Errorf("body is not the page: %q", string(body))
	}
}

func TestStateReportsEverythingTheOverviewNeeds(t *testing.T) {
	srv, _, ring := newTestServer(t)
	ring.Append(Entry{Msg: "injected", Fields: map[string]string{"event": "inject", "dst": "example.com:443"}})
	ring.Append(Entry{Msg: "noise"})

	resp := do(t, srv, http.MethodGet, "/api/state", "", nil)
	var state stateResponse
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !state.Status.Running || state.Status.Mode != "tun" {
		t.Errorf("status = %+v", state.Status)
	}
	if state.Stats.Connections != 3 || state.Stats.DNSQueries != 7 {
		t.Errorf("stats = %+v", state.Stats)
	}
	if state.LogLevel != "info" {
		t.Errorf("log level = %q", state.LogLevel)
	}
	if len(state.Platform) != 1 || state.Platform[0].Name != "engine" {
		t.Errorf("platform = %+v", state.Platform)
	}
	if len(state.Activity) != 1 || state.Activity[0].Fields["dst"] != "example.com:443" {
		t.Errorf("activity = %+v, want only the entry carrying an event field", state.Activity)
	}
	if state.Config.OverriddenByFlag["fake_ttl"] != "fake-ttl" {
		t.Errorf("overrides = %v, want fake_ttl mapped to its flag", state.Config.OverriddenByFlag)
	}
}

func TestLogsPagination(t *testing.T) {
	srv, _, ring := newTestServer(t)
	for _, m := range []string{"one", "two", "three"} {
		ring.Append(Entry{Msg: m})
	}

	resp := do(t, srv, http.MethodGet, "/api/logs", "", nil)
	var first logsResponse
	json.NewDecoder(resp.Body).Decode(&first)
	if len(first.Entries) != 3 || first.Latest != 3 {
		t.Fatalf("first poll: %d entries, latest %d, want 3 and 3", len(first.Entries), first.Latest)
	}

	ring.Append(Entry{Msg: "four"})

	resp = do(t, srv, http.MethodGet, "/api/logs?since=3", "", nil)
	var second logsResponse
	json.NewDecoder(resp.Body).Decode(&second)
	if len(second.Entries) != 1 || second.Entries[0].Msg != "four" {
		t.Fatalf("second poll returned %+v, want only the new line", second.Entries)
	}

	if resp := do(t, srv, http.MethodGet, "/api/logs?since=abc", "", nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("non-numeric since: status %d, want 400", resp.StatusCode)
	}
}

func TestSaveConfigRejectsWhatTheControllerRejects(t *testing.T) {
	srv, ctrl, _ := newTestServer(t)
	ctrl.saveErr = errors.New("fake_ttl must be 1-255, got 0")

	resp := do(t, srv, http.MethodPut, "/api/config", `{"fake_ttl":0}`, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if !strings.Contains(body["error"], "fake_ttl") {
		t.Errorf("error = %q, want the reason from the validator", body["error"])
	}
	if len(ctrl.saved) != 0 {
		t.Errorf("a rejected config was recorded as saved")
	}
}

func TestSaveConfigStoresTheValues(t *testing.T) {
	srv, ctrl, _ := newTestServer(t)

	resp := do(t, srv, http.MethodPut, "/api/config",
		`{"fake_ttl":12,"ports":[443,8443],"doh_enabled":true,"doh_upstream":"quad9"}`, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if len(ctrl.saved) != 1 {
		t.Fatalf("saved %d configs, want 1", len(ctrl.saved))
	}
	got := ctrl.saved[0]
	if got.FakeTTL != 12 || got.DoHUpstream != "quad9" || len(got.Ports) != 2 {
		t.Errorf("saved %+v", got)
	}
}

// An unknown key is a typo that would otherwise be dropped on the floor, which
// is the same reason the config file loader rejects one.
func TestSaveConfigRejectsUnknownKeys(t *testing.T) {
	srv, ctrl, _ := newTestServer(t)

	resp := do(t, srv, http.MethodPut, "/api/config", `{"fake-ttl":12}`, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
	if len(ctrl.saved) != 0 {
		t.Errorf("an unknown key was accepted")
	}
}

func TestLifecycleRoutes(t *testing.T) {
	srv, ctrl, _ := newTestServer(t)

	for path, count := range map[string]*int{
		"/api/start": &ctrl.started,
		"/api/stop":  &ctrl.stopped,
		"/api/apply": &ctrl.applied,
	} {
		if resp := do(t, srv, http.MethodPost, path, "", nil); resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d, want 200", path, resp.StatusCode)
		}
		if *count != 1 {
			t.Errorf("%s called the controller %d times, want 1", path, *count)
		}
	}
}

func TestApplyReportsTheFailure(t *testing.T) {
	srv, ctrl, _ := newTestServer(t)
	ctrl.applyErr = errors.New("create TUN: operation not permitted")

	resp := do(t, srv, http.MethodPost, "/api/apply", "", nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", resp.StatusCode)
	}
	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if !strings.Contains(body["error"], "create TUN") {
		t.Errorf("error = %q, want the engine's own message", body["error"])
	}
}

func TestLogLevelToggle(t *testing.T) {
	srv, ctrl, _ := newTestServer(t)

	if resp := do(t, srv, http.MethodPost, "/api/loglevel", `{"level":"debug"}`, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if ctrl.logLevel != "debug" {
		t.Errorf("log level = %q, want debug", ctrl.logLevel)
	}

	if resp := do(t, srv, http.MethodPost, "/api/loglevel", `{"level":"trace"}`, nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("an unsupported level should be refused")
	}
}

func TestValidateAddr(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8088", "[::1]:8088", "127.0.0.2:1", "127.0.0.1:0"} {
		if err := ValidateAddr(addr); err != nil {
			t.Errorf("ValidateAddr(%q) = %v, want nil", addr, err)
		}
	}

	// Anything reachable from off the machine hands config rewriting and engine
	// control to whoever can reach the port.
	for _, addr := range []string{
		"0.0.0.0:8088",
		"192.168.1.10:8088",
		"[::]:8088",
		":8088",
		"localhost:8088",
		"127.0.0.1",
		"127.0.0.1:99999",
		"",
	} {
		if err := ValidateAddr(addr); err == nil {
			t.Errorf("ValidateAddr(%q) = nil, want an error", addr)
		}
	}
}

func TestNewRejectsAnIncompleteSetup(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	ok := Options{Addr: "127.0.0.1:0", Token: "t", Ctrl: &fakeController{}, Ring: NewRing(4), Logger: logger}

	if _, err := New(ok); err != nil {
		t.Fatalf("a complete setup should build, got %v", err)
	}

	noToken := ok
	noToken.Token = ""
	if _, err := New(noToken); err == nil {
		t.Error("a panel with no token would be open to every local process")
	}

	remote := ok
	remote.Addr = "0.0.0.0:8088"
	if _, err := New(remote); err == nil {
		t.Error("a non-loopback address should be refused")
	}
}

func TestAssetsAreServedFromTheBinary(t *testing.T) {
	srv, _, _ := newTestServer(t)

	// Windows resolves extensions through the registry, so the javascript type
	// is whatever that machine says. The page only needs it not to be html.
	for path, wantType := range map[string]string{
		"/":          "text/html",
		"/app.js":    "",
		"/style.css": "text/css",
	} {
		resp := do(t, srv, http.MethodGet, path, "", nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d, want 200", path, resp.StatusCode)
			continue
		}
		got := resp.Header.Get("Content-Type")
		if wantType == "" {
			if strings.Contains(got, "text/html") {
				t.Errorf("%s: Content-Type %q, a script must not be served as html", path, got)
			}
		} else if !strings.Contains(got, wantType) {
			t.Errorf("%s: Content-Type %q, want %q", path, got, wantType)
		}
		body, _ := io.ReadAll(resp.Body)
		if len(body) == 0 {
			t.Errorf("%s: served an empty file", path)
		}
	}

	if resp := do(t, srv, http.MethodGet, "/nope", "", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown path: status %d, want 404", resp.StatusCode)
	}
}

// A body naming one key means "leave the rest alone". Decoded into an empty
// Config it would write panel_enabled: false and blank the cgroup path on the
// way past, turning the panel off at the next restart.
func TestSaveConfigKeepsKeysTheBodyOmits(t *testing.T) {
	srv, ctrl, _ := newTestServer(t)
	ctrl.config.Values = engine.DefaultConfig()

	resp := do(t, srv, http.MethodPut, "/api/config", `{"fake_ttl":12}`, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}

	got := ctrl.saved[0]
	if got.FakeTTL != 12 {
		t.Errorf("fake_ttl = %d, want the submitted 12", got.FakeTTL)
	}
	if !got.PanelEnabled || got.PanelAddr != "127.0.0.1:8088" {
		t.Errorf("the panel was turned off by a request that never mentioned it: %+v", got)
	}
	if got.MSS != 88 || got.CgroupPath != "/sys/fs/cgroup" || len(got.Ports) != 1 {
		t.Errorf("omitted keys were zeroed: %+v", got)
	}
}

// Binding before returning is what makes a busy port the caller's error. If it
// moved into the goroutine, gecit would announce a panel nothing is serving.
func TestStartReportsABusyPort(t *testing.T) {
	srv, _, _ := newTestServer(t)

	second, err := New(Options{
		Addr:   srv.Addr(),
		Token:  testToken,
		Ctrl:   &fakeController{},
		Ring:   NewRing(4),
		Logger: srv.opts.Logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Start(); err == nil {
		second.Stop(t.Context())
		t.Fatal("binding a port already in use should error")
	}
}

// encoding/json writes into a slice that is long enough, so a PUT must not be
// able to reach the controller's own state through the values it handed out.
func TestSaveConfigDoesNotWriteThroughToTheController(t *testing.T) {
	srv, ctrl, _ := newTestServer(t)
	cfg := engine.DefaultConfig()
	cfg.Ports = []uint16{443, 8443}
	ctrl.config.Values = cfg

	do(t, srv, http.MethodPut, "/api/config", `{"ports":[80]}`, nil)

	if cfg.Ports[0] != 443 {
		t.Errorf("the request wrote through into the caller's slice: %v", cfg.Ports)
	}
}
