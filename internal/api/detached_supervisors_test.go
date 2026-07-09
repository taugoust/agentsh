//go:build !windows

package api

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/auth"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
)

type fakeDetachedSupervisor struct {
	t       *testing.T
	session string
	sock    string
	server  *http.Server
	ln      net.Listener
	delay   time.Duration

	mu               sync.Mutex
	approvals        []map[string]any
	events           []map[string]any
	acceptApprovalID string
	acceptAckID      string
	acceptAnswerID   string
	approvalRaw      []byte
	answerRaw        []byte
	acked            bool
	answered         bool
}

func startFakeDetachedSupervisor(t *testing.T, dir, sessionID string) *fakeDetachedSupervisor {
	t.Helper()
	f := &fakeDetachedSupervisor{t: t, session: sessionID, sock: filepath.Join(dir, sessionID+".sock")}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/approvals", func(w http.ResponseWriter, r *http.Request) {
		f.maybeDelay()
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(f.approvals)
	})
	mux.HandleFunc("/api/v1/session-events", func(w http.ResponseWriter, r *http.Request) {
		f.maybeDelay()
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(f.events)
	})
	mux.HandleFunc("/api/v1/approvals/", func(w http.ResponseWriter, r *http.Request) {
		f.maybeDelay()
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/approvals/")
		if r.Method != http.MethodPost || id != f.acceptApprovalID {
			http.NotFound(w, r)
			return
		}
		raw, _ := readRawJSONBody(r)
		f.mu.Lock()
		f.approvalRaw = append([]byte(nil), raw...)
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})
	mux.HandleFunc("/api/v1/session-events/", func(w http.ResponseWriter, r *http.Request) {
		f.maybeDelay()
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/session-events/")
		parts := strings.Split(rest, "/")
		if len(parts) != 2 || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		id, action := parts[0], parts[1]
		switch action {
		case "ack":
			if id != f.acceptAckID {
				http.NotFound(w, r)
				return
			}
			f.mu.Lock()
			f.acked = true
			f.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		case "answer":
			if id != f.acceptAnswerID {
				http.NotFound(w, r)
				return
			}
			raw, _ := readRawJSONBody(r)
			f.mu.Lock()
			f.answered = true
			f.answerRaw = append([]byte(nil), raw...)
			f.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			http.NotFound(w, r)
		}
	})
	ln, err := net.Listen("unix", f.sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	f.ln = ln
	f.server = &http.Server{Handler: mux}
	go func() { _ = f.server.Serve(ln) }()
	t.Cleanup(func() {
		_ = f.server.Close()
		_ = os.Remove(f.sock)
	})
	return f
}

func (f *fakeDetachedSupervisor) maybeDelay() {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
}

func writeDetachedMetadata(t *testing.T, root string, f *fakeDetachedSupervisor) {
	t.Helper()
	stateDir := filepath.Join(root, f.session)
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := detached.WriteMetadata(stateDir, detached.Metadata{
		SessionID:       f.session,
		ID:              f.session,
		CreatedAt:       time.Now().UTC(),
		State:           "running",
		Policy:          "default",
		WorkspaceMode:   "shadow",
		RealWorkspace:   "/work/" + f.session,
		SupervisorSock:  f.sock,
		OwnerPID:        os.Getpid(),
		ProtocolVersion: detached.ProtocolVersion,
	}); err != nil {
		t.Fatal(err)
	}
}

func newDetachedAggregationTestApp(t *testing.T, roots []string, timeout string) http.Handler {
	t.Helper()
	dir := t.TempDir()
	keysPath := filepath.Join(dir, "keys.yaml")
	if err := os.WriteFile(keysPath, []byte(`
- id: agent
  key: sk-agent
  role: agent
- id: approver
  key: sk-approver
  role: approver
`), 0o600); err != nil {
		t.Fatal(err)
	}
	apiKeyAuth, err := auth.LoadAPIKeys(keysPath, "X-API-Key")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Auth.Type = "api_key"
	cfg.Auth.APIKey.KeysFile = keysPath
	cfg.Auth.APIKey.HeaderName = "X-API-Key"
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Metrics.Enabled = false
	cfg.Sessions.DetachedSupervisors.Enable = true
	cfg.Sessions.DetachedSupervisors.Roots = roots
	cfg.Sessions.DetachedSupervisors.RequestTimeout = timeout
	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, session.NewManager(10), composite.New(nil, nil), engine, events.NewBroker(), apiKeyAuth, nil, nil, metrics.New(), nil, nil)
	return app.Router()
}

func doApproverRequest(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-API-Key", "sk-approver")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestDetachedSupervisorsAggregateSessionEventsAndForwardAckAnswer(t *testing.T) {
	root := t.TempDir()
	f1 := startFakeDetachedSupervisor(t, t.TempDir(), "sess-1")
	f2 := startFakeDetachedSupervisor(t, t.TempDir(), "sess-2")
	f1.events = []map[string]any{{"id": "ev-1", "session_id": "sess-1", "title": "one", "acked": false}}
	f2.events = []map[string]any{{"id": "ev-2", "session_id": "sess-2", "title": "two", "acked": false}}
	f2.acceptAckID = "ev-2"
	f2.acceptAnswerID = "ev-2"
	writeDetachedMetadata(t, root, f1)
	writeDetachedMetadata(t, root, f2)
	h := newDetachedAggregationTestApp(t, []string{root}, "200ms")

	rr := doApproverRequest(h, http.MethodGet, "/api/v1/session-events", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET session-events status=%d body=%s", rr.Code, rr.Body.String())
	}
	var events []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 aggregated events, got %#v", events)
	}

	rr = doApproverRequest(h, http.MethodPost, "/api/v1/session-events/ev-2/ack", `{}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("ack status=%d body=%s", rr.Code, rr.Body.String())
	}
	f2.mu.Lock()
	acked := f2.acked
	f2.mu.Unlock()
	if !acked {
		t.Fatal("expected ack to be forwarded to supervisor owning ev-2")
	}

	answerBody := `{"questionnaire_id":"q1","answers":[{"id":"scope","value":"all"}],"scope_path":"/tmp/raw"}`
	rr = doApproverRequest(h, http.MethodPost, "/api/v1/session-events/ev-2/answer", answerBody)
	if rr.Code != http.StatusOK {
		t.Fatalf("answer status=%d body=%s", rr.Code, rr.Body.String())
	}
	f2.mu.Lock()
	answerRaw := string(f2.answerRaw)
	f2.mu.Unlock()
	if !strings.Contains(answerRaw, `"scope_path":"/tmp/raw"`) {
		t.Fatalf("raw answer JSON was not preserved: %s", answerRaw)
	}
}

func TestDetachedSupervisorsAggregateApprovalsAndForwardRawResolution(t *testing.T) {
	root := t.TempDir()
	f := startFakeDetachedSupervisor(t, t.TempDir(), "sess-approval")
	f.approvals = []map[string]any{{"id": "apr-1", "session_id": "sess-approval", "kind": "file"}}
	f.acceptApprovalID = "apr-1"
	writeDetachedMetadata(t, root, f)
	h := newDetachedAggregationTestApp(t, []string{root}, "200ms")

	rr := doApproverRequest(h, http.MethodGet, "/api/v1/approvals", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET approvals status=%d body=%s", rr.Code, rr.Body.String())
	}
	var approvals []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &approvals); err != nil {
		t.Fatal(err)
	}
	if len(approvals) != 1 || approvals[0]["id"] != "apr-1" {
		t.Fatalf("unexpected approvals: %#v", approvals)
	}

	body := `{"decision":"approve","reason":"ok","scope":"session","scope_kind":"file","scope_key":"file:read:/tmp/a","scope_path":"/tmp/a","scope_prefix":true}`
	rr = doApproverRequest(h, http.MethodPost, "/api/v1/approvals/apr-1", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("resolve status=%d body=%s", rr.Code, rr.Body.String())
	}
	f.mu.Lock()
	raw := string(f.approvalRaw)
	f.mu.Unlock()
	for _, want := range []string{`"scope_kind":"file"`, `"scope_key":"file:read:/tmp/a"`, `"scope_path":"/tmp/a"`, `"scope_prefix":true`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("raw approval JSON missing %s: %s", want, raw)
		}
	}
}

func TestDetachedSupervisorFailuresDoNotBreakGlobalEndpoints(t *testing.T) {
	root := t.TempDir()
	good := startFakeDetachedSupervisor(t, t.TempDir(), "sess-good")
	good.events = []map[string]any{{"id": "ev-good", "session_id": "sess-good", "title": "good"}}
	writeDetachedMetadata(t, root, good)

	slow := startFakeDetachedSupervisor(t, t.TempDir(), "sess-slow")
	slow.delay = 200 * time.Millisecond
	writeDetachedMetadata(t, root, slow)

	missing := &fakeDetachedSupervisor{session: "sess-missing", sock: filepath.Join(t.TempDir(), "missing.sock")}
	writeDetachedMetadata(t, root, missing)

	h := newDetachedAggregationTestApp(t, []string{root}, "20ms")
	rr := doApproverRequest(h, http.MethodGet, "/api/v1/session-events", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET session-events status=%d body=%s", rr.Code, rr.Body.String())
	}
	var events []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0]["id"] != "ev-good" {
		t.Fatalf("expected only good event despite stale/slow supervisors, got %#v", events)
	}
}

func TestDetachedSessionsPushEventsAndApprovalsWithToken(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "sess-push")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := detached.WriteMetadata(stateDir, detached.Metadata{
		SessionID:       "sess-push",
		ID:              "sess-push",
		CreatedAt:       time.Now().UTC(),
		State:           "active",
		Policy:          "default",
		WorkspaceMode:   "shadow",
		RealWorkspace:   "/work/sess-push",
		EventToken:      "tok-push",
		OwnerPID:        os.Getpid(),
		ProtocolVersion: detached.ProtocolVersion,
	}); err != nil {
		t.Fatal(err)
	}
	h := newDetachedAggregationTestApp(t, []string{root}, "20ms")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/detached-sessions/sess-push/session-events", strings.NewReader(`{"id":"ev-push","type":"agent.turn.completed","title":"ready","message":"done"}`))
	req.Header.Set("X-AgentSH-Session-Event-Token", "tok-push")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("push event status=%d body=%s", rr.Code, rr.Body.String())
	}

	rr = doApproverRequest(h, http.MethodGet, "/api/v1/session-events", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list events status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "ev-push") {
		t.Fatalf("pushed event missing from central list: %s", rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/detached-sessions/sess-push/approvals", strings.NewReader(`{"id":"apr-push","kind":"file","target":"/tmp/x"}`))
	req.Header.Set("X-AgentSH-Session-Event-Token", "tok-push")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("push approval status=%d body=%s", rr.Code, rr.Body.String())
	}

	rr = doApproverRequest(h, http.MethodGet, "/api/v1/approvals", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list approvals status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "apr-push") {
		t.Fatalf("pushed approval missing from central list: %s", rr.Body.String())
	}

	rr = doApproverRequest(h, http.MethodPost, "/api/v1/approvals/apr-push", `{"decision":"approve","scope":"once","reason":"ok"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("resolve pushed approval status=%d body=%s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/detached-sessions/sess-push/approvals/apr-push/resolution", nil)
	req.Header.Set("X-AgentSH-Session-Event-Token", "tok-push")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("get pushed resolution status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"resolved":true`) {
		t.Fatalf("expected resolved approval: %s", rr.Body.String())
	}
}

func TestDetachedSessionsPushedCommandSessionScopeResolvesCoveredPending(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "sess-push-command")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := detached.WriteMetadata(stateDir, detached.Metadata{
		SessionID:       "sess-push-command",
		ID:              "sess-push-command",
		CreatedAt:       time.Now().UTC(),
		State:           "active",
		Policy:          "default",
		WorkspaceMode:   "shadow",
		RealWorkspace:   "/work/sess-push-command",
		EventToken:      "tok-command",
		OwnerPID:        os.Getpid(),
		ProtocolVersion: detached.ProtocolVersion,
	}); err != nil {
		t.Fatal(err)
	}
	h := newDetachedAggregationTestApp(t, []string{root}, "20ms")

	command := "/nix/store/abc-sqlite/bin/sqlite3"
	rule := "approve-unknown-nix-store-executables"
	approvalRequest := func(id string, args []string) approvals.Request {
		scope, ok, scopeOptions := commandApprovalScopeOptions(command, args, rule)
		if !ok {
			t.Fatal("commandApprovalScopeOptions returned !ok")
		}
		fields := map[string]any{"command": command, "args": args}
		for k, v := range approvals.ScopeFields(scope) {
			fields[k] = v
		}
		fields["scope_options"] = scopeOptions
		return approvals.Request{ID: id, Kind: "command", Target: command, Rule: rule, Fields: fields}
	}
	postApproval := func(apr approvals.Request) {
		raw, err := json.Marshal(apr)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/detached-sessions/sess-push-command/approvals", strings.NewReader(string(raw)))
		req.Header.Set("X-AgentSH-Session-Event-Token", "tok-command")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("push approval %s status=%d body=%s", apr.ID, rr.Code, rr.Body.String())
		}
	}

	apr1 := approvalRequest("apr-sqlite-1", []string{"events.db", "select 1"})
	apr2 := approvalRequest("apr-sqlite-2", []string{"-readonly", "events.db", "select 2"})
	postApproval(apr1)
	postApproval(apr2)

	executable := findCommandScopeOption(t, apr1, "command-executable:")
	resolveRaw := approvalResolutionJSON(t, "approve", approvals.ScopeSession, executable)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/detached-sessions/sess-push-command/approvals/apr-sqlite-1/resolution", strings.NewReader(string(resolveRaw)))
	req.Header.Set("X-AgentSH-Session-Event-Token", "tok-command")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("resolve status=%d body=%s", rr.Code, rr.Body.String())
	}

	rr = doApproverRequest(h, http.MethodGet, "/api/v1/approvals", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list approvals status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "apr-sqlite-2") {
		t.Fatalf("covered detached approval still listed after session resolution: %s", rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/detached-sessions/sess-push-command/approvals/apr-sqlite-2/resolution", nil)
	req.Header.Set("X-AgentSH-Session-Event-Token", "tok-command")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("get covered resolution status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Resolved   bool                 `json:"resolved"`
		Resolution approvals.Resolution `json:"resolution"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Resolved || !body.Resolution.Approved || body.Resolution.ScopeKey != executable.Key {
		t.Fatalf("covered approval resolution = %+v, want approved executable session scope %s", body, executable.Key)
	}
}

func TestSessionEventEndpointsRequireApproverRole(t *testing.T) {
	h := newDetachedAggregationTestApp(t, nil, "20ms")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/session-events", nil)
	req.Header.Set("X-API-Key", "sk-agent")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for agent key, got %d", rr.Code)
	}
}
