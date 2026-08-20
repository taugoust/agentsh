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

func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "as-sock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

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
		State:           detached.LifecycleReady,
		Policy:          "default",
		WorkspaceMode:   "shadow",
		RealWorkspace:   "/work/" + f.session,
		SupervisorSock:  f.sock,
		OwnerPID:        os.Getpid(),
		Generation:      1,
		IncarnationID:   "test-incarnation",
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

func TestDetachedSupervisorsListReportsNetworkEnforcement(t *testing.T) {
	root := t.TempDir()
	f := startFakeDetachedSupervisor(t, shortSocketDir(t), "sess-network")
	stateDir := filepath.Join(root, f.session)
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := detached.WriteMetadata(stateDir, detached.Metadata{
		SessionID:       f.session,
		ID:              f.session,
		CreatedAt:       time.Now().UTC(),
		State:           detached.LifecycleReady,
		Policy:          "default",
		WorkspaceMode:   "shadow",
		RealWorkspace:   "/work/" + f.session,
		SupervisorSock:  f.sock,
		OwnerPID:        os.Getpid(),
		Generation:      1,
		IncarnationID:   "test-incarnation",
		ProtocolVersion: detached.ProtocolVersion,
		NetworkEnforcement: &detached.NetworkEnforcement{
			Status:                detached.NetworkEnforcementStatusDegraded,
			Tier:                  detached.NetworkEnforcementTierCgroupDelegated,
			NetworkPolicyEnforced: false,
			CgroupDelegated:       true,
		},
	}); err != nil {
		t.Fatal(err)
	}
	h := newDetachedAggregationTestApp(t, []string{root}, "200ms")

	rr := doApproverRequest(h, http.MethodGet, "/api/v1/detached-supervisors", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var got []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1: %#v", len(got), got)
	}
	network, ok := got[0]["network_enforcement"].(map[string]any)
	if !ok {
		t.Fatalf("network_enforcement = %#v, want object", got[0]["network_enforcement"])
	}
	if network["status"] != string(detached.NetworkEnforcementStatusDegraded) {
		t.Fatalf("status = %#v", network["status"])
	}
	if network["tier"] != string(detached.NetworkEnforcementTierCgroupDelegated) {
		t.Fatalf("tier = %#v", network["tier"])
	}
	if network["network_policy_enforced"] != false {
		t.Fatalf("network_policy_enforced = %#v, want false", network["network_policy_enforced"])
	}
	if network["cgroup_delegated"] != true {
		t.Fatalf("cgroup_delegated = %#v, want true", network["cgroup_delegated"])
	}
	if got[0]["network_enforcement_source"] != "metadata-snapshot-stale" || got[0]["network_enforcement_live"] != false {
		t.Fatalf("network evidence source = %#v live=%#v, want stale metadata snapshot", got[0]["network_enforcement_source"], got[0]["network_enforcement_live"])
	}
}

func TestDetachedSupervisorsAggregateSessionEventsAndForwardAckAnswer(t *testing.T) {
	root := t.TempDir()
	f1 := startFakeDetachedSupervisor(t, shortSocketDir(t), "sess-1")
	f2 := startFakeDetachedSupervisor(t, shortSocketDir(t), "sess-2")
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
	f := startFakeDetachedSupervisor(t, shortSocketDir(t), "sess-approval")
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
	good := startFakeDetachedSupervisor(t, shortSocketDir(t), "sess-good")
	good.events = []map[string]any{{"id": "ev-good", "session_id": "sess-good", "title": "good"}}
	writeDetachedMetadata(t, root, good)

	slow := startFakeDetachedSupervisor(t, shortSocketDir(t), "sess-slow")
	slow.delay = 200 * time.Millisecond
	writeDetachedMetadata(t, root, slow)

	missing := &fakeDetachedSupervisor{session: "sess-missing", sock: filepath.Join(shortSocketDir(t), "missing.sock")}
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

func TestDetachedSessionsPushEventsWithToken(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "sess-push")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := detached.WriteMetadata(stateDir, detached.Metadata{
		SessionID:       "sess-push",
		ID:              "sess-push",
		CreatedAt:       time.Now().UTC(),
		State:           detached.LifecycleReady,
		Policy:          "default",
		WorkspaceMode:   "shadow",
		RealWorkspace:   "/work/sess-push",
		EventToken:      "tok-push",
		OwnerPID:        os.Getpid(),
		Generation:      1,
		IncarnationID:   "test-incarnation",
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
