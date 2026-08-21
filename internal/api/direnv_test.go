package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

func testDirenvEngine(t *testing.T) *policy.Engine {
	t.Helper()
	p, err := policy.LoadFromBytes([]byte(`
version: 1
name: direnv-test
command_rules:
  - name: allow-server-direnv-export
    commands: ["direnv"]
    args_patterns: ["^export json$"]
    internal_provenance: direnv_refresh
    context: [direct]
    decision: allow
  - name: deny-generic-direnv-export
    commands: ["direnv"]
    args_patterns: ["^export json$"]
    context: [direct]
    decision: deny
  - name: allow-test-commands
    commands: ["*"]
    decision: allow
direnv:
  enabled: true
  allow: ["*"]
  deny: []
  max_keys: 64
  max_value_bytes: 4096
  max_bytes: 32768
  max_stdout_bytes: 65536
  max_stderr_bytes: 4096
  queue_timeout: 1s
  evaluation_timeout: 2s
`))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := policy.NewEngine(p, false, false)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestCommandOutputArtifactCapture_DirenvJSONValidation(t *testing.T) {
	cfg := testDirenvEngine(t).DirenvImportPolicy()
	if _, err := parseDirenvJSON([]byte(`{"A":"one","a":"two"}`), cfg); err == nil {
		t.Fatal("expected case-folded duplicate rejection")
	}
	if _, err := parseDirenvJSON([]byte(`{"A":1}`), cfg); err == nil {
		t.Fatal("expected non-string rejection")
	}
	cfg.MaxValueBytes = 2
	if _, err := parseDirenvJSON([]byte(`{"A":"long"}`), cfg); err == nil {
		t.Fatal("expected value bound rejection")
	}
}

func TestCommandOutputArtifactCapture_DirenvAtomicFiltering(t *testing.T) {
	cfg := testDirenvEngine(t).DirenvImportPolicy()
	s := &session.Session{}
	s.SetServiceEnvVars(map[string]string{"DATABASE_URL": "supervisor-owned"})
	s.ReplaceDirenvEnvironment(map[string]string{"OLD": "keep", "REMOVE": "old"})
	old, generation := s.DirenvEnvironment()
	result := evaluateDirenvResult(cfg, s, old, generation, internalSensitiveExecResult{
		Stdout: []byte(`{"DEV_SHELL":"ready","REMOVE":null,"HOME":"stolen","project_token":"secret","database_url":"stolen"}`),
	})
	if result.State != "loaded" || result.SetCount != 1 || result.UnsetCount != 1 || result.RejectedCount != 3 {
		t.Fatalf("result = %#v", result)
	}
	got, _ := s.DirenvEnvironment()
	if got["DEV_SHELL"] != "ready" || got["OLD"] != "keep" {
		t.Fatalf("committed environment = %#v", got)
	}
	if _, ok := got["REMOVE"]; ok {
		t.Fatalf("unset key retained: %#v", got)
	}
	for name, run := range map[string]internalSensitiveExecResult{
		"malformed": {Stdout: []byte(`{"BROKEN":`)},
		"truncated": {Stdout: []byte(`{}`), StdoutTruncated: true},
		"timeout":   {ExitCode: 124, ExecErr: context.DeadlineExceeded},
		"unallowed": {ExitCode: 1, Stderr: []byte(".envrc is not allowed")},
	} {
		t.Run(name, func(t *testing.T) {
			before, beforeGeneration := s.DirenvEnvironment()
			failed := evaluateDirenvResult(cfg, s, before, beforeGeneration, run)
			after, afterGeneration := s.DirenvEnvironment()
			if !reflect.DeepEqual(before, after) || beforeGeneration != afterGeneration {
				t.Fatalf("failed refresh committed: result=%#v before=%#v after=%#v", failed, before, after)
			}
		})
	}
}

func TestCommandOutputArtifactCapture_DirenvRevokesStalePolicyAndServiceValues(t *testing.T) {
	cfg := testDirenvEngine(t).DirenvImportPolicy()
	s := &session.Session{}
	s.ReplaceDirenvEnvironment(map[string]string{
		"KEEP":          "current",
		"POLICY_STALE":  "old-policy-value",
		"SERVICE_STALE": "old-direnv-value",
	})

	cfg.Deny = []string{"POLICY_*"}
	s.SetServiceEnvVars(map[string]string{"service_stale": "supervisor-owned"})
	old, _ := s.DirenvEnvironment()
	next, generation, removed := pruneDirenvEnvironment(cfg, s, old)
	if removed != 2 || generation != 2 || !reflect.DeepEqual(next, map[string]string{"KEEP": "current"}) {
		t.Fatalf("policy/service transition = next=%#v generation=%d removed=%d", next, generation, removed)
	}

	cfg.Enabled = false
	next, generation, removed = pruneDirenvEnvironment(cfg, s, next)
	if removed != 1 || generation != 3 || len(next) != 0 {
		t.Fatalf("disabled transition = next=%#v generation=%d removed=%d", next, generation, removed)
	}
}

func TestDirenvFileWithinWorkspaceDoesNotSearchParents(t *testing.T) {
	parent := t.TempDir()
	workspace := filepath.Join(parent, "workspace")
	nested := filepath.Join(workspace, "nested", "deeper")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, ".envrc"), []byte("outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	found, err := direnvFileWithinWorkspace(nested, workspace)
	if err != nil || found {
		t.Fatalf("outside parent .envrc: found=%t err=%v", found, err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".envrc"), []byte("inside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	found, err = direnvFileWithinWorkspace(nested, workspace)
	if err != nil || !found {
		t.Fatalf("workspace .envrc: found=%t err=%v", found, err)
	}
}

func TestCommandOutputArtifactCapture_DirenvEndpointKeepsValuesServerSide(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake direnv fixture requires a POSIX executable script")
	}
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	ws := filepath.Join(t.TempDir(), "workspace")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, ".envrc"), []byte("# test fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	sess.SetPolicyEngine(testDirenvEngine(t))
	bin := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(bin, "direnv")
	secret := "refresh-value-must-not-egress"
	nestedSecret := "distinctive-direnv-nested-argv-secret-7f51"
	nested := filepath.Join(bin, "nested-direnv-helper")
	if err := os.WriteFile(nested, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "#!/bin/sh\n" + nested + " '" + nestedSecret + "'\nif [ \"${DEV_SHELL:-}\" = ready ]; then\n  exit 0\nfi\nprintf '%s' '{\"DEV_SHELL\":\"ready\",\"HOME\":\"" + secret + "\",\"PROJECT_TOKEN\":\"" + secret + "\"}'\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	app := newTestApp(t, sessions, store)

	generic := httptest.NewRecorder()
	app.Router().ServeHTTP(generic, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/exec", strings.NewReader(`{"command":"direnv","args":["export","json"],"working_dir":"/workspace","actor":{"kind":"extension","label":"Pi direnv refresh"}}`)))
	if generic.Code != http.StatusForbidden {
		t.Fatalf("generic exec spoofed refresh provenance: status=%d body=%s", generic.Code, generic.Body.String())
	}

	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/refresh_direnv", strings.NewReader(`{"cwd":"/workspace","actor":{"kind":"extension","label":"test"}}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), secret) || strings.Contains(rr.Body.String(), "DEV_SHELL") {
		t.Fatalf("refresh response leaked environment: %s", rr.Body.String())
	}
	var response toolResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	result := response.Result.(map[string]any)
	if result["state"] != "loaded" || result["set_count"] != float64(1) || result["rejected_count"] != float64(2) {
		t.Fatalf("response = %#v", result)
	}
	got, _ := sess.DirenvEnvironment()
	if got["DEV_SHELL"] != "ready" || got["HOME"] != "" || got["PROJECT_TOKEN"] != "" {
		t.Fatalf("server snapshot = %#v", got)
	}

	unchanged := httptest.NewRecorder()
	app.Router().ServeHTTP(unchanged, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/refresh_direnv", strings.NewReader(`{"cwd":"/workspace","actor":{"kind":"extension","label":"test"}}`)))
	if unchanged.Code != http.StatusOK {
		t.Fatalf("unchanged status = %d body=%s", unchanged.Code, unchanged.Body.String())
	}
	if strings.Contains(unchanged.Body.String(), secret) || strings.Contains(unchanged.Body.String(), "DEV_SHELL") {
		t.Fatalf("unchanged response leaked environment: %s", unchanged.Body.String())
	}
	var unchangedResponse toolResponse
	if err := json.Unmarshal(unchanged.Body.Bytes(), &unchangedResponse); err != nil {
		t.Fatal(err)
	}
	unchangedResult := unchangedResponse.Result.(map[string]any)
	if unchangedResult["state"] != "unchanged" || unchangedResult["set_count"] != float64(0) || unchangedResult["rejected_count"] != float64(0) {
		t.Fatalf("unchanged response = %#v", unchangedResult)
	}
	gotAfterUnchanged, _ := sess.DirenvEnvironment()
	if !reflect.DeepEqual(gotAfterUnchanged, got) {
		t.Fatalf("unchanged refresh modified snapshot: before=%#v after=%#v", got, gotAfterUnchanged)
	}

	events, err := store.QueryEvents(context.Background(), types.EventQuery{SessionID: sess.ID, Limit: 100, Asc: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		encoded, _ := json.Marshal(event)
		if strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), nestedSecret) {
			t.Fatalf("event leaked sensitive refresh data: %s", encoded)
		}
		if event.Type == "command_started" {
			if chunk, _, _, readErr := store.ReadOutputChunk(context.Background(), event.CommandID, "stdout", 0, 1024); readErr == nil || len(chunk) != 0 {
				t.Fatalf("sensitive output was persisted: %q err=%v", chunk, readErr)
			}
		}
	}
}
