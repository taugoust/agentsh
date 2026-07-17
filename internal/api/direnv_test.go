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
	body := "#!/bin/sh\nprintf '%s' '{\"DEV_SHELL\":\"ready\",\"HOME\":\"" + secret + "\",\"PROJECT_TOKEN\":\"" + secret + "\"}'\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	app := newTestApp(t, sessions, store)
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

	events, err := store.QueryEvents(context.Background(), types.EventQuery{SessionID: sess.ID, Limit: 100, Asc: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		encoded, _ := json.Marshal(event)
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("event leaked environment: %s", encoded)
		}
		if event.Type == "command_started" {
			if chunk, _, _, readErr := store.ReadOutputChunk(context.Background(), event.CommandID, "stdout", 0, 1024); readErr == nil || len(chunk) != 0 {
				t.Fatalf("sensitive output was persisted: %q err=%v", chunk, readErr)
			}
		}
	}
}
