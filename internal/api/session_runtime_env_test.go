package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
)

func TestCreateSession_AssignsRuntimeHomeAndTmp(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	app := newTestApp(t, sessions, store)
	app.cfg.Sessions.WorkspaceShadow.BaseDir = filepath.Join(t.TempDir(), "workspaces")
	app.cfg.Sessions.OutputArtifacts.MaxBytes = 5

	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}

	body := `{"workspace":` + strconvQuote(ws) + `,"policy":"default","workspace_mode":"direct"}`
	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions", strings.NewReader(body)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create session status = %d body = %s", rr.Code, rr.Body.String())
	}

	var out struct {
		ID              string `json:"id"`
		RuntimeHome     string `json:"runtime_home"`
		RuntimeTmp      string `json:"runtime_tmp"`
		ProcessHome     string `json:"process_home"`
		RuntimeHomeMode string `json:"runtime_home_mode"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.RuntimeHome == "" || out.RuntimeTmp == "" {
		t.Fatalf("runtime paths missing: %+v", out)
	}
	if out.ProcessHome != out.RuntimeHome || out.RuntimeHomeMode != "isolated" {
		t.Fatalf("isolated process home mismatch: %+v", out)
	}
	for _, dir := range []string{out.RuntimeHome, out.RuntimeTmp, filepath.Join(out.RuntimeHome, ".config"), filepath.Join(out.RuntimeHome, ".cache"), filepath.Join(out.RuntimeHome, ".local", "state"), filepath.Join(out.RuntimeHome, ".local", "share")} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("runtime dir %s: %v", dir, err)
		}
		if !info.IsDir() {
			t.Fatalf("runtime path is not dir: %s", dir)
		}
	}
	created, ok := sessions.Get(out.ID)
	if !ok {
		t.Fatal("created session not found")
	}
	artifact, err := created.WriteOutputArtifact("config-bound", strings.NewReader("123456"))
	if err != nil {
		t.Fatalf("WriteOutputArtifact: %v", err)
	}
	if artifact.BytesWritten != 5 || !artifact.Truncated {
		t.Fatalf("configured artifact bound was not applied: %+v", artifact)
	}
}

func TestCreateSession_RuntimeHomeModeRealKeepsRuntimeDataIsolated(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	app := newTestApp(t, sessions, store)
	app.cfg.Sessions.WorkspaceShadow.BaseDir = filepath.Join(t.TempDir(), "workspaces")

	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	realHome := filepath.Join(t.TempDir(), "real-home")
	if err := os.MkdirAll(realHome, 0o755); err != nil {
		t.Fatal(err)
	}

	body := `{"workspace":` + strconvQuote(ws) + `,"policy":"default","workspace_mode":"direct","home":` + strconvQuote(realHome) + `,"runtime_home_mode":"real","env_base_mode":"inherit_allowed","env_inherit":["SSH_AUTH_SOCK"]}`
	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions", strings.NewReader(body)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create session status = %d body = %s", rr.Code, rr.Body.String())
	}

	var out struct {
		RuntimeHome     string   `json:"runtime_home"`
		RuntimeTmp      string   `json:"runtime_tmp"`
		ProcessHome     string   `json:"process_home"`
		RuntimeHomeMode string   `json:"runtime_home_mode"`
		EnvBaseMode     string   `json:"env_base_mode"`
		EnvInherit      []string `json:"env_inherit"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.ProcessHome != realHome {
		t.Fatalf("process_home = %q, want %q", out.ProcessHome, realHome)
	}
	if out.RuntimeHome == "" || out.RuntimeHome == realHome || out.RuntimeTmp == "" {
		t.Fatalf("runtime data dirs not isolated: %+v", out)
	}
	if out.RuntimeHomeMode != "real" || out.EnvBaseMode != "inherit_allowed" || len(out.EnvInherit) != 1 || out.EnvInherit[0] != "SSH_AUTH_SOCK" {
		t.Fatalf("runtime/env modes not surfaced: %+v", out)
	}
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
