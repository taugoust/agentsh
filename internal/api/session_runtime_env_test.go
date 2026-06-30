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
		ID          string `json:"id"`
		RuntimeHome string `json:"runtime_home"`
		RuntimeTmp  string `json:"runtime_tmp"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.RuntimeHome == "" || out.RuntimeTmp == "" {
		t.Fatalf("runtime paths missing: %+v", out)
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
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
