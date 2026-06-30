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

func TestPiToolFileEndpoints_WriteReadEdit(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)

	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(filepath.Join(ws, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	app := newTestApp(t, sessions, store)
	h := app.Router()

	writeBody := `{"path":"src/a.txt","content":"hello world","actor":{"kind":"parent","label":"test"}}`
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/write_file", strings.NewReader(writeBody)))
	if rr.Code != http.StatusOK {
		t.Fatalf("write_file status = %d body = %s", rr.Code, rr.Body.String())
	}
	if got, err := os.ReadFile(filepath.Join(ws, "src", "a.txt")); err != nil || string(got) != "hello world" {
		t.Fatalf("workspace file = %q err=%v", string(got), err)
	}

	editBody := `{"path":"src/a.txt","oldText":"world","newText":"agentsh"}`
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/edit_file", strings.NewReader(editBody)))
	if rr.Code != http.StatusOK {
		t.Fatalf("edit_file status = %d body = %s", rr.Code, rr.Body.String())
	}

	readBody := `{"path":"src/a.txt"}`
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/read_file", strings.NewReader(readBody)))
	if rr.Code != http.StatusOK {
		t.Fatalf("read_file status = %d body = %s", rr.Code, rr.Body.String())
	}
	var resp toolResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("result type = %T", resp.Result)
	}
	if result["content"] != "hello agentsh" {
		t.Fatalf("content = %#v", result["content"])
	}
}

func TestPiToolFileEndpoints_RejectTraversalAndDuplicateEdit(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)

	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "dup.txt"), []byte("x x"), 0o644); err != nil {
		t.Fatal(err)
	}

	app := newTestApp(t, sessions, store)
	h := app.Router()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/read_file", strings.NewReader(`{"path":"../secret"}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("traversal status = %d body = %s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/edit_file", strings.NewReader(`{"path":"dup.txt","oldText":"x","newText":"y"}`)))
	if rr.Code != http.StatusConflict {
		t.Fatalf("duplicate edit status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestPiToolExecBash_UsesNonLoginShell(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)

	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	app := newTestApp(t, sessions, store)
	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/exec_bash", strings.NewReader(`{"command":"if shopt -q login_shell; then echo login; else echo non-login; fi"}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("exec_bash status = %d body = %s", rr.Code, rr.Body.String())
	}
	var resp toolResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("result type = %T", resp.Result)
	}
	if got := result["stdout"]; got != "non-login\n" {
		t.Fatalf("stdout = %#v, want non-login", got)
	}
}

func TestPiToolExecBash_ValidatesRequestWithoutSpawning(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)

	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	app := newTestApp(t, sessions, store)
	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/exec_bash", strings.NewReader(`{"command":""}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("exec_bash validation status = %d body = %s", rr.Code, rr.Body.String())
	}
}
