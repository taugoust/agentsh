package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/go-chi/chi/v5"
)

func TestCancelExecBashToolCancelsExactActiveRequest(t *testing.T) {
	app := &App{}
	requestID := "11111111-1111-4111-8111-111111111111"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !app.registerExecCancellation("session-one", requestID, cancel) {
		t.Fatal("register exact exec cancellation failed")
	}
	if app.registerExecCancellation("session-one", requestID, func() {}) {
		t.Fatal("duplicate active request ID was accepted")
	}

	route := chi.NewRouter()
	route.Post("/sessions/{id}/tools/exec_bash/{requestID}/cancel", app.cancelExecBashTool)
	rr := httptest.NewRecorder()
	route.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/sessions/session-one/tools/exec_bash/"+requestID+"/cancel", nil))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("cancel status = %d body=%s", rr.Code, rr.Body.String())
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("exact exec context was not cancelled")
	}
	app.unregisterExecCancellation("session-one", requestID)

	rr = httptest.NewRecorder()
	route.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/sessions/session-one/tools/exec_bash/"+requestID+"/cancel", nil))
	if rr.Code != http.StatusAccepted || !strings.Contains(rr.Body.String(), `"cancelled":false`) {
		t.Fatalf("idempotent completed cancellation = %d %s", rr.Code, rr.Body.String())
	}
}

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
	var editResp toolResponse
	if err := json.NewDecoder(rr.Body).Decode(&editResp); err != nil {
		t.Fatal(err)
	}
	editResult, ok := editResp.Result.(map[string]any)
	if !ok {
		t.Fatalf("edit result type = %T", editResp.Result)
	}
	diff, ok := editResult["diff"].(string)
	if !ok || !strings.Contains(diff, "-hello world") || !strings.Contains(diff, "+hello agentsh") {
		t.Fatalf("edit diff = %#v", editResult["diff"])
	}
	details, ok := editResult["details"].(map[string]any)
	if !ok || details["diff"] != diff {
		t.Fatalf("edit details = %#v, want matching diff", editResult["details"])
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

func TestPiToolErrorsExposeStableDomainCodes(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	workspace := t.TempDir()
	sess, err := sessions.Create(workspace, "default")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "dup.txt"), []byte("x x"), 0o600); err != nil {
		t.Fatal(err)
	}
	handler := newTestApp(t, sessions, store).Router()

	for _, tc := range []struct {
		name       string
		url        string
		body       string
		wantStatus int
		wantCode   string
		wantPath   string
	}{
		{name: "missing file", url: "/api/v1/sessions/" + sess.ID + "/tools/read_file", body: `{"path":"missing.txt"}`, wantStatus: http.StatusNotFound, wantCode: toolErrorFileNotFound, wantPath: "/workspace/missing.txt"},
		{name: "missing session", url: "/api/v1/sessions/session-missing/tools/read_file", body: `{"path":"missing.txt"}`, wantStatus: http.StatusNotFound, wantCode: toolErrorSessionNotFound, wantPath: "missing.txt"},
		{name: "edit conflict", url: "/api/v1/sessions/" + sess.ID + "/tools/edit_file", body: `{"path":"dup.txt","oldText":"x","newText":"y"}`, wantStatus: http.StatusConflict, wantCode: toolErrorEditConflict, wantPath: "/workspace/dup.txt"},
		{name: "invalid request", url: "/api/v1/sessions/" + sess.ID + "/tools/read_file", body: `{`, wantStatus: http.StatusBadRequest, wantCode: toolErrorInvalidRequest},
		{name: "unsupported endpoint", url: "/api/v1/sessions/" + sess.ID + "/tools/not_a_tool", body: `{}`, wantStatus: http.StatusNotFound, wantCode: toolErrorUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, tc.url, strings.NewReader(tc.body)))
			if recorder.Code != tc.wantStatus {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			var response toolResponse
			if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
				t.Fatal(err)
			}
			if response.OK || response.Code != tc.wantCode || response.Path != tc.wantPath || response.ErrorID == "" {
				t.Fatalf("domain error=%+v", response)
			}
			if strings.Contains(recorder.Body.String(), workspace) {
				t.Fatalf("error leaked real workspace path: %s", recorder.Body.String())
			}
		})
	}

	for _, tc := range []struct {
		message string
		want    string
	}{
		{message: "operation denied by policy rule read", want: toolErrorPolicyDenied},
		{message: "operation denied by approval", want: toolErrorApprovalDenied},
	} {
		recorder := httptest.NewRecorder()
		writeToolError(recorder, http.StatusForbidden, tc.message)
		var response toolResponse
		if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
			t.Fatal(err)
		}
		if response.Code != tc.want {
			t.Fatalf("message=%q code=%q want=%q", tc.message, response.Code, tc.want)
		}
	}
}

func TestCommandTimeoutPiToolExecBashBoundsQueuedRequests(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	sess, err := sessions.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := sess.AcquireExecution(context.Background(), session.ExecutionAdmission{CommandID: "held"})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()

	app := newTestApp(t, sessions, store)
	rr := httptest.NewRecorder()
	body := `{"command":"printf should-not-run","queue_timeout_ms":20}`
	started := time.Now()
	app.Router().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/exec_bash", strings.NewReader(body)))
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("queued exec_bash returned after %v", elapsed)
	}
	if rr.Code != http.StatusRequestTimeout {
		t.Fatalf("exec_bash status = %d body = %s", rr.Code, rr.Body.String())
	}
	var wire struct {
		Result struct {
			CommandStarted bool               `json:"command_started"`
			Outcome        *types.ExecOutcome `json:"outcome"`
		} `json:"result"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&wire); err != nil {
		t.Fatal(err)
	}
	if wire.Result.CommandStarted || wire.Result.Outcome == nil || wire.Result.Outcome.Code != "E_QUEUE_TIMEOUT" || !wire.Result.Outcome.Retryable {
		t.Fatalf("queue outcome = %+v", wire.Result)
	}
}

func TestPiToolExecBashExplicitCancellationInterruptsAdmission(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	sess, err := sessions.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := sess.AcquireExecution(context.Background(), session.ExecutionAdmission{CommandID: "held"})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()

	app := newTestApp(t, sessions, store)
	requestID := "22222222-2222-4222-8222-222222222222"
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		body := strings.NewReader(`{"request_id":"` + requestID + `","command":"printf should-not-run"}`)
		app.Router().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/exec_bash", body))
	}()

	deadline := time.Now().Add(time.Second)
	for {
		app.execCancellationMu.Lock()
		_, active := app.execCancellations[execCancellationKey(sess.ID, requestID)]
		app.execCancellationMu.Unlock()
		if active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("exec_bash did not publish its cancellation identity")
		}
		time.Sleep(time.Millisecond)
	}
	cancelResponse := httptest.NewRecorder()
	app.Router().ServeHTTP(cancelResponse, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/exec_bash/"+requestID+"/cancel", nil))
	if cancelResponse.Code != http.StatusAccepted {
		t.Fatalf("cancel status = %d body=%s", cancelResponse.Code, cancelResponse.Body.String())
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("explicit cancellation did not interrupt queued exec_bash")
	}
	if strings.Contains(rr.Body.String(), "should-not-run") && rr.Code == http.StatusOK {
		t.Fatalf("cancelled queued command executed: %s", rr.Body.String())
	}
}

func TestPiToolExecBashWaitsForAdmissionByDefault(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	sess, err := sessions.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := sess.AcquireExecution(context.Background(), session.ExecutionAdmission{CommandID: "held"})
	if err != nil {
		t.Fatal(err)
	}

	app := newTestApp(t, sessions, store)
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		body := strings.NewReader(`{"command":"printf admitted"}`)
		app.Router().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/exec_bash", body))
	}()

	select {
	case <-done:
		t.Fatal("exec_bash returned while execution admission was held")
	case <-time.After(50 * time.Millisecond):
	}
	lease.Release()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("exec_bash did not run after execution admission was released")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("exec_bash status = %d body = %s", rr.Code, rr.Body.String())
	}
	var response struct {
		OK     bool `json:"ok"`
		Result struct {
			Stdout string `json:"stdout"`
		} `json:"result"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.Result.Stdout != "admitted" {
		t.Fatalf("exec_bash response = %+v", response)
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

func TestPiToolExecBash_PreExecFailureIsPromotedAndNotStarted(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("strict command jail is Linux-only")
	}
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	workspace := t.TempDir()
	sess, err := sessions.Create(workspace, "default")
	if err != nil {
		t.Fatal(err)
	}
	app := newTestApp(t, sessions, store)
	app.cfg.Sandbox.Network.EBPF.Enforce = true
	app.cfg.Sandbox.UnixSockets.WrapperBin = filepath.Join(t.TempDir(), "missing-wrapper")
	marker := filepath.Join(workspace, "must-not-exist")
	body, _ := json.Marshal(map[string]string{"command": "printf ran > " + marker})
	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/exec_bash", strings.NewReader(string(body))))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var wire struct {
		OK     bool `json:"ok"`
		Result struct {
			CommandStarted bool               `json:"command_started"`
			Error          *types.ExecError   `json:"error"`
			Outcome        *types.ExecOutcome `json:"outcome"`
		} `json:"result"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&wire); err != nil {
		t.Fatal(err)
	}
	if wire.OK || wire.Result.CommandStarted || wire.Result.Error == nil || wire.Result.Outcome == nil || wire.Result.Outcome.FailureKind != types.ExecFailurePreExec {
		t.Fatalf("result=%+v", wire.Result)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("marker exists after pre-exec refusal: %v", err)
	}
}

func TestPiToolExecBash_ChildExit127IsStartedNotPreExec(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash integration requires a POSIX shell")
	}
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	sess, err := sessions.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}
	app := newTestApp(t, sessions, store)
	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/exec_bash", strings.NewReader(`{"command":"exit 127"}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var wire struct {
		Result struct {
			ExitCode       int                `json:"exit_code"`
			CommandStarted bool               `json:"command_started"`
			Error          *types.ExecError   `json:"error"`
			Outcome        *types.ExecOutcome `json:"outcome"`
		} `json:"result"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&wire); err != nil {
		t.Fatal(err)
	}
	if wire.Result.ExitCode != 127 || !wire.Result.CommandStarted || wire.Result.Error != nil || wire.Result.Outcome == nil || wire.Result.Outcome.FailureKind != types.ExecFailureChildExit {
		t.Fatalf("result=%+v", wire.Result)
	}
}

func TestPiToolExecBash_RemoteArtifactRetainsBeyondResponseCap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash artifact integration requires a POSIX shell")
	}
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
	runtimeRoot := filepath.Join(t.TempDir(), "runtime")
	runtimeHome := filepath.Join(runtimeRoot, "home")
	runtimeTmp := filepath.Join(runtimeRoot, "tmp")
	for _, dir := range []string{runtimeHome, runtimeTmp} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sess.SetRuntimePaths(runtimeHome, runtimeTmp, nil)
	if err := sess.ConfigureOutputArtifacts(4 * 1024 * 1024); err != nil {
		t.Fatal(err)
	}

	app := newTestApp(t, sessions, store)
	body := `{"command":"yes x | head -c 2200000","persist_output_over_bytes":51200,"persist_output_over_lines":200}`
	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/exec_bash", strings.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("exec_bash status = %d body = %.1000s", rr.Code, rr.Body.String())
	}
	var resp toolResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("result type = %T", resp.Result)
	}
	path, _ := result["full_output_path"].(string)
	if path == "" {
		t.Fatalf("missing remote full_output_path: %#v", result)
	}
	if got := int64(result["artifact_total_bytes"].(float64)); got != 2_200_000 {
		t.Fatalf("artifact total bytes = %d", got)
	}
	if got := int64(result["artifact_bytes"].(float64)); got != 2_200_000 {
		t.Fatalf("artifact bytes = %d", got)
	}
	if complete, _ := result["artifact_complete"].(bool); !complete {
		t.Fatalf("artifact unexpectedly incomplete: %#v", result)
	}
	if truncated, _ := result["stdout_truncated"].(bool); !truncated {
		t.Fatalf("2.2 MiB stdout did not cross 2 MiB response cap: %#v", result)
	}
	stdout, _ := result["stdout"].(string)
	if len(stdout) != defaultMaxOutputBytes {
		t.Fatalf("retained response stdout = %d bytes, want %d", len(stdout), defaultMaxOutputBytes)
	}
	if got := int64(result["stdout_total_bytes"].(float64)); got != 2_200_000 {
		t.Fatalf("stdout total bytes = %d", got)
	}
	commandID, _ := result["command_id"].(string)
	stored, storedTotal, storedTruncated, err := store.ReadOutputChunk(context.Background(), commandID, "stdout", 0, 3*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != defaultMaxOutputBytes || storedTotal != 2_200_000 || !storedTruncated {
		t.Fatalf("stored capture len=%d total=%d truncated=%v", len(stored), storedTotal, storedTruncated)
	}
	if info, err := os.Stat(path); err != nil || info.Size() != 2_200_000 {
		t.Fatalf("remote artifact stat = %v, err=%v", info, err)
	}

	readBody, _ := json.Marshal(map[string]string{"path": path})
	readRecorder := httptest.NewRecorder()
	app.Router().ServeHTTP(readRecorder, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/read_file", strings.NewReader(string(readBody))))
	if readRecorder.Code != http.StatusOK {
		t.Fatalf("registered artifact read status = %d body = %s", readRecorder.Code, readRecorder.Body.String())
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

func TestPiToolReadFile_ShadowAllowsOnlyExactRegisteredOutputArtifact(t *testing.T) {
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
	sess.WorkspaceMode = string(types.WorkspaceModeShadow)
	runtimeRoot := filepath.Join(t.TempDir(), "runtime")
	runtimeHome := filepath.Join(runtimeRoot, "home")
	runtimeTmp := filepath.Join(runtimeRoot, "tmp")
	for _, dir := range []string{runtimeHome, runtimeTmp} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sess.SetRuntimePaths(runtimeHome, runtimeTmp, nil)
	if err := sess.ConfigureOutputArtifacts(1024); err != nil {
		t.Fatal(err)
	}
	artifact, err := sess.WriteOutputArtifact("stdout", strings.NewReader("remote output"))
	if err != nil {
		t.Fatal(err)
	}
	unregistered := filepath.Join(runtimeTmp, "unregistered.log")
	if err := os.WriteFile(unregistered, []byte("must stay private"), 0o600); err != nil {
		t.Fatal(err)
	}

	app := newTestApp(t, sessions, store)
	h := app.Router()
	postRead := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(map[string]string{"path": path})
		if err != nil {
			t.Fatal(err)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/read_file", strings.NewReader(string(body))))
		return rr
	}

	rr := postRead(artifact.Path)
	if rr.Code != http.StatusOK {
		t.Fatalf("registered artifact status = %d body = %s", rr.Code, rr.Body.String())
	}
	var resp toolResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok || result["content"] != "remote output" {
		t.Fatalf("registered artifact result = %#v", resp.Result)
	}

	for _, path := range []string{unregistered, filepath.Dir(artifact.Path), artifact.Path + ".other"} {
		rr = postRead(path)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("unregistered path %q status = %d body = %s", path, rr.Code, rr.Body.String())
		}
	}

	writeBody, err := json.Marshal(map[string]string{"path": artifact.Path, "content": "replace"})
	if err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/write_file", strings.NewReader(string(writeBody))))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("artifact write status = %d body = %s", rr.Code, rr.Body.String())
	}

	editBody, err := json.Marshal(map[string]string{"path": artifact.Path, "oldText": "remote", "newText": "local"})
	if err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/edit_file", strings.NewReader(string(editBody))))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("artifact edit status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestDefaultMaxOutputBytes_IsTwoMiB(t *testing.T) {
	const want = 2 * 1024 * 1024
	if defaultMaxOutputBytes != want {
		t.Fatalf("defaultMaxOutputBytes = %d, want %d", defaultMaxOutputBytes, want)
	}
}
