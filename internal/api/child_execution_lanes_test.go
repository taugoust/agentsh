package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

func newChildLaneTest(t *testing.T, concurrency int) (*App, *session.Session, http.Handler) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("shared child execution lanes currently require Linux peer/process identity")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("exec_bash requires bash")
	}
	st := newSQLiteStore(t)
	manager := session.NewManager(4)
	sess, err := manager.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}
	app := newTestApp(t, manager, composite.New(st, st))
	app.cfg.Sessions.Subagents.MaxExecConcurrency = concurrency
	return app, sess, MarkUnixSocketRequests(app.Router())
}

func activeChildCapabilityForTest(t *testing.T, app *App, sess *session.Session, lane string) *childCapabilityHandle {
	t.Helper()
	handle, err := app.mintChildCapability(sess.ID, lane)
	if err != nil {
		t.Fatal(err)
	}
	pgid := getProcessGroupID(os.Getpid())
	if pgid <= 0 {
		pgid = os.Getpid()
	}
	if err := app.activateChildCapability(handle, os.Getpid(), pgid); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.revokeChildCapability(handle, errChildCapabilityRevoked) })
	return handle
}

func childExecRequest(ctx context.Context, sessionID, token, command string) *http.Request {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = context.WithValue(ctx, ctxKeyUnixSocket, true)
	ctx = context.WithValue(ctx, ctxKeyUnixPeer, unixHTTPPeer{PID: os.Getpid(), Supported: true})
	body, _ := json.Marshal(execBashToolRequest{Command: command})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sessionID+"/tools/exec_bash", strings.NewReader(string(body))).WithContext(ctx)
	req.Header.Set(childCapabilityHeader, token)
	return req
}

func runChildExec(handler http.Handler, req *http.Request) <-chan *httptest.ResponseRecorder {
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		result <- recorder
	}()
	return result
}

func waitForChildLanePath(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", path)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitForActiveExecutions(t *testing.T, sess *session.Session, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if got := sess.ActiveExecutionCount(); got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("active executions = %d, want %d", sess.ActiveExecutionCount(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitForExecutionQueueDepth(t *testing.T, sess *session.Session, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if got := sess.ExecutionQueueDepth(); got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("execution queue depth = %d, want %d", sess.ExecutionQueueDepth(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitForStartedMarkers(t *testing.T, markers []string, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		started := 0
		for _, marker := range markers {
			if _, err := os.Stat(marker); err == nil {
				started++
			}
		}
		if started == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("started command markers = %d, want %d", started, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func releaseMarkerCommand(started, release string) string {
	return "printf started > " + started + "; while [ ! -e " + release + " ]; do sleep 0.01; done"
}

func requireChildExecOK(t *testing.T, result <-chan *httptest.ResponseRecorder) {
	t.Helper()
	select {
	case recorder := <-result:
		if recorder.Code != http.StatusOK {
			t.Fatalf("exec_bash status = %d body = %s", recorder.Code, recorder.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exec_bash did not finish")
	}
}

func TestChildExecutionLanes_DifferentAuthenticatedChildrenOverlap(t *testing.T) {
	app, sess, handler := newChildLaneTest(t, 2)
	first := activeChildCapabilityForTest(t, app, sess, "subagent-a")
	second := activeChildCapabilityForTest(t, app, sess, "subagent-b")
	if !app.childSharedExecutionSupported(sess, &childCapabilityClaim{peerBound: true, stablePID: true}) {
		t.Fatal("minimal Linux test configuration unexpectedly rejected shared execution")
	}

	dir := t.TempDir()
	release := filepath.Join(dir, "release")
	startedA := filepath.Join(dir, "started-a")
	startedB := filepath.Join(dir, "started-b")
	t.Cleanup(func() { _ = os.WriteFile(release, nil, 0o600) })

	resultA := runChildExec(handler, childExecRequest(context.Background(), sess.ID, first.token, releaseMarkerCommand(startedA, release)))
	resultB := runChildExec(handler, childExecRequest(context.Background(), sess.ID, second.token, releaseMarkerCommand(startedB, release)))
	waitForChildLanePath(t, startedA)
	waitForChildLanePath(t, startedB)
	waitForActiveExecutions(t, sess, 2)
	if got := sess.Snapshot().State; got != types.SessionStateBusy {
		t.Fatalf("session state = %q, want busy", got)
	}
	if current := sess.CurrentCommandID(); current != "" {
		t.Fatalf("shared execution overwrote singleton current command with %q", current)
	}

	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	requireChildExecOK(t, resultA)
	requireChildExecOK(t, resultB)
	waitForActiveExecutions(t, sess, 0)
	if got := sess.Snapshot().State; got != types.SessionStateReady {
		t.Fatalf("session state after both commands = %q, want ready", got)
	}
}

func TestChildExecutionLanes_SameCapabilitySerializes(t *testing.T) {
	app, sess, handler := newChildLaneTest(t, 2)
	capability := activeChildCapabilityForTest(t, app, sess, "subagent-a")

	dir := t.TempDir()
	release := filepath.Join(dir, "release")
	startedA := filepath.Join(dir, "started-a")
	startedB := filepath.Join(dir, "started-b")
	t.Cleanup(func() { _ = os.WriteFile(release, nil, 0o600) })
	first := runChildExec(handler, childExecRequest(context.Background(), sess.ID, capability.token, releaseMarkerCommand(startedA, release)))
	waitForChildLanePath(t, startedA)
	second := runChildExec(handler, childExecRequest(context.Background(), sess.ID, capability.token, "printf started > "+startedB))

	waitForExecutionQueueDepth(t, sess, 1)
	waitForActiveExecutions(t, sess, 1)
	if _, err := os.Stat(startedB); err == nil {
		t.Fatal("same-lane command started before its predecessor released")
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	requireChildExecOK(t, first)
	requireChildExecOK(t, second)
	waitForChildLanePath(t, startedB)
}

func TestChildExecutionLanes_AggregateCap(t *testing.T) {
	app, sess, handler := newChildLaneTest(t, 2)
	capabilities := []*childCapabilityHandle{
		activeChildCapabilityForTest(t, app, sess, "subagent-a"),
		activeChildCapabilityForTest(t, app, sess, "subagent-b"),
		activeChildCapabilityForTest(t, app, sess, "subagent-c"),
	}
	dir := t.TempDir()
	release := filepath.Join(dir, "release")
	markers := []string{filepath.Join(dir, "a"), filepath.Join(dir, "b"), filepath.Join(dir, "c")}
	t.Cleanup(func() { _ = os.WriteFile(release, nil, 0o600) })
	results := make([]<-chan *httptest.ResponseRecorder, 3)
	for i := range capabilities {
		results[i] = runChildExec(handler, childExecRequest(context.Background(), sess.ID, capabilities[i].token, releaseMarkerCommand(markers[i], release)))
	}
	waitForActiveExecutions(t, sess, 2)
	waitForExecutionQueueDepth(t, sess, 1)
	waitForStartedMarkers(t, markers, 2)
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, result := range results {
		requireChildExecOK(t, result)
	}
	for _, marker := range markers {
		waitForChildLanePath(t, marker)
	}
}

func TestChildExecutionCapability_ForgedWrongProcessAndRevokedAreRejected(t *testing.T) {
	app, sess, handler := newChildLaneTest(t, 2)
	capability := activeChildCapabilityForTest(t, app, sess, "subagent-a")

	assertCode := func(name, token string, peerPID int, want string) {
		t.Helper()
		ctx := context.WithValue(context.Background(), ctxKeyUnixPeer, unixHTTPPeer{PID: peerPID, Supported: true})
		req := childExecRequest(ctx, sess.ID, token, "true")
		// childExecRequest installs the normal test PID; replace it for the
		// wrong-process case.
		req = req.WithContext(context.WithValue(req.Context(), ctxKeyUnixPeer, unixHTTPPeer{PID: peerPID, Supported: true}))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("%s status = %d body = %s", name, recorder.Code, recorder.Body.String())
		}
		var response toolResponse
		if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
			t.Fatal(err)
		}
		if response.Code != want {
			t.Fatalf("%s code = %q, want %q", name, response.Code, want)
		}
	}

	forged := base64.RawURLEncoding.EncodeToString(make([]byte, childCapabilityBytes))
	assertCode("forged", forged, os.Getpid(), toolErrorChildCapabilityInvalid)
	assertCode("wrong process", capability.token, os.Getpid()+1, toolErrorChildCapabilityInvalid)
	app.revokeChildCapability(capability, errChildCapabilityRevoked)
	assertCode("revoked", capability.token, os.Getpid(), toolErrorChildCapabilityRevoked)
}

func TestChildExecutionCapability_RevocationCancelsTypedQueuedRequest(t *testing.T) {
	app, sess, handler := newChildLaneTest(t, 1)
	first := activeChildCapabilityForTest(t, app, sess, "subagent-a")
	second := activeChildCapabilityForTest(t, app, sess, "subagent-b")
	dir := t.TempDir()
	release := filepath.Join(dir, "release")
	started := filepath.Join(dir, "started")
	t.Cleanup(func() { _ = os.WriteFile(release, nil, 0o600) })

	active := runChildExec(handler, childExecRequest(context.Background(), sess.ID, first.token, releaseMarkerCommand(started, release)))
	waitForChildLanePath(t, started)
	queued := runChildExec(handler, childExecRequest(context.Background(), sess.ID, second.token, "true"))
	waitForExecutionQueueDepth(t, sess, 1)
	app.revokeChildCapability(second, errChildCapabilityRevoked)

	select {
	case recorder := <-queued:
		if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), "E_CHILD_CAPABILITY_REVOKED") {
			t.Fatalf("queued revocation status = %d body = %s", recorder.Code, recorder.Body.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("revoked queued request did not leave admission")
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	requireChildExecOK(t, active)
}

func TestChildExecutionLanes_StrictProxyConfigurationFallsBackToExclusive(t *testing.T) {
	app, sess, _ := newChildLaneTest(t, 4)
	capability := activeChildCapabilityForTest(t, app, sess, "subagent-a")
	request := childExecRequest(context.Background(), sess.ID, capability.token, "true")
	claim, err := app.authenticateChildCapability(request.Context(), request, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	app.cfg.Sandbox.Network.EBPF.Enforce = true
	if app.childSharedExecutionSupported(sess, claim) {
		t.Fatal("strict eBPF/proxy command was admitted to a shared lane")
	}
}

func TestChildExecutionCapability_IsScrubbedFromExecutedCommands(t *testing.T) {
	app, sess, handler := newChildLaneTest(t, 2)
	capability := activeChildCapabilityForTest(t, app, sess, "subagent-a")
	ctx := context.WithValue(context.Background(), ctxKeyUnixSocket, true)
	ctx = context.WithValue(ctx, ctxKeyUnixPeer, unixHTTPPeer{PID: os.Getpid(), Supported: true})
	body, err := json.Marshal(execBashToolRequest{
		Command: `test -z "$AGENTSH_CHILD_CAPABILITY"`,
		Env:     map[string]string{childCapabilityEnv: capability.token},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/exec_bash", strings.NewReader(string(body))).WithContext(ctx)
	request.Header.Set(childCapabilityHeader, capability.token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("credential scrub status = %d body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestChildExecutionCapability_SessionLifecycleRevokesClaim(t *testing.T) {
	app, sess, _ := newChildLaneTest(t, 2)
	capability := activeChildCapabilityForTest(t, app, sess, "subagent-a")
	request := childExecRequest(context.Background(), sess.ID, capability.token, "true")
	claim, err := app.authenticateChildCapability(request.Context(), request, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := claim.validate(); err != nil {
		t.Fatalf("live claim validation: %v", err)
	}
	app.revokeChildCapabilitiesForSession(sess.ID, errChildCapabilityRevoked)
	if err := claim.validate(); !errors.Is(err, errChildCapabilityRevoked) {
		t.Fatalf("claim after session revocation = %v", err)
	}
}

func TestChildExecutionCapability_ProcessIdentityChangeRevokesClaim(t *testing.T) {
	app, sess, _ := newChildLaneTest(t, 2)
	capability := activeChildCapabilityForTest(t, app, sess, "subagent-a")
	request := childExecRequest(context.Background(), sess.ID, capability.token, "true")
	claim, err := app.authenticateChildCapability(request.Context(), request, sess.ID)
	if err != nil {
		t.Fatal(err)
	}

	app.childCapabilityMu.Lock()
	record := app.childCapabilities[capability.digest]
	if record == nil || !record.stableProcessIdentity {
		app.childCapabilityMu.Unlock()
		t.Fatal("test capability has no stable process identity")
	}
	record.processStartIdentity = "reused-process-identity"
	app.childCapabilityMu.Unlock()
	if err := claim.validate(); !errors.Is(err, errChildCapabilityRevoked) {
		t.Fatalf("claim after process identity change = %v", err)
	}
}
