package api

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestReapExpiredSessions_DetachedSessionCommitsStoppingBeforeRemoval(t *testing.T) {
	manager := session.NewManager(1)
	sess, runtimeState, stateDir := newDetachedExpiryFixture(t, manager)
	app := &App{sessions: manager}
	app.SetDetachedRuntime(runtimeState)

	result := app.ReapExpiredSessionsWithResult(sess.CreatedAt.Add(2*time.Hour), time.Hour, 0)
	if result.Err != nil {
		t.Fatalf("ReapExpiredSessionsWithResult: %v", result.Err)
	}
	if !result.DetachedSupervisorExpired {
		t.Fatal("detached supervisor expiry was not reported")
	}
	if len(result.Sessions) != 1 || result.Sessions[0].ID != sess.ID {
		t.Fatalf("reaped sessions = %+v, want %s", result.Sessions, sess.ID)
	}
	if _, ok := manager.Get(sess.ID); ok {
		t.Fatal("expired detached session remains installed")
	}

	status := runtimeState.RuntimeStatus()
	if status.LifecycleState != detached.LifecycleStopping || status.Recoverable {
		t.Fatalf("runtime status = %+v, want stopping and non-recoverable", status)
	}
	manifest, err := detached.ReadRecoveryManifest(stateDir)
	if err != nil {
		t.Fatalf("ReadRecoveryManifest: %v", err)
	}
	if manifest.State != detached.LifecycleStopping {
		t.Fatalf("durable manifest state = %q, want stopping", manifest.State)
	}
	meta, _, err := detached.ReadMetadataFromRoot(filepath.Dir(stateDir), sess.ID)
	if err != nil {
		t.Fatalf("ReadMetadataFromRoot: %v", err)
	}
	if meta.State != detached.LifecycleStopping {
		t.Fatalf("durable metadata state = %q, want stopping", meta.State)
	}
}

func TestReapExpiredSessions_DurableStoppingFailureRetainsSession(t *testing.T) {
	manager := session.NewManager(1)
	sess, runtimeState, stateDir := newDetachedExpiryFixture(t, manager)
	app := &App{sessions: manager}
	app.SetDetachedRuntime(runtimeState)

	if err := os.RemoveAll(stateDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stateDir, []byte("blocks lifecycle persistence\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result := app.ReapExpiredSessionsWithResult(sess.CreatedAt.Add(2*time.Hour), time.Hour, 0)
	if result.Err == nil || !strings.Contains(result.Err.Error(), "persist detached session expiry") {
		t.Fatalf("expiry error = %v, want durable transition failure", result.Err)
	}
	if result.DetachedSupervisorExpired || len(result.Sessions) != 0 {
		t.Fatalf("expiry committed despite persistence failure: %+v", result)
	}
	if _, ok := manager.Get(sess.ID); !ok {
		t.Fatal("session was removed after durable stopping failure")
	}
}

func TestDestroySession_SignalsDetachedSupervisorShutdown(t *testing.T) {
	manager := session.NewManager(1)
	sess, runtimeState, _ := newDetachedExpiryFixture(t, manager)
	app := &App{
		sessions:       manager,
		store:          composite.New(memEventStore{}, nil),
		broker:         events.NewBroker(),
		detachedStopCh: make(chan struct{}),
	}
	app.SetDetachedRuntime(runtimeState)
	stopCh := app.DetachedStopSignal()

	req := httptest.NewRequest("DELETE", "/api/v1/sessions/"+sess.ID, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", sess.ID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()
	app.destroySession(rr, req)

	if rr.Code != 204 {
		t.Fatalf("destroy status = %d, body %s", rr.Code, rr.Body.String())
	}
	select {
	case <-stopCh:
	default:
		t.Fatal("explicit detached session destroy did not signal supervisor shutdown")
	}
	if _, ok := manager.Get(sess.ID); ok {
		t.Fatal("destroyed detached session remains installed")
	}
	if status := runtimeState.RuntimeStatus(); status.LifecycleState != detached.LifecycleStopped || status.Recoverable {
		t.Fatalf("runtime status = %+v, want stopped and non-recoverable", status)
	}
}

func TestDetachedRuntimeStatus_FailsClosedWhenExactSessionIsAbsent(t *testing.T) {
	manager := session.NewManager(1)
	sess, runtimeState, _ := newDetachedExpiryFixture(t, manager)
	app := &App{sessions: manager}
	app.SetDetachedRuntime(runtimeState)
	if !manager.Destroy(sess.ID) {
		t.Fatal("failed to remove fixture session")
	}

	status := app.detachedRuntimeStatus()
	if status.LifecycleState != detached.LifecycleFailed || status.Recoverable {
		t.Fatalf("status = %+v, want failed and non-recoverable", status)
	}
	if !strings.Contains(status.LastError, "exact session is absent") {
		t.Fatalf("last_error = %q", status.LastError)
	}
}

func newDetachedExpiryFixture(t *testing.T, manager *session.Manager) (*session.Session, *detached.Runtime, string) {
	t.Helper()
	workspace := t.TempDir()
	sessionID := "session-" + uuid.NewString()
	sess, err := manager.CreateWithID(sessionID, workspace, "default")
	if err != nil {
		t.Fatalf("CreateWithID: %v", err)
	}
	createdAt := time.Now().UTC().Add(-2 * time.Hour)
	sess.CreatedAt = createdAt
	sess.LastActivity = createdAt

	root := t.TempDir()
	stateDir := filepath.Join(root, sessionID)
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(stateDir, "supervisor.env")
	if err := os.WriteFile(envFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	req := types.CreateSessionRequest{
		ID: sessionID, Workspace: workspace, Policy: "default",
		WorkspaceMode: string(types.WorkspaceModeDirect),
	}
	manifest := detached.NewRecoveryManifest(sessionID, req, detached.LaunchSpec{
		Executable: executable, WorkingDir: workspace, EnvironmentFile: envFile,
		LogFile: filepath.Join(stateDir, "supervisor.log"),
	}, createdAt)
	if err := detached.WriteRecoveryManifest(stateDir, manifest); err != nil {
		t.Fatalf("WriteRecoveryManifest: %v", err)
	}
	if err := detached.WriteMetadata(stateDir, detached.Metadata{
		SessionID: sessionID, ID: sessionID, CreatedAt: createdAt,
		State: detached.LifecycleProvisioning, Policy: "default",
		RealWorkspace: workspace, WorkspaceMode: string(types.WorkspaceModeDirect),
		SupervisorSock:  filepath.Join(stateDir, "supervisor.sock"),
		ProtocolVersion: detached.ProtocolVersion,
	}); err != nil {
		t.Fatalf("WriteMetadata: %v", err)
	}
	runtimeState, err := detached.BeginRuntime(stateDir, os.Getpid(), "test-start", "test-boot", createdAt)
	if err != nil {
		t.Fatalf("BeginRuntime: %v", err)
	}
	if err := runtimeState.MarkReady(sess.Snapshot(), "test-policy-digest", nil); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}
	return sess, runtimeState, stateDir
}
