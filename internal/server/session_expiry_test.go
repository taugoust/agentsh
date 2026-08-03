package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

func TestServerRun_ExitsCleanlyWhenDetachedSessionExpires(t *testing.T) {
	dir := t.TempDir()
	policyDir := filepath.Join(dir, "policies")
	if err := os.Mkdir(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	policy := `version: 1
name: default
command_rules:
  - name: allow-all
    commands: ["*"]
    decision: allow
file_rules:
  - name: allow-all
    paths: ["/**"]
    operations: ["*"]
    decision: allow
`
	if err := os.WriteFile(filepath.Join(policyDir, "default.yaml"), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Server.HTTP.Addr = "127.0.0.1:0"
	cfg.Server.HTTP.ReadTimeout = "1s"
	cfg.Server.HTTP.WriteTimeout = "1s"
	cfg.Server.HTTP.MaxRequestSize = "1MB"
	cfg.Sessions.BaseDir = filepath.Join(dir, "sessions")
	cfg.Audit.Storage.SQLitePath = filepath.Join(dir, "events.db")
	cfg.Policies.Dir = policyDir
	cfg.Policies.Default = "default"
	cfg.Metrics.Enabled = false
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"

	srv, err := New(cfg)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skipf("listening not permitted in this environment: %v", err)
		}
		t.Fatal(err)
	}
	defer srv.Close()

	workspace := t.TempDir()
	sessionID := "session-" + uuid.NewString()
	sess, err := srv.sessions.CreateWithID(sessionID, workspace, "default")
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Now().UTC().Add(-time.Hour)
	sess.CreatedAt = createdAt
	sess.LastActivity = createdAt

	stateRoot := t.TempDir()
	stateDir := filepath.Join(stateRoot, sessionID)
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
		t.Fatal(err)
	}
	if err := detached.WriteMetadata(stateDir, detached.Metadata{
		SessionID: sessionID, ID: sessionID, CreatedAt: createdAt,
		State: detached.LifecycleProvisioning, Policy: "default",
		RealWorkspace: workspace, WorkspaceMode: string(types.WorkspaceModeDirect),
		SupervisorSock:  filepath.Join(stateDir, "supervisor.sock"),
		ProtocolVersion: detached.ProtocolVersion,
	}); err != nil {
		t.Fatal(err)
	}
	runtimeState, err := detached.BeginRuntime(stateDir, os.Getpid(), "test-start", "test-boot", createdAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtimeState.MarkReady(sess.Snapshot(), "test-policy-digest", nil); err != nil {
		t.Fatal(err)
	}
	srv.app.SetDetachedRuntime(runtimeState)
	srv.sessionTimeout = 30 * time.Minute
	srv.idleTimeout = 0
	srv.reapInterval = 5 * time.Millisecond

	runErr := make(chan error, 1)
	go func() {
		runErr <- srv.Run(context.Background())
	}()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned error after intentional expiry: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not exit after its exact detached session expired")
	}
	if _, ok := srv.sessions.Get(sessionID); ok {
		t.Fatal("expired session remains installed after Run exit")
	}
	if status := runtimeState.RuntimeStatus(); status.LifecycleState != detached.LifecycleStopping || status.Recoverable {
		t.Fatalf("runtime status after Run = %+v, want stopping and non-recoverable", status)
	}
}
