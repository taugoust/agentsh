package api

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

func newDetachedRuntimeFixture(t *testing.T, stateDir, sessionID, workspace string) *detached.Runtime {
	t.Helper()
	envFile := filepath.Join(stateDir, "supervisor.env")
	if err := os.WriteFile(envFile, []byte("AGENTSH_DETACHED_EVENT_TOKEN=\"test-token\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	realPaths := true
	request := types.CreateSessionRequest{
		ID: sessionID, Workspace: workspace, Policy: "default",
		WorkspaceMode: string(types.WorkspaceModeDirect), RealPaths: &realPaths,
	}
	manifest := detached.NewRecoveryManifest(sessionID, request, detached.LaunchSpec{
		Executable: filepath.Join(stateDir, "agentsh"), WorkingDir: workspace,
		EnvironmentFile: envFile, LogFile: filepath.Join(stateDir, "supervisor.log"),
	}, time.Now().UTC())
	if err := detached.WriteRecoveryManifest(stateDir, manifest); err != nil {
		t.Fatal(err)
	}
	if err := detached.WriteMetadata(stateDir, detached.Metadata{
		SessionID: sessionID, ID: sessionID, State: detached.LifecycleProvisioning,
		SupervisorSock: filepath.Join(stateDir, "supervisor.sock"), ProtocolVersion: detached.ProtocolVersion,
	}); err != nil {
		t.Fatal(err)
	}
	runtime, err := detached.BeginRuntime(stateDir, 100, "start-1", "boot-1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func TestNethelperRebind_DetachedBootstrapRehydratesExactSessionAndInterruptedEvidence(t *testing.T) {
	t.Setenv(detached.EnvNetworkEnforcementRequested, string(detached.NetworkEnforcementRequestNone))
	root := t.TempDir()
	sessionID := "session-exact-recovery"
	stateDir := filepath.Join(root, sessionID)
	workspace := filepath.Join(root, "workspace")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}

	runtimeOne := newDetachedRuntimeFixture(t, stateDir, sessionID, workspace)
	sqliteStore := newSQLiteStore(t)
	store := composite.New(sqliteStore, sqliteStore)
	appOne := newTestApp(t, session.NewManager(1), store)
	appOne.cfg.Sessions.WorkspaceShadow.BaseDir = filepath.Join(stateDir, "workspace-state")
	appOne.SetDetachedRuntime(runtimeOne)
	first, _, err := appOne.BootstrapDetachedSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != sessionID || first.Workspace != workspace {
		t.Fatalf("first bootstrap = %+v", first)
	}
	if err := runtimeOne.UpdateMutable(detached.MutableSessionState{Cwd: workspace, Environment: map[string]string{"PATH": "/nix/store/test/bin"}}); err != nil {
		t.Fatal(err)
	}
	firstSession, ok := appOne.sessions.Get(sessionID)
	if !ok {
		t.Fatal("first session missing")
	}
	artifact, err := firstSession.WriteOutputArtifact("completed", strings.NewReader("durable output"))
	if err != nil {
		t.Fatal(err)
	}
	if err := runtimeOne.RecordCommand(detached.InflightCommand{CommandID: "cmd-interrupted", Operation: "exec", AdmittedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := runtimeOne.MarkCommandStarted("cmd-interrupted", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	runtimeTwo, err := detached.BeginRuntime(stateDir, 200, "start-2", "boot-1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	appTwo := newTestApp(t, session.NewManager(1), store)
	appTwo.cfg.Sessions.WorkspaceShadow.BaseDir = filepath.Join(stateDir, "workspace-state")
	appTwo.SetDetachedRuntime(runtimeTwo)
	second, _, err := appTwo.BootstrapDetachedSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID || !second.CreatedAt.Equal(first.CreatedAt) || second.Workspace != first.Workspace {
		t.Fatalf("recovered session changed identity\nfirst:  %+v\nsecond: %+v", first, second)
	}
	recoveredSession, ok := appTwo.sessions.Get(sessionID)
	if !ok {
		t.Fatal("recovered session missing")
	}
	cwd, environment, _ := recoveredSession.GetCwdEnvHistory()
	if cwd != workspace || environment["PATH"] != "/nix/store/test/bin" {
		t.Fatalf("recovered mutable state cwd=%q env=%#v", cwd, environment)
	}
	artifactFile, _, err := recoveredSession.OpenOutputArtifact(artifact.Path)
	if err != nil {
		t.Fatalf("open restored output artifact: %v", err)
	}
	_ = artifactFile.Close()
	events, err := store.QueryEvents(context.Background(), types.EventQuery{SessionID: sessionID, CommandID: "cmd-interrupted", Limit: 20, Asc: true})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Type == "command_interrupted" && event.TerminationReason == "supervisor_restart" && event.Fields["retryable"] == false {
			found = true
		}
	}
	if !found {
		t.Fatalf("interrupted terminal evidence missing: %+v", events)
	}
}
