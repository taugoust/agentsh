package detached

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestReadTerminalRuntimeStatusFromRootRequiresExactDurableIdentity(t *testing.T) {
	root := t.TempDir()
	sessionID := "session-terminal"
	stateDir := filepath.Join(root, sessionID)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := NewRecoveryManifest(sessionID, types.CreateSessionRequest{ID: sessionID, Workspace: root}, LaunchSpec{
		Executable: filepath.Join(root, "agentsh"), WorkingDir: root,
		EnvironmentFile: filepath.Join(stateDir, "supervisor.env"), LogFile: filepath.Join(stateDir, "supervisor.log"),
	}, time.Now().UTC())
	manifest.State = LifecycleStopped
	manifest.Generation = 1
	manifest.IncarnationID = "11111111-1111-4111-8111-111111111111"
	if err := WriteRecoveryManifest(stateDir, manifest); err != nil {
		t.Fatal(err)
	}
	meta := Metadata{
		SessionID: sessionID, ID: sessionID, State: LifecycleStopped,
		ProtocolVersion: ProtocolVersion, Generation: manifest.Generation,
		IncarnationID: manifest.IncarnationID,
	}
	if err := WriteMetadata(stateDir, meta); err != nil {
		t.Fatal(err)
	}
	status, err := ReadTerminalRuntimeStatusFromRoot(root, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if status.SessionID != sessionID || status.LifecycleState != LifecycleStopped || status.Generation != 1 || status.IncarnationID != manifest.IncarnationID || status.Recoverable {
		t.Fatalf("terminal status = %+v", status)
	}

	manifest.State = LifecycleReady
	if err := WriteRecoveryManifest(stateDir, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTerminalRuntimeStatusFromRoot(root, sessionID); err == nil {
		t.Fatal("non-terminal manifest was accepted as stop evidence")
	}
	manifest.State = LifecycleStopped
	manifest.IncarnationID = "22222222-2222-4222-8222-222222222222"
	if err := WriteRecoveryManifest(stateDir, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTerminalRuntimeStatusFromRoot(root, sessionID); err == nil {
		t.Fatal("mismatched terminal incarnation was accepted as stop evidence")
	}
}

func TestRuntimeHeartbeatUsesAdvisoryRecordAndStopsAtTerminal(t *testing.T) {
	root := t.TempDir()
	sessionID := "session-heartbeat"
	stateDir := filepath.Join(root, sessionID)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(stateDir, "supervisor.env")
	if err := atomicWritePrivateFile(envFile, nil); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	req := types.CreateSessionRequest{ID: sessionID, Workspace: root, Policy: "default", WorkspaceMode: string(types.WorkspaceModeDirect)}
	manifest := NewRecoveryManifest(sessionID, req, LaunchSpec{
		Executable: filepath.Join(root, "agentsh"), WorkingDir: root,
		EnvironmentFile: envFile, LogFile: filepath.Join(stateDir, "supervisor.log"),
	}, now)
	if err := WriteRecoveryManifest(stateDir, manifest); err != nil {
		t.Fatal(err)
	}
	if err := WriteMetadata(stateDir, Metadata{
		SessionID: sessionID, ID: sessionID, State: LifecycleProvisioning,
		SupervisorSock: filepath.Join(stateDir, "supervisor.sock"), EventToken: "event-token", ProtocolVersion: ProtocolVersion,
	}); err != nil {
		t.Fatal(err)
	}
	runtimeState, err := BeginRuntime(stateDir, 101, "start", "boot", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtimeState.MarkReady(types.Session{
		ID: sessionID, CreatedAt: now, Workspace: root, WorkspaceMount: root,
		WorkspaceMode: string(types.WorkspaceModeDirect), Policy: "default",
	}, "policy-digest", nil); err != nil {
		t.Fatal(err)
	}

	before := runtimeState.RuntimeStatus().HeartbeatAt
	heartbeatAt := before.Add(time.Second)
	if err := runtimeState.Heartbeat(heartbeatAt); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(HeartbeatPath(stateDir))
	if err != nil {
		t.Fatalf("advisory heartbeat was not written: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("heartbeat permissions = %o, want 600", info.Mode().Perm())
	}

	data, err := readProtectedRegularFile(MetadataPath(stateDir), 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	var durable Metadata
	if err := json.Unmarshal(data, &durable); err != nil {
		t.Fatal(err)
	}
	if !durable.HeartbeatAt.Equal(before) {
		t.Fatalf("heartbeat rewrote durable metadata: got %s want %s", durable.HeartbeatAt, before)
	}
	merged, _, err := ReadMetadataFromRoot(root, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if !merged.HeartbeatAt.Equal(heartbeatAt) {
		t.Fatalf("merged heartbeat = %s, want %s", merged.HeartbeatAt, heartbeatAt)
	}

	if err := runtimeState.MarkStopping(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(HeartbeatPath(stateDir)); !os.IsNotExist(err) {
		t.Fatalf("terminal transition retained heartbeat: %v", err)
	}
	stoppingMeta, _, err := ReadMetadataFromRoot(root, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if stoppingMeta.EventToken != "" {
		t.Fatal("stopping metadata retained detached event authority")
	}
	if _, err := os.Stat(envFile); err != nil {
		t.Fatalf("stopping transition removed restart environment before clean exit: %v", err)
	}
	terminalHeartbeat := runtimeState.RuntimeStatus().HeartbeatAt
	if err := runtimeState.Heartbeat(terminalHeartbeat.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(HeartbeatPath(stateDir)); !os.IsNotExist(err) {
		t.Fatalf("terminal heartbeat was recreated: %v", err)
	}
	if got := runtimeState.RuntimeStatus().HeartbeatAt; !got.Equal(terminalHeartbeat) {
		t.Fatalf("terminal heartbeat advanced from %s to %s", terminalHeartbeat, got)
	}
	if err := runtimeState.MarkFailed("concurrent shutdown error"); err == nil {
		t.Fatal("stopping lifecycle was rewritten as failed")
	}
	if got := runtimeState.RuntimeStatus().LifecycleState; got != LifecycleStopping {
		t.Fatalf("lifecycle after rejected failure = %q, want stopping", got)
	}
	if err := runtimeState.MarkStopped(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(envFile); !os.IsNotExist(err) {
		t.Fatalf("stopped transition retained supervisor environment: %v", err)
	}
}

func TestRuntimeRecoveryPreservesIdentityAndInterruptsInflightCommand(t *testing.T) {
	root := t.TempDir()
	sessionID := "session-recovery"
	stateDir := filepath.Join(root, sessionID)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(stateDir, "supervisor.env")
	if err := atomicWritePrivateFile(envFile, []byte("AGENTSH_DETACHED_EVENT_TOKEN=\"token\"\nAGENTSH_NETHELPER_SOCKET=\"old.sock\"\n")); err != nil {
		t.Fatal(err)
	}
	req := types.CreateSessionRequest{ID: sessionID, Workspace: root, Policy: "default", WorkspaceMode: string(types.WorkspaceModeDirect)}
	manifest := NewRecoveryManifest(sessionID, req, LaunchSpec{
		Executable: filepath.Join(root, "agentsh"), WorkingDir: root,
		EnvironmentFile: envFile, LogFile: filepath.Join(stateDir, "supervisor.log"),
	}, time.Now().UTC())
	if err := WriteRecoveryManifest(stateDir, manifest); err != nil {
		t.Fatal(err)
	}
	meta := Metadata{SessionID: sessionID, ID: sessionID, State: LifecycleProvisioning, SupervisorSock: filepath.Join(stateDir, "supervisor.sock"), ProtocolVersion: ProtocolVersion}
	if err := WriteMetadata(stateDir, meta); err != nil {
		t.Fatal(err)
	}

	first, err := BeginRuntime(stateDir, 101, "start-1", "boot-1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if first.IsRecovery() {
		t.Fatal("first provisioning incarnation was classified as recovery")
	}
	session := types.Session{ID: sessionID, CreatedAt: time.Now().UTC(), Workspace: root, WorkspaceMount: root, WorkspaceMode: string(types.WorkspaceModeDirect), Policy: "default"}
	if err := first.MarkReady(session, "policy-digest", &NetworkEnforcement{Requested: NetworkEnforcementRequestNone, Status: NetworkEnforcementStatusNone}); err != nil {
		t.Fatal(err)
	}
	admitted := time.Now().UTC()
	if err := first.RecordCommand(InflightCommand{CommandID: "cmd-1", Operation: "exec", AdmittedAt: admitted}); err != nil {
		t.Fatal(err)
	}
	if err := first.MarkCommandStarted("cmd-1", admitted.Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	second, err := BeginRuntime(stateDir, 202, "start-2", "boot-1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !second.IsRecovery() {
		t.Fatal("second incarnation was not classified as recovery")
	}
	status := second.RuntimeStatus()
	if status.SessionID != sessionID || status.Generation != 2 || status.IncarnationID == "" || status.OwnerPID != 202 {
		t.Fatalf("unexpected recovered status: %+v", status)
	}
	interrupted, err := second.TakeInterrupted()
	if err != nil {
		t.Fatal(err)
	}
	if len(interrupted) != 1 || interrupted[0].CommandID != "cmd-1" || interrupted[0].StartedAt.IsZero() {
		t.Fatalf("interrupted commands = %+v", interrupted)
	}
	persisted, err := ReadRecoveryManifest(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(persisted.Inflight) != 0 || len(persisted.Interrupted) != 1 {
		t.Fatalf("persisted command journal = %+v", persisted)
	}
}

func TestReadRecoveryManifestRejectsUnsafeFile(t *testing.T) {
	root := t.TempDir()
	sessionID := "session-protected-manifest"
	stateDir := filepath.Join(root, sessionID)
	manifest := NewRecoveryManifest(sessionID, types.CreateSessionRequest{ID: sessionID, Workspace: root}, LaunchSpec{
		Executable: filepath.Join(root, "agentsh"), WorkingDir: root,
		EnvironmentFile: filepath.Join(stateDir, "supervisor.env"),
	}, time.Now().UTC())
	if err := WriteRecoveryManifest(stateDir, manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(RecoveryManifestPath(stateDir), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRecoveryManifest(stateDir); err == nil {
		t.Fatal("public recovery manifest permissions were accepted")
	}
}

func TestRuntimeRetriesOnlyFailedPreServeProvisioningWithoutDurableIdentity(t *testing.T) {
	root := t.TempDir()
	sessionID := "session-provisioning-retry"
	stateDir := filepath.Join(root, sessionID)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(stateDir, "supervisor.env")
	if err := atomicWritePrivateFile(envFile, []byte("PATH=\"/bin\"\n")); err != nil {
		t.Fatal(err)
	}
	manifest := NewRecoveryManifest(sessionID, types.CreateSessionRequest{ID: sessionID, Workspace: root}, LaunchSpec{
		Executable: filepath.Join(root, "agentsh"), WorkingDir: root, EnvironmentFile: envFile,
	}, time.Now().UTC())
	manifest.State = LifecycleFailed
	if err := WriteRecoveryManifest(stateDir, manifest); err != nil {
		t.Fatal(err)
	}
	if err := WriteMetadata(stateDir, Metadata{SessionID: sessionID, State: LifecycleFailed, ProtocolVersion: ProtocolVersion}); err != nil {
		t.Fatal(err)
	}
	runtime, err := BeginRuntime(stateDir, 10, "start", "boot", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.IsRecovery() || runtime.RuntimeStatus().LifecycleState != LifecycleProvisioning {
		t.Fatalf("failed pre-serve incarnation was not retried as provisioning: %+v", runtime.RuntimeStatus())
	}

	manifest = runtime.Manifest()
	manifest.State = LifecycleReady
	manifest.SessionCreatedAt = time.Time{}
	manifest.PolicyDigest = ""
	if err := WriteRecoveryManifest(stateDir, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := BeginRuntime(stateDir, 11, "start-2", "boot", time.Now().UTC()); err == nil {
		t.Fatal("ready lifecycle without durable identity was silently reprovisioned")
	}
}

func TestRuntimeRotatesOnlyNethelperPathsInProtectedEnvironment(t *testing.T) {
	root := t.TempDir()
	sessionID := "session-env"
	stateDir := filepath.Join(root, sessionID)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(stateDir, "supervisor.env")
	content := "AGENTSH_DETACHED_EVENT_TOKEN=\"secret-token\"\nAGENTSH_NETHELPER_SOCKET=\"old.sock\"\nAGENTSH_NETHELPER_CREDENTIAL_FILE=\"old.credential\"\nOPENAI_API_KEY=\"must-be-scrubbed\"\n"
	if err := atomicWritePrivateFile(envFile, []byte(content)); err != nil {
		t.Fatal(err)
	}
	manifest := NewRecoveryManifest(sessionID, types.CreateSessionRequest{ID: sessionID, Workspace: root}, LaunchSpec{
		Executable: filepath.Join(root, "agentsh"), WorkingDir: root, EnvironmentFile: envFile,
	}, time.Now().UTC())
	if err := WriteRecoveryManifest(stateDir, manifest); err != nil {
		t.Fatal(err)
	}
	if err := WriteMetadata(stateDir, Metadata{SessionID: sessionID, State: LifecycleProvisioning, ProtocolVersion: ProtocolVersion}); err != nil {
		t.Fatal(err)
	}
	runtime, err := BeginRuntime(stateDir, 1, "", "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.ScrubServiceEnvironment([]string{"OPENAI_API_KEY"}); err != nil {
		t.Fatal(err)
	}
	newSocket := filepath.Join(root, "new.sock")
	newCredential := filepath.Join(root, "new.credential")
	newBootstrap := filepath.Join(root, "new.bootstrap")
	if err := runtime.UpdateNethelperBinding(newSocket, newCredential, newBootstrap, 2); err != nil {
		t.Fatal(err)
	}
	assignments, err := ReadServiceEnvironment(envFile)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, assignment := range assignments {
		for i := range assignment {
			if assignment[i] == '=' {
				got[assignment[:i]] = assignment[i+1:]
				break
			}
		}
	}
	if got["OPENAI_API_KEY"] != "" || got["AGENTSH_DETACHED_EVENT_TOKEN"] != "secret-token" || got["AGENTSH_NETHELPER_SOCKET"] != newSocket || got["AGENTSH_NETHELPER_CREDENTIAL_FILE"] != newCredential || got["AGENTSH_NETHELPER_BOOTSTRAP_RESULT"] != newBootstrap {
		t.Fatalf("rotated environment = %#v", got)
	}
	persisted, err := ReadRecoveryManifest(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Nethelper == nil || persisted.Nethelper.Generation != 2 || persisted.Nethelper.SocketPath != newSocket || persisted.Nethelper.CredentialFile != newCredential || persisted.Nethelper.BootstrapResultPath != newBootstrap {
		t.Fatalf("durable nethelper identity = %+v", persisted.Nethelper)
	}
	if err := runtime.UpdateServiceEnvironment(map[string]string{"UNSAFE_SECRET": "value"}); err == nil {
		t.Fatal("unsupported environment update succeeded")
	}
}
