package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/runtimeprovider"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

func TestRuntimeProviderPrepareSelectsOnlyConfiguredNamedProfile(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	t.Setenv("HOME", filepath.Join(root, "home"))
	configPath := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(configPath, []byte(`
sessions:
  runtime:
    default_profile: workstation
    profiles:
      workstation:
        provider: native
      compatibility:
        provider: native
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTSH_CONFIG", configPath)
	workspace := t.TempDir()
	sessionID := "session-" + uuid.NewString()

	request, gotConfigPath, cfg, err := prepareDetachedRuntimeRequest(
		sessionID, []string{workspace}, string(types.WorkspaceModeShadow), "default",
		"", "", nil, "compatibility",
	)
	if err != nil {
		t.Fatal(err)
	}
	if request.Provider != runtimeprovider.NativeProvider || request.Profile != "compatibility" || request.SessionID != sessionID || request.Session.ID != sessionID {
		t.Fatalf("runtime request = %+v", request)
	}
	if gotConfigPath != configPath || cfg.Sessions.Runtime.DefaultProfile != "workstation" {
		t.Fatalf("runtime config path/profile = %q / %+v", gotConfigPath, cfg.Sessions.Runtime)
	}
	if request.Session.Shadow == nil || !request.Session.Shadow.KeepOnDestroy {
		t.Fatalf("shadow request lost existing detached semantics: %+v", request.Session)
	}
	if filepath.Base(request.StateDir) != sessionID {
		t.Fatalf("state directory %q is not bound to %s", request.StateDir, sessionID)
	}

	unknownID := "session-" + uuid.NewString()
	_, _, _, err = prepareDetachedRuntimeRequest(
		unknownID, []string{workspace}, string(types.WorkspaceModeShadow), "default",
		"", "", nil, "project-selected",
	)
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("unknown runtime profile error = %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(detachedSessionsRoot(), unknownID)); !os.IsNotExist(statErr) {
		t.Fatalf("unknown profile reserved state before validation: %v", statErr)
	}
}

func TestRuntimeProviderDefaultsToNativeAndExposesStartFlag(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	t.Setenv("HOME", filepath.Join(root, "home"))
	configPath := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(configPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTSH_CONFIG", configPath)
	request, _, _, err := prepareDetachedRuntimeRequest(
		"session-"+uuid.NewString(), []string{t.TempDir()}, string(types.WorkspaceModeDirect), "default",
		"", "", nil, "",
	)
	if err != nil {
		t.Fatal(err)
	}
	if request.Provider != runtimeprovider.NativeProvider || request.Profile != runtimeprovider.DefaultProfile {
		t.Fatalf("default runtime = %s/%s", request.Provider, request.Profile)
	}
	if request.Session.RealPaths == nil || !*request.Session.RealPaths {
		t.Fatalf("native direct request changed real-path behavior: %+v", request.Session)
	}
	if newSessionStartCmd().Flags().Lookup("runtime-profile") == nil {
		t.Fatal("session start does not expose --runtime-profile")
	}
}

func TestRuntimeProviderInfersProtocolV2NativeManifestWithoutChangingLegacyFiles(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_STATE_HOME", root)
	t.Setenv("HOME", root)
	sessionID := "session-" + uuid.NewString()
	stateDir := filepath.Join(detachedSessionsRoot(), sessionID)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	envFile := filepath.Join(stateDir, "supervisor.env")
	if err := os.WriteFile(envFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	recovery := detached.NewRecoveryManifest(sessionID, types.CreateSessionRequest{
		ID: sessionID, Workspace: workspace, WorkspaceMode: string(types.WorkspaceModeDirect),
	}, detached.LaunchSpec{
		Executable: filepath.Join(root, "agentsh"), WorkingDir: workspace,
		EnvironmentFile: envFile, LogFile: filepath.Join(stateDir, "supervisor.log"),
	}, now)
	recovery.State = detached.LifecycleReady
	recovery.SessionCreatedAt = now
	recovery.PolicyDigest = "policy-digest"
	recovery.Generation = 4
	recovery.IncarnationID = "incarnation-4"
	if err := detached.WriteRecoveryManifest(stateDir, recovery); err != nil {
		t.Fatal(err)
	}
	meta := detached.Metadata{
		SessionID: sessionID, ID: sessionID, CreatedAt: now, State: detached.LifecycleReady,
		RealWorkspace: workspace, WorkspaceMode: string(types.WorkspaceModeDirect),
		SupervisorSock: filepath.Join(stateDir, "supervisor.sock"),
		OwnerPID:       123, OwnerStartIdentity: "start-4", BootID: "boot-4",
		Generation: 4, IncarnationID: "incarnation-4", ProtocolVersion: detached.ProtocolVersion,
	}
	if err := detached.WriteMetadata(stateDir, meta); err != nil {
		t.Fatal(err)
	}

	manifest, legacy, err := runtimeManifestForDetachedSession(sessionID, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if !legacy || manifest.Provider != runtimeprovider.NativeProvider || manifest.Profile != runtimeprovider.DefaultProfile || manifest.State != runtimeprovider.StateReady {
		t.Fatalf("inferred runtime manifest = %+v, legacy=%t", manifest, legacy)
	}
	if manifest.Identity.Generation != 4 || manifest.Identity.IncarnationID != "incarnation-4" || manifest.Endpoint.Address != meta.SupervisorSock {
		t.Fatalf("inferred runtime identity = %+v / %+v", manifest.Identity, manifest.Endpoint)
	}
	if _, err := os.Stat(runtimeprovider.ManifestPath(stateDir)); !os.IsNotExist(err) {
		t.Fatalf("read-only legacy inference wrote a provider manifest: %v", err)
	}
}

func TestRuntimeProviderKeepsProtocolV1RecoveryPath(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_STATE_HOME", root)
	t.Setenv("HOME", root)
	sessionID := "session-" + uuid.NewString()
	stateDir := filepath.Join(detachedSessionsRoot(), sessionID)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	envFile := filepath.Join(stateDir, "supervisor.env")
	if err := os.WriteFile(envFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	recovery := detached.NewRecoveryManifest(sessionID, types.CreateSessionRequest{ID: sessionID, Workspace: workspace}, detached.LaunchSpec{
		Executable: filepath.Join(root, "agentsh"), WorkingDir: workspace, EnvironmentFile: envFile,
	}, time.Now().UTC())
	if err := detached.WriteRecoveryManifest(stateDir, recovery); err != nil {
		t.Fatal(err)
	}
	if err := detached.WriteMetadata(stateDir, detached.Metadata{
		SessionID: sessionID, State: detached.LifecycleProvisioning,
		SupervisorSock: filepath.Join(stateDir, "supervisor.sock"), ProtocolVersion: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, legacy, err := runtimeManifestForDetachedSession(sessionID, stateDir); !legacy || !errors.Is(err, errLegacyRuntimeProviderIdentity) {
		t.Fatalf("protocol-v1 runtime inference = legacy %t, error %v", legacy, err)
	}
}
