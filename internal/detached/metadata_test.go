package detached

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMetadataCreateRead(t *testing.T) {
	root := t.TempDir()
	meta := testMetadata(t, root, "session-test")
	stateDir := filepath.Join(root, meta.SessionID)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteMetadata(stateDir, meta); err != nil {
		t.Fatalf("WriteMetadata: %v", err)
	}

	got, gotStateDir, err := ReadMetadataFromRoot(root, meta.SessionID)
	if err != nil {
		t.Fatalf("ReadMetadataFromRoot: %v", err)
	}
	if gotStateDir != stateDir {
		t.Fatalf("stateDir = %q, want %q", gotStateDir, stateDir)
	}
	if !reflect.DeepEqual(got, meta) {
		t.Fatalf("metadata mismatch\ngot:  %#v\nwant: %#v", got, meta)
	}
}

func TestListMetadataDiscoveryFilters(t *testing.T) {
	root := t.TempDir()
	live := testMetadata(t, root, "session-live")
	dead := testMetadata(t, root, "session-dead")
	dead.OwnerPID = 424242
	missingSocket := testMetadata(t, root, "session-missing-socket")
	missingSocket.SupervisorSock = filepath.Join(root, "missing.sock")
	missingSocketField := testMetadata(t, root, "session-empty-socket")
	missingSocketField.SupervisorSock = ""

	writeTestMetadata(t, root, live)
	writeTestMetadata(t, root, dead)
	writeTestMetadata(t, root, missingSocket)
	writeTestMetadata(t, root, missingSocketField)
	writeRawMetadata(t, root, "session-invalid-json", []byte(`{"session_id":`))

	got, err := ListMetadataFromRoot(root, DiscoveryOptions{
		RequireSocket: true,
		CheckPID:      true,
		PIDAlive: func(pid int) bool {
			return pid != dead.OwnerPID
		},
	})
	if err != nil {
		t.Fatalf("ListMetadataFromRoot: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1: %#v", len(got), got)
	}
	if got[0].SessionID != live.SessionID {
		t.Fatalf("discovered session = %q, want %q", got[0].SessionID, live.SessionID)
	}
}

func TestListMetadataIgnoresInvalidJSON(t *testing.T) {
	root := t.TempDir()
	writeRawMetadata(t, root, "session-invalid", []byte(`not-json`))
	got, err := ListMetadataFromRoot(root, DiscoveryOptions{})
	if err != nil {
		t.Fatalf("ListMetadataFromRoot: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("len(got) = %d, want 0", len(got))
	}
}

func TestListMetadataIgnoresMissingSocket(t *testing.T) {
	root := t.TempDir()
	meta := testMetadata(t, root, "session-missing")
	meta.SupervisorSock = filepath.Join(root, "does-not-exist.sock")
	writeTestMetadata(t, root, meta)

	got, err := ListMetadataFromRoot(root, DiscoveryOptions{RequireSocket: true})
	if err != nil {
		t.Fatalf("ListMetadataFromRoot: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("len(got) = %d, want 0", len(got))
	}
}

func TestListMetadataDetectsDeadPID(t *testing.T) {
	root := t.TempDir()
	meta := testMetadata(t, root, "session-dead-pid")
	meta.OwnerPID = 999999
	writeTestMetadata(t, root, meta)

	got, err := ListMetadataFromRoot(root, DiscoveryOptions{
		RequireSocket: true,
		CheckPID:      true,
		PIDAlive:      func(int) bool { return false },
	})
	if err != nil {
		t.Fatalf("ListMetadataFromRoot: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("len(got) = %d, want 0", len(got))
	}
}

func TestMetadataStableJSONShape(t *testing.T) {
	root := t.TempDir()
	meta := testMetadata(t, root, "session-shape")
	stateDir := filepath.Join(root, meta.SessionID)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteMetadata(stateDir, meta); err != nil {
		t.Fatalf("WriteMetadata: %v", err)
	}
	b, err := os.ReadFile(MetadataPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf(`{
  "session_id": "session-shape",
  "id": "session-shape",
  "created_at": %q,
  "state": "active",
  "policy": "agent-default",
  "real_workspace": %q,
  "workspace_mode": "shadow",
  "worktree": %q,
  "supervisor_sock": %q,
  "owner_pid": 12345,
  "protocol_version": 1
}
`, meta.CreatedAt.Format(time.RFC3339Nano), meta.RealWorkspace, meta.Worktree, meta.SupervisorSock)
	if string(b) != want {
		t.Fatalf("metadata JSON shape changed\ngot:\n%s\nwant:\n%s", string(b), want)
	}
}

func TestMetadataNetworkEnforcementJSONFields(t *testing.T) {
	root := t.TempDir()
	meta := testMetadata(t, root, "session-network")
	meta.NetworkEnforcement = &NetworkEnforcement{
		Requested:             NetworkEnforcementRequestBestEffort,
		Readiness:             NetworkEnforcementStatusDegraded,
		Status:                NetworkEnforcementStatusDegraded,
		Tier:                  NetworkEnforcementTierCgroupDelegated,
		NetworkPolicyEnforced: false,
		CgroupDelegated:       true,
		Warning:               "network policy is not enforced",
		Detail:                "delegated cgroup only",
	}
	stateDir := filepath.Join(root, meta.SessionID)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteMetadata(stateDir, meta); err != nil {
		t.Fatalf("WriteMetadata: %v", err)
	}

	got, _, err := ReadMetadataFromRoot(root, meta.SessionID)
	if err != nil {
		t.Fatalf("ReadMetadataFromRoot: %v", err)
	}
	if !reflect.DeepEqual(got.NetworkEnforcement, meta.NetworkEnforcement) {
		t.Fatalf("network enforcement mismatch\ngot:  %#v\nwant: %#v", got.NetworkEnforcement, meta.NetworkEnforcement)
	}

	b, err := os.ReadFile(MetadataPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("metadata JSON: %v", err)
	}
	raw, ok := doc["network_enforcement"].(map[string]any)
	if !ok {
		t.Fatalf("network_enforcement = %#v, want object", doc["network_enforcement"])
	}
	checks := map[string]any{
		"requested":               string(NetworkEnforcementRequestBestEffort),
		"readiness":               string(NetworkEnforcementStatusDegraded),
		"status":                  string(NetworkEnforcementStatusDegraded),
		"tier":                    string(NetworkEnforcementTierCgroupDelegated),
		"network_policy_enforced": false,
		"cgroup_delegated":        true,
		"warning":                 "network policy is not enforced",
		"detail":                  "delegated cgroup only",
	}
	for key, want := range checks {
		if got := raw[key]; got != want {
			t.Fatalf("network_enforcement.%s = %#v, want %#v", key, got, want)
		}
	}
}

func TestMetadataNeverSerializesUnprovenNetworkPolicyEnforced(t *testing.T) {
	root := t.TempDir()
	meta := testMetadata(t, root, "session-unproven-network")
	meta.NetworkEnforcement = &NetworkEnforcement{
		Requested:             NetworkEnforcementRequestStrict,
		Readiness:             NetworkEnforcementStatusReady,
		Status:                NetworkEnforcementStatusReady,
		Tier:                  NetworkEnforcementTierHelperEBPFProxyRequired,
		NetworkPolicyEnforced: true,
		CgroupDelegated:       true,
		HelperConfigured:      true,
		HelperAuthenticated:   true,
		ToolBoundaryActive:    true,
		ProxyReady:            true,
		DirectBypassBlocked:   true,
		FailClosedSetup:       true,
		// No disposable preflight or complete unsupported-traffic evidence.
	}
	stateDir := filepath.Join(root, meta.SessionID)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteMetadata(stateDir, meta); err != nil {
		t.Fatalf("WriteMetadata: %v", err)
	}
	got, _, err := ReadMetadataFromRoot(root, meta.SessionID)
	if err != nil {
		t.Fatalf("ReadMetadataFromRoot: %v", err)
	}
	if got.NetworkEnforcement == nil || got.NetworkEnforcement.NetworkPolicyEnforced {
		t.Fatalf("network enforcement = %#v, want unproven claim forced false", got.NetworkEnforcement)
	}
}

func TestReadMetadataBackwardsCompatibleWithoutNetworkEnforcement(t *testing.T) {
	root := t.TempDir()
	writeRawMetadata(t, root, "session-old", []byte(`{"session_id":"session-old","owner_pid":0,"protocol_version":1}`))

	got, _, err := ReadMetadataFromRoot(root, "session-old")
	if err != nil {
		t.Fatalf("ReadMetadataFromRoot old metadata: %v", err)
	}
	if got.NetworkEnforcement != nil {
		t.Fatalf("NetworkEnforcement = %#v, want nil for old metadata", got.NetworkEnforcement)
	}
}

func TestValidateUsableErrors(t *testing.T) {
	root := t.TempDir()
	meta := testMetadata(t, root, "session-stale")
	meta.SupervisorSock = filepath.Join(root, "missing.sock")
	err := ValidateUsable(meta, func(int) bool { return true })
	if err == nil || !strings.Contains(err.Error(), "supervisor.sock is missing") {
		t.Fatalf("missing socket error = %v, want supervisor.sock message", err)
	}

	meta.SupervisorSock = ""
	err = ValidateUsable(meta, func(int) bool { return true })
	if err == nil || !strings.Contains(err.Error(), "no supervisor_sock") {
		t.Fatalf("empty socket error = %v, want no supervisor_sock message", err)
	}

	meta = testMetadata(t, root, "session-dead")
	err = ValidateUsable(meta, func(int) bool { return false })
	if err == nil || !strings.Contains(err.Error(), "dead supervisor") {
		t.Fatalf("dead PID error = %v, want dead supervisor message", err)
	}
}

func TestValidateUsableV2ChecksKernelProcessAndSocketIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("Unix socket identity test")
	}
	root := t.TempDir()
	sock := filepath.Join(root, "supervisor.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("Unix sockets unavailable: %v", err)
	}
	defer listener.Close()
	start, boot, err := CurrentProcessIdentity(os.Getpid())
	if err != nil || start == "" || boot == "" {
		t.Skipf("stable process identity unavailable: %v", err)
	}
	meta := Metadata{
		SessionID: "session-v2", State: LifecycleReady, SupervisorSock: sock,
		OwnerPID: os.Getpid(), OwnerStartIdentity: start, BootID: boot,
		Generation: 1, IncarnationID: "incarnation-v2", ProtocolVersion: ProtocolVersion,
	}
	if err := ValidateUsable(meta, func(pid int) bool { return pid == os.Getpid() }); err != nil {
		t.Fatalf("ValidateUsable exact v2 identity: %v", err)
	}
	meta.OwnerStartIdentity = "reused-process-start"
	if err := ValidateUsable(meta, func(int) bool { return true }); err == nil || !strings.Contains(err.Error(), "reused") {
		t.Fatalf("reused process identity error = %v", err)
	}
}

func TestReadMetadataRejectsPathIdentitySubstitutionAndUnsafeFile(t *testing.T) {
	root := t.TempDir()
	meta := testMetadata(t, root, "session-expected")
	meta.SessionID = "session-substituted"
	meta.ID = "session-substituted"
	stateDir := filepath.Join(root, "session-expected")
	if err := WriteMetadata(stateDir, meta); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadMetadataFromRoot(root, "session-expected"); err == nil || !strings.Contains(err.Error(), "identities differ") {
		t.Fatalf("metadata path substitution error = %v", err)
	}
	if _, _, err := ReadMetadataFromRoot(root, "../session-expected"); err == nil {
		t.Fatal("metadata path traversal was accepted")
	}

	meta.SessionID = "session-expected"
	meta.ID = "session-expected"
	if err := WriteMetadata(stateDir, meta); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(MetadataPath(stateDir), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadMetadataFromRoot(root, "session-expected"); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("public metadata permissions error = %v", err)
	}
}

func testMetadata(t *testing.T, root, id string) Metadata {
	t.Helper()
	sock := filepath.Join(root, id, "supervisor.sock")
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sock, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	return Metadata{
		SessionID:       id,
		ID:              id,
		CreatedAt:       time.Date(2026, 6, 27, 12, 13, 14, 123456789, time.UTC),
		State:           "active",
		Policy:          "agent-default",
		RealWorkspace:   filepath.Join(root, "real"),
		WorkspaceMode:   "shadow",
		Worktree:        filepath.Join(root, id, "workspace", "work"),
		SupervisorSock:  sock,
		OwnerPID:        12345,
		ProtocolVersion: 1,
	}
}

func writeTestMetadata(t *testing.T, root string, meta Metadata) {
	t.Helper()
	stateDir := filepath.Join(root, meta.SessionID)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteMetadata(stateDir, meta); err != nil {
		t.Fatal(err)
	}
}

func writeRawMetadata(t *testing.T, root, id string, data []byte) {
	t.Helper()
	stateDir := filepath.Join(root, id)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(MetadataPath(stateDir), data, 0o600); err != nil {
		t.Fatal(err)
	}
}
