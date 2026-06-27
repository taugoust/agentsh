package detached

import (
	"fmt"
	"os"
	"path/filepath"
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
	if got != meta {
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
		ProtocolVersion: ProtocolVersion,
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
