package api

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

// Helper to create a bare session and workspace.
func newTestSession(t *testing.T) *session.Session {
	t.Helper()
	sessions := session.NewManager(10)
	ws := t.TempDir()
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCommandTimeoutProcessGroupIDFallsBackToKnownChildPID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix process groups are unavailable")
	}
	const nonexistentPID = 1 << 30
	if got := getProcessGroupID(nonexistentPID); got != nonexistentPID {
		t.Fatalf("process group ID = %d, want child PID %d", got, nonexistentPID)
	}
}

func TestCommandTimeoutKillsProcessGroup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-group shell fixture requires POSIX")
	}
	s := newTestSession(t)
	childFile := filepath.Join(s.Workspace, "child.txt")
	req := processTreeRequest(childFile, "50ms")

	exitCode, _, _, _, _, _, _, _, err := runCommandWithResources(context.Background(), s, "cmd-timeout", req, &config.Config{}, policy.ResolvedEnvPolicy{}, 0, nil, nil, nil, "")
	if exitCode != 124 || !errors.Is(err, errCommandTimeout) {
		t.Fatalf("timeout result = exit %d err %v", exitCode, err)
	}
	assertChildDidNotSurvive(t, childFile)
}

func TestCommandTimeoutKillsProcessGroupStreaming(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-group shell fixture requires POSIX")
	}
	s := newTestSession(t)
	childFile := filepath.Join(s.Workspace, "child-stream.txt")
	req := processTreeRequest(childFile, "50ms")

	exitCode, _, _, _, _, _, _, _, err := runCommandWithResourcesStreamingEmit(context.Background(), s, "cmd-timeout-stream", req, &config.Config{}, policy.ResolvedEnvPolicy{}, 0, nil, nil, nil, nil, "")
	if exitCode != 124 || !errors.Is(err, errCommandTimeout) {
		t.Fatalf("stream timeout result = exit %d err %v", exitCode, err)
	}
	assertChildDidNotSurvive(t, childFile)
}

func TestCommandTimeoutDoesNotClaimCallerDeadline(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-group shell fixture requires POSIX")
	}
	s := newTestSession(t)
	childFile := filepath.Join(s.Workspace, "caller-deadline-child.txt")
	req := processTreeRequest(childFile, "1s")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	exitCode, _, _, _, _, _, _, _, err := runCommandWithResources(ctx, s, "cmd-caller-deadline", req, &config.Config{}, policy.ResolvedEnvPolicy{}, 0, nil, nil, nil, "")
	if exitCode == 124 || errors.Is(err, errCommandTimeout) {
		t.Fatalf("caller deadline was mislabeled = exit %d err %v", exitCode, err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("caller deadline error = %v", err)
	}
	assertChildDidNotSurvive(t, childFile)
}

func processTreeRequest(childFile, timeout string) types.ExecRequest {
	return types.ExecRequest{
		Command: "sh",
		Args:    []string{"-c", `(sleep 0.25; printf survived > "$CHILD_FILE") & sleep 5`},
		Timeout: timeout,
		Env:     map[string]string{"CHILD_FILE": childFile},
	}
}

func assertChildDidNotSurvive(t *testing.T, childFile string) {
	t.Helper()
	time.Sleep(350 * time.Millisecond)
	if _, err := os.Stat(childFile); err == nil {
		t.Fatalf("child process survived and wrote %s", childFile)
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat child marker: %v", err)
	}
}
