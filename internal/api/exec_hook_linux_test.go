//go:build linux

package api

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

func newHookFailureTestSession(t *testing.T) (*session.Session, string) {
	t.Helper()
	ws := t.TempDir()
	s := &session.Session{
		ID:        "session-hook-failure",
		Workspace: ws,
		Cwd:       "/workspace",
		Env:       map[string]string{},
	}
	s.SetWorkspaceMount(ws)
	return s, filepath.Join(ws, "marker")
}

func assertHookFailureResult(t *testing.T, exitCode int, err error, marker string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected hook failure error")
	}
	if !strings.Contains(err.Error(), "hook boom") {
		t.Fatalf("error = %v, want hook boom", err)
	}
	if exitCode != 127 {
		t.Fatalf("exit code = %d, want 127", exitCode)
	}
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("command should not have reached shell body; marker stat err = %v", statErr)
	}
}

func TestRunCommandWithResourcesHookErrorFailsClosed(t *testing.T) {
	s, marker := newHookFailureTestSession(t)
	req := types.ExecRequest{Command: "sh", Args: []string{"-c", "touch \"$MARKER\""}, Env: map[string]string{"MARKER": marker}}
	hookErr := errors.New("hook boom")
	hook := func(pid int) (func() error, error) { return nil, hookErr }

	exitCode, _, _, _, _, _, _, _, err := runCommandWithResources(context.Background(), s, "cmd-hook-fail", req, &config.Config{}, policy.ResolvedEnvPolicy{}, 0, hook, nil, nil, "")
	assertHookFailureResult(t, exitCode, err, marker)
}

func TestRunCommandWithResourcesStreamingHookErrorFailsClosed(t *testing.T) {
	s, marker := newHookFailureTestSession(t)
	req := types.ExecRequest{Command: "sh", Args: []string{"-c", "touch \"$MARKER\""}, Env: map[string]string{"MARKER": marker}}
	hookErr := errors.New("hook boom")
	hook := func(pid int) (func() error, error) { return nil, hookErr }

	exitCode, _, _, _, _, _, _, _, err := runCommandWithResourcesStreamingEmit(context.Background(), s, "cmd-hook-fail-stream", req, &config.Config{}, policy.ResolvedEnvPolicy{}, 0, nil, hook, nil, nil, "")
	assertHookFailureResult(t, exitCode, err, marker)
}
