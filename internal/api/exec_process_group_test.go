package api

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
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

	exitCode, _, _, _, _, _, _, _, err := runCommandWithResources(context.Background(), s, "cmd-timeout", req, &config.Config{}, policy.ResolvedEnvPolicy{}, 0, nil, nil, nil, "", nil)
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

	exitCode, _, _, _, _, _, _, _, err := runCommandWithResourcesStreamingEmit(context.Background(), s, "cmd-timeout-stream", req, &config.Config{}, policy.ResolvedEnvPolicy{}, 0, nil, nil, nil, nil, "", nil)
	if exitCode != 124 || !errors.Is(err, errCommandTimeout) {
		t.Fatalf("stream timeout result = exit %d err %v", exitCode, err)
	}
	assertChildDidNotSurvive(t, childFile)
}

func TestCommandTimeoutEscapedPipeHolderDoesNotBlockWaitForever(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("session escape fixture requires POSIX")
	}
	const roleEnv = "AGENTSH_TEST_ESCAPED_PIPE_ROLE"
	switch os.Getenv(roleEnv) {
	case "holder":
		time.Sleep(30 * time.Second)
		return
	case "launcher":
		cmd := exec.Command(os.Args[0], "-test.run=^TestCommandTimeoutEscapedPipeHolderDoesNotBlockWaitForever$")
		cmd.Env = append(os.Environ(), roleEnv+"=holder")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			os.Exit(2)
		}
		if err := os.WriteFile(os.Getenv("AGENTSH_TEST_ESCAPED_PIPE_PID_FILE"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
			_ = cmd.Process.Kill()
			os.Exit(3)
		}
		time.Sleep(30 * time.Second)
		return
	}

	s := newTestSession(t)
	pidFile := filepath.Join(t.TempDir(), "escaped-pid")
	req := types.ExecRequest{
		Command: os.Args[0],
		Args:    []string{"-test.run=^TestCommandTimeoutEscapedPipeHolderDoesNotBlockWaitForever$"},
		Timeout: "50ms",
		Env: map[string]string{
			roleEnv:                              "launcher",
			"AGENTSH_TEST_ESCAPED_PIPE_PID_FILE": pidFile,
		},
	}
	started := time.Now()
	exitCode, _, _, _, _, _, _, _, err := runCommandWithResources(context.Background(), s, "cmd-escaped-pipe", req, &config.Config{}, policy.ResolvedEnvPolicy{}, 0, nil, nil, nil, "", nil)
	if elapsed := time.Since(started); elapsed > commandWaitDelay+2*time.Second {
		t.Fatalf("cancellation remained blocked on escaped capture pipe for %v", elapsed)
	}
	if exitCode != 124 || !errors.Is(err, errCommandTimeout) {
		t.Fatalf("timeout result = exit %d err %v", exitCode, err)
	}

	if raw, readErr := os.ReadFile(pidFile); readErr == nil {
		if pid, parseErr := strconv.Atoi(string(raw)); parseErr == nil {
			if proc, findErr := os.FindProcess(pid); findErr == nil {
				_ = proc.Kill()
			}
		}
	}
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

	exitCode, _, _, _, _, _, _, _, err := runCommandWithResources(ctx, s, "cmd-caller-deadline", req, &config.Config{}, policy.ResolvedEnvPolicy{}, 0, nil, nil, nil, "", nil)
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
