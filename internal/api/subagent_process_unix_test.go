//go:build !windows

package api

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func waitForSubagentTestFile(t *testing.T, path string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && strings.TrimSpace(string(data)) != "" {
			return strings.TrimSpace(string(data))
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read %s: %v", path, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
	return ""
}

func TestSubagentProcessCancellationUsesGracefulTermination(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh is unavailable")
	}
	dir := t.TempDir()
	readyFile := filepath.Join(dir, "ready")
	termFile := filepath.Join(dir, "terminated")
	script := `term_file=$1; ready_file=$2; trap 'printf terminated > "$term_file"; exit 0' TERM; printf ready > "$ready_file"; while :; do :; done`
	cmd := exec.Command(sh, "-c", script, "subagent-test", termFile, readyFile)
	ctx, cancel := context.WithCancel(context.Background())
	outcomeCh := make(chan subagentProcessOutcome, 1)
	go func() {
		outcomeCh <- runOwnedSubagentProcess(ctx, cmd, 500*time.Millisecond)
	}()

	waitForSubagentTestFile(t, readyFile)
	cancel()
	var outcome subagentProcessOutcome
	select {
	case outcome = <-outcomeCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for cancelled subagent process")
	}
	if outcome.Termination != subagentTerminationGraceful {
		t.Fatalf("termination = %q, want graceful (error=%v signal=%q)", outcome.Termination, outcome.RunError, outcome.Signal)
	}
	if got := waitForSubagentTestFile(t, termFile); got != "terminated" {
		t.Fatalf("termination marker = %q", got)
	}
}

func TestSubagentProcessCancellationEscalatesToForcedTermination(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh is unavailable")
	}
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "descendant.pid")
	script := `pid_file=$1; trap '' TERM; sleep 30 & child=$!; printf '%s' "$child" > "$pid_file"; wait`
	cmd := exec.Command(sh, "-c", script, "subagent-test", pidFile)
	ctx, cancel := context.WithCancel(context.Background())
	outcomeCh := make(chan subagentProcessOutcome, 1)
	go func() {
		outcomeCh <- runOwnedSubagentProcess(ctx, cmd, 50*time.Millisecond)
	}()
	childPIDText := waitForSubagentTestFile(t, pidFile)
	cancel()
	select {
	case outcome := <-outcomeCh:
		if outcome.Termination != subagentTerminationForced {
			t.Fatalf("termination = %q, want forced (error=%v signal=%q)", outcome.Termination, outcome.RunError, outcome.Signal)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for forced subagent termination")
	}

	childPID, err := strconv.Atoi(childPIDText)
	if err != nil {
		t.Fatalf("parse descendant pid: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		err = syscall.Kill(childPID, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err == nil {
		t.Fatalf("descendant process %d still exists after forced group termination", childPID)
	}
}
