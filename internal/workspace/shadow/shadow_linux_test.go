//go:build linux

package shadow

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkspaceLifecycleRetainsResolvedExecutablesAfterPathIsCleared(t *testing.T) {
	shExecutable, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("locate shell fixture: %v", err)
	}
	shExecutable, err = filepath.Abs(shExecutable)
	if err != nil {
		t.Fatal(err)
	}

	binDir := filepath.Join(t.TempDir(), "runtime path with spaces", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"rsync", "diff"} {
		script := []byte("#!" + shExecutable + "\nexit 0\n")
		if err := os.WriteFile(filepath.Join(binDir, name), script, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", binDir)

	realRoot := filepath.Join(t.TempDir(), "real root with spaces")
	if err := os.MkdirAll(realRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	baseDir := filepath.Join(t.TempDir(), "shadow root with spaces")
	workspace, err := Create(context.Background(), "session-test", realRoot, Options{BaseDir: baseDir})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Creation stores absolute trusted paths. Later lifecycle operations must not
	// regress to basename lookup if the detached process has no ambient PATH.
	t.Setenv("PATH", "")
	if _, err := workspace.Diff(context.Background()); err != nil {
		t.Fatalf("Diff() error with empty PATH = %v", err)
	}
	if err := workspace.Accept(context.Background()); err != nil {
		t.Fatalf("Accept() error with empty PATH = %v", err)
	}
}

func TestCreateFailsBeforeSessionStateWhenRsyncIsUnavailable(t *testing.T) {
	t.Setenv("PATH", "")
	realRoot := t.TempDir()
	baseDir := t.TempDir()
	sessionDir := filepath.Join(baseDir, "session-test")

	_, err := Create(context.Background(), "session-test", realRoot, Options{BaseDir: baseDir})
	if err == nil {
		t.Fatal("Create() unexpectedly succeeded without rsync")
	}
	if !strings.Contains(err.Error(), "resolve shadow workspace rsync") {
		t.Fatalf("Create() error = %q, want rsync preflight diagnostic", err)
	}
	if _, statErr := os.Stat(sessionDir); !os.IsNotExist(statErr) {
		t.Fatalf("session state exists after failed preflight: %v", statErr)
	}
}
