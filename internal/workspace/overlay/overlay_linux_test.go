//go:build linux

package overlay

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateFailsBeforeSessionStateWhenRsyncIsUnavailable(t *testing.T) {
	t.Setenv("PATH", "")
	realRoot := t.TempDir()
	baseDir := t.TempDir()
	sessionDir := filepath.Join(baseDir, "session-test")

	_, err := Create(context.Background(), "session-test", realRoot, Options{BaseDir: baseDir})
	if err == nil {
		t.Fatal("Create() unexpectedly succeeded without rsync")
	}
	if !strings.Contains(err.Error(), "resolve overlay rsync") {
		t.Fatalf("Create() error = %q, want rsync preflight diagnostic", err)
	}
	if _, statErr := os.Stat(sessionDir); !os.IsNotExist(statErr) {
		t.Fatalf("session state exists after failed preflight: %v", statErr)
	}
}
