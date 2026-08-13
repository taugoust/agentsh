//go:build linux

package shadow

import (
	"bytes"
	"context"
	"errors"
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

func TestWorkspaceDiffHandlesDanglingSymlinks(t *testing.T) {
	realRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(realRoot, "regular.txt"), []byte("real\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(string(filepath.Separator), "missing", "same"), filepath.Join(realRoot, "same-link")); err != nil {
		t.Fatal(err)
	}

	workspace, err := Create(context.Background(), "session-links", realRoot, Options{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	out, err := workspace.Diff(context.Background())
	if err != nil {
		t.Fatalf("Diff() error for identical dangling link = %v: %s", err, out)
	}
	if len(out) != 0 {
		t.Fatalf("Diff() for identical trees = %q", out)
	}

	workLink := filepath.Join(workspace.Work, "same-link")
	if err := os.Remove(workLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(string(filepath.Separator), "missing", "changed"), workLink); err != nil {
		t.Fatal(err)
	}
	out, err = workspace.Diff(context.Background())
	if err != nil {
		t.Fatalf("Diff() error for changed dangling link = %v: %s", err, out)
	}
	if text := string(out); !strings.Contains(text, "same-link") || !strings.Contains(text, "differ") {
		t.Fatalf("Diff() changed-link output = %q", text)
	}

	if err := os.Symlink(filepath.Join(string(filepath.Separator), "missing", "work-only"), filepath.Join(workspace.Work, "work-only-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(string(filepath.Separator), "missing", "real-only"), filepath.Join(realRoot, "real-only-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace.Work, "regular.txt"), []byte("draft is longer\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, excluded := range []string{".git", ".direnv"} {
		if err := os.MkdirAll(filepath.Join(workspace.Work, excluded), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(workspace.Work, excluded, "draft-only"), []byte("excluded\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	out, err = workspace.Diff(context.Background())
	if err != nil {
		t.Fatalf("Diff() error for one-sided dangling links = %v: %s", err, out)
	}
	text := string(out)
	for _, expected := range []string{
		"Itemized shadow Apply plan",
		"work-only-link -> " + filepath.Join(string(filepath.Separator), "missing", "work-only"),
		"*deleting   real-only-link",
		"regular.txt",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("Diff() output missing %q: %s", expected, text)
		}
	}
	for _, excluded := range []string{".git", ".direnv"} {
		if strings.Contains(text, excluded) {
			t.Errorf("Diff() output includes excluded path %q: %s", excluded, text)
		}
	}
	if data, err := os.ReadFile(filepath.Join(realRoot, "regular.txt")); err != nil || string(data) != "real\n" {
		t.Fatalf("Diff() mutated real content: data=%q err=%v", data, err)
	}
	if target, err := os.Readlink(filepath.Join(realRoot, "real-only-link")); err != nil || target != filepath.Join(string(filepath.Separator), "missing", "real-only") {
		t.Fatalf("Diff() mutated real symlink: target=%q err=%v", target, err)
	}
}

func TestReviewBindsRealAndShadowTreesBeforeAccept(t *testing.T) {
	realRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(realRoot, "value.bin"), []byte{0, 1, 2}, 0o644); err != nil {
		t.Fatal(err)
	}
	workspace, err := Create(context.Background(), "session-review", realRoot, Options{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace.Work, "value.bin"), []byte{3, 4, 5, 6}, 0o644); err != nil {
		t.Fatal(err)
	}
	review, err := workspace.Review(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if review.Generation != 1 || !strings.HasPrefix(review.Hash, "sha256:") || review.BaseHash == review.ShadowHash {
		t.Fatalf("review = %+v", review)
	}
	if err := os.WriteFile(filepath.Join(realRoot, "concurrent.txt"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := workspace.AcceptReviewed(context.Background(), review.Generation, review.Hash); !errors.Is(err, ErrStaleReview) {
		t.Fatalf("accept after real change error = %v", err)
	}
	if _, err := os.Stat(workspace.Work); err != nil {
		t.Fatalf("stale accept invalidated retained shadow: %v", err)
	}
	// Restore the reviewed base before taking the fresh review. The accept plan
	// intentionally mirrors shadow -> real, including deletion of real-only files.
	if err := os.Remove(filepath.Join(realRoot, "concurrent.txt")); err != nil {
		t.Fatal(err)
	}
	fresh, err := workspace.Review(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Generation != 2 || fresh.Hash == review.Hash {
		t.Fatalf("fresh review = %+v", fresh)
	}
	if err := workspace.AcceptReviewed(context.Background(), fresh.Generation, fresh.Hash); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(realRoot, "value.bin"))
	if err != nil || !bytes.Equal(data, []byte{3, 4, 5, 6}) {
		t.Fatalf("accepted binary = %v, %v", data, err)
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
