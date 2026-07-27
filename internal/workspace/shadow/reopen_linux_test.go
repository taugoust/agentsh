//go:build linux

package shadow

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func installShadowRuntimeFixtures(t *testing.T) {
	t.Helper()
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	shell, err = filepath.Abs(shell)
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"rsync", "diff"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!"+shell+"\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
}

func materializeRetainedShadow(t *testing.T, base, id, real string) (Root, time.Time) {
	t.Helper()
	work := filepath.Join(base, id, "work")
	for _, dir := range []string{work, filepath.Join(base, id, "home"), filepath.Join(base, id, "tmp")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return Root{Name: filepath.Base(real), Real: real, Work: work}, time.Now().UTC()
}

func TestOpenMultiPreservesRetainedShadowChanges(t *testing.T) {
	installShadowRuntimeFixtures(t)
	real := filepath.Join(t.TempDir(), "real")
	base := filepath.Join(t.TempDir(), "shadow")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	expected, createdAt := materializeRetainedShadow(t, base, "session-reopen", real)
	retainedPath := filepath.Join(expected.Work, "file.txt")
	if err := os.WriteFile(retainedPath, []byte("retained change\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenMulti(context.Background(), "session-reopen", []RootSpec{{Path: real}}, Options{BaseDir: base, AcceptChown: true}, []Root{expected}, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(reopened.Work, "file.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "retained change\n" {
		t.Fatalf("reopened content = %q", data)
	}
	if !reopened.CreatedAt.Equal(createdAt) || reopened.State != StateActive {
		t.Fatalf("reopened identity = %+v", reopened)
	}
}

func TestOpenMultiRejectsDurableRootMismatchWithoutDeletingData(t *testing.T) {
	installShadowRuntimeFixtures(t)
	real := filepath.Join(t.TempDir(), "real")
	base := filepath.Join(t.TempDir(), "shadow")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	expected, createdAt := materializeRetainedShadow(t, base, "session-mismatch", real)
	sentinel := filepath.Join(expected.Work, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	expected.Real = filepath.Join(t.TempDir(), "other")
	if _, err := OpenMulti(context.Background(), "session-mismatch", []RootSpec{{Path: real}}, Options{BaseDir: base}, []Root{expected}, createdAt); err == nil {
		t.Fatal("mismatched retained identity reopened")
	}
	if data, err := os.ReadFile(sentinel); err != nil || string(data) != "keep" {
		t.Fatalf("retained data changed after refusal: data=%q err=%v", data, err)
	}
}
