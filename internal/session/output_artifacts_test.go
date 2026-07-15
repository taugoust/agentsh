package session

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func newOutputArtifactTestSession(t *testing.T, maxBytes int64) (*Session, string) {
	t.Helper()
	workspace := filepath.Join(t.TempDir(), "workspace")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := NewManager(1).Create(workspace, "default")
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot := filepath.Join(t.TempDir(), "runtime")
	runtimeHome := filepath.Join(runtimeRoot, "home")
	runtimeTmp := filepath.Join(runtimeRoot, "tmp")
	for _, dir := range []string{runtimeRoot, runtimeHome, runtimeTmp} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	s.SetRuntimePaths(runtimeHome, runtimeTmp, nil)
	if err := s.ConfigureOutputArtifacts(maxBytes); err != nil {
		t.Fatal(err)
	}
	return s, runtimeTmp
}

func TestOutputArtifact_BoundedPrivateWriteAndExactRegistration(t *testing.T) {
	s, runtimeTmp := newOutputArtifactTestSession(t, 5)
	artifact, err := s.WriteOutputArtifact("../stdout/log", strings.NewReader("123456789"))
	if err != nil {
		t.Fatalf("WriteOutputArtifact: %v", err)
	}
	if artifact.BytesWritten != 5 || !artifact.Truncated {
		t.Fatalf("artifact = %+v, want 5 bytes and truncated", artifact)
	}
	if !IsRealPathUnder(artifact.Path, runtimeTmp) {
		t.Fatalf("artifact path %q is outside RuntimeTmp %q", artifact.Path, runtimeTmp)
	}
	data, err := os.ReadFile(artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != "12345" {
		t.Fatalf("artifact content = %q, want %q", got, "12345")
	}

	registered, ok := s.RegisteredOutputArtifactPath(artifact.Path)
	if !ok || registered != artifact.Path {
		t.Fatalf("registered path = %q, %v; want %q, true", registered, ok, artifact.Path)
	}
	if _, ok := s.RegisteredOutputArtifactPath(filepath.Dir(artifact.Path)); ok {
		t.Fatal("artifact directory was accepted as a registered artifact")
	}
	if _, ok := s.RegisteredOutputArtifactPath(artifact.Path + ".other"); ok {
		t.Fatal("unregistered sibling path was accepted")
	}
	if _, ok := s.RegisteredOutputArtifactPath(filepath.Base(artifact.Path)); ok {
		t.Fatal("relative artifact path was accepted")
	}

	other, _ := newOutputArtifactTestSession(t, 5)
	if _, ok := other.RegisteredOutputArtifactPath(artifact.Path); ok {
		t.Fatal("artifact registration leaked into another session")
	}

	if runtime.GOOS != "windows" {
		rootInfo, err := os.Stat(filepath.Dir(artifact.Path))
		if err != nil {
			t.Fatal(err)
		}
		if got := rootInfo.Mode().Perm(); got != 0o700 {
			t.Fatalf("artifact dir mode = %o, want 700", got)
		}
		fileInfo, err := os.Stat(artifact.Path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fileInfo.Mode().Perm(); got != 0o600 {
			t.Fatalf("artifact file mode = %o, want 600", got)
		}
	}
}

func TestOutputArtifact_ExactLimitIsNotTruncated(t *testing.T) {
	s, _ := newOutputArtifactTestSession(t, 5)
	artifact, err := s.WriteOutputArtifact("stdout", strings.NewReader("12345"))
	if err != nil {
		t.Fatalf("WriteOutputArtifact: %v", err)
	}
	if artifact.BytesWritten != 5 || artifact.Truncated {
		t.Fatalf("artifact = %+v, want exactly 5 untruncated bytes", artifact)
	}
}

func TestOutputArtifact_CloseRuntimeRemovesAndDeregisters(t *testing.T) {
	s, _ := newOutputArtifactTestSession(t, 1024)
	cleanupCalled := false
	s.SetRuntimePaths(s.RuntimeHomePath(), s.RuntimeTmpPath(), func() error {
		cleanupCalled = true
		return nil
	})
	if err := s.ConfigureOutputArtifacts(1024); err != nil {
		t.Fatal(err)
	}
	artifact, err := s.WriteOutputArtifact("stderr", strings.NewReader("diagnostic"))
	if err != nil {
		t.Fatalf("WriteOutputArtifact: %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(artifact.Path, 0o400); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Dir(artifact.Path), 0o500); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.CloseRuntime(); err != nil {
		t.Fatalf("CloseRuntime: %v", err)
	}
	if !cleanupCalled {
		t.Fatal("runtime cleanup callback was not called")
	}
	if _, err := os.Stat(artifact.Path); !os.IsNotExist(err) {
		t.Fatalf("artifact still exists after CloseRuntime: %v", err)
	}
	if _, ok := s.RegisteredOutputArtifactPath(artifact.Path); ok {
		t.Fatal("artifact remained registered after CloseRuntime")
	}
	if _, err := s.WriteOutputArtifact("late", strings.NewReader("data")); !errors.Is(err, ErrOutputArtifactsUnavailable) {
		t.Fatalf("write after CloseRuntime error = %v, want ErrOutputArtifactsUnavailable", err)
	}
}

func TestOutputArtifact_OpenRejectsIdentityReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink replacement requires POSIX symlink semantics")
	}
	s, _ := newOutputArtifactTestSession(t, 1024)
	artifact, err := s.WriteOutputArtifact("stdout", strings.NewReader("safe"))
	if err != nil {
		t.Fatalf("WriteOutputArtifact: %v", err)
	}
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(artifact.Path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, artifact.Path); err != nil {
		t.Fatal(err)
	}
	if file, _, err := s.OpenOutputArtifact(artifact.Path); err == nil {
		_ = file.Close()
		t.Fatal("OpenOutputArtifact accepted a replaced symlink")
	}
}

func TestConfigureOutputArtifactsRejectsNonPositiveLimit(t *testing.T) {
	s := &Session{}
	for _, maxBytes := range []int64{0, -1} {
		if err := s.ConfigureOutputArtifacts(maxBytes); err == nil {
			t.Fatalf("ConfigureOutputArtifacts(%d) succeeded", maxBytes)
		}
	}
}
