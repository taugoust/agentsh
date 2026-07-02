package cleanup

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRemoveAllWritableRemovesReadOnlyTree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are not enforced on Windows")
	}
	root := filepath.Join(t.TempDir(), "session")
	modDir := filepath.Join(root, "home", "go", "pkg", "mod", "example.com", "mod@v1.0.0", ".github", "workflows")
	if err := os.MkdirAll(modDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	file := filepath.Join(modDir, "go.yaml")
	if err := os.WriteFile(file, []byte("name: ci\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	for _, p := range []string{file, modDir, filepath.Dir(modDir), filepath.Dir(filepath.Dir(modDir))} {
		if err := os.Chmod(p, 0o555); err != nil {
			t.Fatalf("Chmod %s: %v", p, err)
		}
	}

	if err := RemoveAllWritable(root); err != nil {
		t.Fatalf("RemoveAllWritable: %v", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("root still exists or stat failed unexpectedly: %v", err)
	}
}

func TestRemoveAllWritableDoesNotFollowSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions vary on Windows")
	}
	parent := t.TempDir()
	root := filepath.Join(parent, "session")
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("MkdirAll root: %v", err)
	}
	if err := os.WriteFile(outside, []byte("keep"), 0o400); err != nil {
		t.Fatalf("WriteFile outside: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if err := RemoveAllWritable(root); err != nil {
		t.Fatalf("RemoveAllWritable: %v", err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("outside symlink target should remain: %v", err)
	}
}
