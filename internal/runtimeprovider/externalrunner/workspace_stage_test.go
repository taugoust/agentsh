package externalrunner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStageWorkspaceSkipsHostDirenvState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "staged")
	if err := os.MkdirAll(filepath.Join(source, ".direnv", "flake-inputs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "README.md"), []byte("kept\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/nix/store/00000000000000000000000000000000-source", filepath.Join(source, ".direnv", "flake-inputs", "source")); err != nil {
		t.Fatal(err)
	}

	if err := stageWorkspace(context.Background(), source, destination); err != nil {
		t.Fatalf("stage workspace: %v", err)
	}
	if contents, err := os.ReadFile(filepath.Join(destination, "README.md")); err != nil || string(contents) != "kept\n" {
		t.Fatalf("staged ordinary file = %q, %v", contents, err)
	}
	if _, err := os.Lstat(filepath.Join(destination, ".direnv")); !os.IsNotExist(err) {
		t.Fatalf("host .direnv was staged: %v", err)
	}
}

func TestStageWorkspaceStillRejectsOtherAbsoluteSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(source, "unsafe")); err != nil {
		t.Fatal(err)
	}

	err := stageWorkspace(context.Background(), source, filepath.Join(root, "staged"))
	if err == nil || !strings.Contains(err.Error(), "refuses absolute symlink unsafe") {
		t.Fatalf("stageWorkspace error = %v", err)
	}
}
