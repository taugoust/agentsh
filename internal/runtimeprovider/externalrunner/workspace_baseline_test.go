package externalrunner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWorkspaceBaselineDetectsRealWorkspaceDrift(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "staged")
	if err := os.MkdirAll(filepath.Join(source, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "README.md"), []byte("baseline\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, ".git", "index"), []byte("ignored\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	baseline, err := stageWorkspace(context.Background(), source, destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Entries) != 1 {
		t.Fatalf("baseline entries = %#v", baseline.Entries)
	}

	if err := os.WriteFile(filepath.Join(source, ".git", "index"), []byte("changed but excluded\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	drift, err := VerifyWorkspaceBaseline(context.Background(), baseline)
	if err != nil || len(drift) != 0 {
		t.Fatalf("excluded Git metadata drift = %#v, %v", drift, err)
	}

	if err := os.WriteFile(filepath.Join(source, "README.md"), []byte("host changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	drift, err = VerifyWorkspaceBaseline(context.Background(), baseline)
	if err != nil || len(drift) != 1 || !strings.Contains(drift[0].Path, "README.md") {
		t.Fatalf("content drift = %#v, %v", drift, err)
	}
}

func TestWorkspaceBaselineDetectsAddedAndRemovedPaths(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	if err := os.Mkdir(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "removed.txt"), []byte("baseline\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	baseline, err := snapshotWorkspace(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(source, "removed.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "added.txt"), []byte("new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	drift, err := VerifyWorkspaceBaseline(context.Background(), baseline)
	if err != nil || len(drift) != 2 {
		t.Fatalf("path drift = %#v, %v", drift, err)
	}
	if drift[0].Reason != "added to real workspace" || drift[1].Reason != "removed from real workspace" {
		t.Fatalf("unexpected ordered drift = %#v", drift)
	}
}

func TestWorkspaceBaselineRoundTripPreservesNonUTF8Paths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows paths must be valid Unicode")
	}
	source := filepath.Join(t.TempDir(), "source")
	if err := os.Mkdir(source, 0o755); err != nil {
		t.Fatal(err)
	}
	name := string([]byte{'b', 'a', 'd', '-', 0xff})
	if err := os.WriteFile(filepath.Join(source, name), []byte("content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	baseline, err := snapshotWorkspace(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), WorkspaceBaselineName)
	if err := WriteWorkspaceBaseline(path, baseline); err != nil {
		t.Fatal(err)
	}
	loaded, err := ReadWorkspaceBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Entries) != 1 || loaded.Entries[0].Path != baseline.Entries[0].Path {
		t.Fatalf("round-trip baseline = %#v", loaded)
	}
	drift, err := VerifyWorkspaceBaseline(context.Background(), loaded)
	if err != nil || len(drift) != 0 {
		t.Fatalf("round-trip drift = %#v, %v", drift, err)
	}
}
