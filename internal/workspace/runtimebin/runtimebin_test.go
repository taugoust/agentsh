package runtimebin

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestResolveUsesPackagedPathWithEmptyAmbientPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("executable fixture uses Unix permission bits")
	}
	binDir := filepath.Join(t.TempDir(), "runtime path with spaces", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(binDir, "rsync")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	setPackagedPathForTest(t, binDir)
	t.Setenv("PATH", "")

	got, err := Resolve("rsync")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got != executable {
		t.Fatalf("Resolve() = %q, want %q", got, executable)
	}
}

func TestResolvePackagedPathFailsClosedWithoutAmbientFallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("executable fixture uses Unix permission bits")
	}
	ambientBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(ambientBin, "rsync"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	setPackagedPathForTest(t, filepath.Join(t.TempDir(), "missing"))
	t.Setenv("PATH", ambientBin)

	_, err := Resolve("rsync")
	if err == nil {
		t.Fatal("Resolve() unexpectedly used the ambient PATH")
	}
	if !strings.Contains(err.Error(), "packaged runtime closure") {
		t.Fatalf("Resolve() error = %q, want packaged-closure diagnostic", err)
	}
}

func TestResolveAmbientPathForNonPackagedBuild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("executable fixture uses Unix permission bits")
	}
	binDir := t.TempDir()
	executable := filepath.Join(binDir, "rsync")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	setPackagedPathForTest(t, "")
	t.Setenv("PATH", binDir)

	got, err := Resolve("rsync")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got != executable {
		t.Fatalf("Resolve() = %q, want %q", got, executable)
	}
}

func TestResolveRejectsPathInsteadOfBasename(t *testing.T) {
	setPackagedPathForTest(t, t.TempDir())
	if _, err := Resolve(filepath.Join("relative", "rsync")); err == nil {
		t.Fatal("Resolve() accepted a path instead of an executable basename")
	}
}

func setPackagedPathForTest(t *testing.T, value string) {
	t.Helper()
	previous := packagedPath
	packagedPath = value
	t.Cleanup(func() { packagedPath = previous })
}
