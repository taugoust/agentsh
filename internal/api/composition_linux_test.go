//go:build linux && cgo

package api

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCompositionProcessExecutablePathPrefersMakeWrapperTarget(t *testing.T) {
	directory := t.TempDir()
	wrapper := filepath.Join(directory, "agentsh-unixwrap")
	hidden := filepath.Join(directory, ".agentsh-unixwrap-wrapped")
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := compositionProcessExecutablePath(wrapper); got != wrapper {
		t.Fatalf("path without makeWrapper target = %q, want %q", got, wrapper)
	}
	if err := os.WriteFile(hidden, []byte("trusted image"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := compositionProcessExecutablePath(wrapper); got != hidden {
		t.Fatalf("makeWrapper process identity = %q, want %q", got, hidden)
	}
}
