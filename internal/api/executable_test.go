package api

import (
	"os/exec"
	"runtime"
	"testing"
)

func testNoopExecutable(t *testing.T) string {
	t.Helper()
	name := "true"
	if runtime.GOOS == "windows" {
		name = "cmd.exe"
	}
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("find no-op test executable %q: %v", name, err)
	}
	return path
}
