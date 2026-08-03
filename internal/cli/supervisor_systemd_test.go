package cli

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStopDetachedSupervisorSystemdUnit_AlreadyCollectedIsSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is unavailable on Windows")
	}
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	script := filepath.Join(dir, "systemctl")
	content := `#!/bin/sh
printf '%s\n' "$*" >>"$SYSTEMCTL_CALLS"
if [ "$2" = show ]; then
  printf 'not-found\n'
  exit 0
fi
printf 'stop must not be called for an absent unit\n' >&2
exit 99
`
	if err := os.WriteFile(script, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SYSTEMCTL_CALLS", calls)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	unit := "agentsh-supervisor-session-test.service"
	if err := stopDetachedSupervisorSystemdUnit(context.Background(), unit); err != nil {
		t.Fatalf("stopDetachedSupervisorSystemdUnit: %v", err)
	}
	data, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(string(data))
	want := "--user show --property=LoadState --value " + unit
	if got != want {
		t.Fatalf("systemctl calls = %q, want %q", got, want)
	}
}
