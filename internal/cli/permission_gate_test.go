package cli

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPermissionGateCommandRegistered(t *testing.T) {
	root := NewRoot("test")
	command, _, err := root.Find([]string{"permission-gate", "run"})
	if err != nil {
		t.Fatal(err)
	}
	if command == nil || command.Name() != "run" || command.Parent() == nil || command.Parent().Name() != "permission-gate" {
		t.Fatalf("permission-gate run command was not registered: %#v", command)
	}
	if !strings.Contains(command.Long, "does not create\nnamespaces") {
		t.Fatalf("guard-only behavior missing from help: %q", command.Long)
	}
}

func TestPermissionGateRunRequiresDashAndCommand(t *testing.T) {
	for _, args := range [][]string{
		{"permission-gate", "run"},
		{"permission-gate", "run", "command-without-dash"},
		{"permission-gate", "run", "--"},
	} {
		root := NewRoot("test")
		root.SetArgs(args)
		err := root.Execute()
		if err == nil || !strings.Contains(err.Error(), "command required after --") {
			t.Fatalf("Execute(%v) error = %v", args, err)
		}
	}
}

func TestPermissionGateRunPropagatesChildExitCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission gate launch")
	}
	root := NewRoot("test")
	root.SetArgs([]string{
		"permission-gate", "run", "--audit-log", filepath.Join(t.TempDir(), "audit.jsonl"),
		"--", "sh", "-c", "exit 7",
	})
	err := root.Execute()
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("Execute() error = %v, want ExitError", err)
	}
	if exitErr.Code() != 7 || exitErr.Message() != "" {
		t.Fatalf("ExitError = code %d message %q", exitErr.Code(), exitErr.Message())
	}
}
