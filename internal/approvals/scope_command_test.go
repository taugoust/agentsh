package approvals

import (
	"strings"
	"testing"
)

func TestNewCommandExecutableScope_IgnoresArgs(t *testing.T) {
	scope, ok := NewCommandScope("sqlite3", []string{"events.db", "select 1"}, "approve-sqlite")
	if !ok {
		t.Fatal("NewCommandScope returned !ok")
	}
	if scope.Kind != "command" || scope.Operation != "exec" || scope.Rule != "approve-sqlite" {
		t.Fatalf("unexpected scope metadata: %+v", scope)
	}
	if !strings.HasPrefix(scope.Key, "command-executable:") {
		t.Fatalf("unexpected key: %q", scope.Key)
	}
	if scope.Label != "sqlite3" || scope.Path != "sqlite3" {
		t.Fatalf("label/path = %q/%q, want sqlite3", scope.Label, scope.Path)
	}

	sameExecutable, ok := NewCommandScope("sqlite3", []string{"events.db", "select 2"}, "approve-sqlite")
	if !ok {
		t.Fatal("same executable NewCommandScope returned !ok")
	}
	if sameExecutable.Key != scope.Key {
		t.Fatalf("same executable key mismatch across args: %q != %q", sameExecutable.Key, scope.Key)
	}
}

func TestNewCommandExecutableScope_NixStorePathUsesPathNotArgv(t *testing.T) {
	command := "/nix/store/abc-sqlite-3.45/bin/sqlite3"
	scope, ok := NewCommandExecutableScope(command, "approve-unknown-nix-store-executables")
	if !ok {
		t.Fatal("NewCommandExecutableScope returned !ok")
	}
	if scope.Label != command || scope.Path != command {
		t.Fatalf("label/path = %q/%q, want %q", scope.Label, scope.Path, command)
	}

	fromDefaultA, ok := NewCommandScope(command, []string{"events.db", "select 1"}, "approve-unknown-nix-store-executables")
	if !ok {
		t.Fatal("NewCommandScope A returned !ok")
	}
	fromDefaultB, ok := NewCommandScope(command, []string{"events.db", "select 2", "limit", "50"}, "approve-unknown-nix-store-executables")
	if !ok {
		t.Fatal("NewCommandScope B returned !ok")
	}
	if fromDefaultA.Key != fromDefaultB.Key || fromDefaultA.Key != scope.Key {
		t.Fatalf("nix executable key changed with argv: scope=%q a=%q b=%q", scope.Key, fromDefaultA.Key, fromDefaultB.Key)
	}
}

func TestNewCommandInvocationScope_RemainsExact(t *testing.T) {
	scope, ok := NewCommandInvocationScope("git", []string{"status", "--short"}, "approve-git")
	if !ok {
		t.Fatal("NewCommandInvocationScope returned !ok")
	}
	if scope.Kind != "command" || scope.Operation != "exec" || scope.Rule != "approve-git" {
		t.Fatalf("unexpected scope metadata: %+v", scope)
	}
	if !strings.HasPrefix(scope.Key, "command-invocation:") {
		t.Fatalf("unexpected key: %q", scope.Key)
	}
	if scope.Label != "git status --short" {
		t.Fatalf("label = %q", scope.Label)
	}

	same, ok := NewCommandInvocationScope("git", []string{"status", "--short"}, "approve-git")
	if !ok {
		t.Fatal("same NewCommandInvocationScope returned !ok")
	}
	if same.Key != scope.Key {
		t.Fatalf("same invocation key mismatch: %q != %q", same.Key, scope.Key)
	}

	different, ok := NewCommandInvocationScope("git", []string{"status"}, "approve-git")
	if !ok {
		t.Fatal("different NewCommandInvocationScope returned !ok")
	}
	if different.Key == scope.Key {
		t.Fatalf("different args should produce different scope key %q", scope.Key)
	}
}

func TestNewCommandExecutableScope_IsRuleAware(t *testing.T) {
	a, ok := NewCommandExecutableScope("sqlite3", "approve-sqlite")
	if !ok {
		t.Fatal("scope A returned !ok")
	}
	b, ok := NewCommandExecutableScope("sqlite3", "approve-other")
	if !ok {
		t.Fatal("scope B returned !ok")
	}
	if a.Key == b.Key {
		t.Fatalf("executable scope key should include rule: %q", a.Key)
	}
}
