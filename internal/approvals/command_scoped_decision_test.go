package approvals

import (
	"context"
	"testing"
	"time"
)

func TestCommandExecutableSessionApprovalMatchesDifferentArgs(t *testing.T) {
	m := New("api", time.Minute, nil)
	ctx := context.Background()

	scope, ok := NewCommandExecutableScope("sqlite3", "approve-sqlite")
	if !ok {
		t.Fatal("failed to build executable scope")
	}
	m.SetScoped(ctx, "s1", "cmd-prev", scope, true, "ok", "approve-sqlite")

	sameExecutableDifferentArgs, ok := NewCommandScope("sqlite3", []string{"events.db", "select 2"}, "approve-sqlite")
	if !ok {
		t.Fatal("failed to build default scope")
	}
	dec, ok := m.CheckScoped(ctx, "s1", "cmd-next", sameExecutableDifferentArgs)
	if !ok || !dec.Approved || dec.Key != scope.Key {
		t.Fatalf("scoped decision = %+v ok=%v", dec, ok)
	}
}

func TestCommandExecutableSessionApprovalDoesNotMatchDifferentExecutable(t *testing.T) {
	m := New("api", time.Minute, nil)
	ctx := context.Background()

	sqlite, _ := NewCommandExecutableScope("sqlite3", "approve-db")
	m.SetScoped(ctx, "s1", "cmd-prev", sqlite, true, "ok", "approve-db")

	psql, _ := NewCommandExecutableScope("psql", "approve-db")
	if _, ok := m.CheckScoped(ctx, "s1", "cmd-next", psql); ok {
		t.Fatal("different executable unexpectedly used scoped approval")
	}
}

func TestCommandInvocationSessionApprovalRemainsNarrow(t *testing.T) {
	m := New("api", time.Minute, nil)
	ctx := context.Background()

	scope, ok := NewCommandInvocationScope("sqlite3", []string{"events.db", "select 1"}, "approve-sqlite")
	if !ok {
		t.Fatal("failed to build invocation scope")
	}
	m.SetScoped(ctx, "s1", "cmd-prev", scope, true, "ok", "approve-sqlite")

	same, _ := NewCommandInvocationScope("sqlite3", []string{"events.db", "select 1"}, "approve-sqlite")
	if dec, ok := m.CheckScoped(ctx, "s1", "cmd-next", same); !ok || !dec.Approved {
		t.Fatalf("same invocation did not hit: %+v ok=%v", dec, ok)
	}

	different, _ := NewCommandInvocationScope("sqlite3", []string{"events.db", "select 2"}, "approve-sqlite")
	if _, ok := m.CheckScoped(ctx, "s1", "cmd-next", different); ok {
		t.Fatal("different invocation unexpectedly used exact scoped approval")
	}
}
