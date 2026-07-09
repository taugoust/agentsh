package approvals

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestResolveOnceFileTreeMatchesNestedAndSiblingWithinCommand(t *testing.T) {
	ctx := context.Background()
	em := &stubEmitter{}
	m := New("api", time.Minute, em)

	tree, ok := NewFileTreeScope("read", "/workspace/pkg", "outside-read")
	if !ok {
		t.Fatal("NewFileTreeScope returned !ok")
	}
	done := make(chan Resolution, 1)
	go func() {
		res, _ := m.RequestApproval(ctx, Request{
			ID:        "a-tree",
			SessionID: "s1",
			CommandID: "cmd1",
			Kind:      "file",
			Target:    "/workspace/pkg/initial.go",
			Rule:      "outside-read",
		})
		done <- res
	}()
	waitForPending(t, m, 1)
	if ok := m.ResolveForSessionWithScopeTarget("s1", "a-tree", true, "ok", ScopeOnce, tree); !ok {
		t.Fatal("failed to resolve approval with once tree target")
	}
	select {
	case res := <-done:
		if !res.Approved || res.Scope != ScopeOnce || res.ScopeKey != tree.Key {
			t.Fatalf("resolution = %+v, want approved once with tree target", res)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for resolution")
	}

	for _, p := range []string{
		"/workspace/pkg/sub/file.go",
		"/workspace/pkg/sibling.go",
	} {
		file, ok := NewFileScopeWithRule("read", p, "outside-read")
		if !ok {
			t.Fatalf("NewFileScopeWithRule(%q) returned !ok", p)
		}
		dec, ok := m.CheckScoped(ctx, "s1", "cmd1", file)
		if !ok || !dec.Approved || dec.Key != tree.Key {
			t.Fatalf("tree command-scoped approval did not match %s: ok=%v dec=%+v", p, ok, dec)
		}
	}

	if got := countEventsByType(em.events, "approval_command_scope_used"); got < 2 {
		t.Fatalf("approval_command_scope_used count = %d, want at least 2", got)
	}
}

func TestFileDirCommandScopedDecisionMatchesOnlyFirstLevelWithinCommand(t *testing.T) {
	ctx := context.Background()
	em := &stubEmitter{}
	m := New("api", 0, em)

	dir, ok := NewFileDirScope("read", "/workspace/vendor", "outside-read")
	if !ok {
		t.Fatal("NewFileDirScope returned !ok")
	}
	m.SetCommandScoped(ctx, "s1", "cmd1", dir, true, "ok", "outside-read")

	direct, ok := NewFileScopeWithRule("read", "/workspace/vendor/README.md", "outside-read")
	if !ok {
		t.Fatal("NewFileScopeWithRule direct returned !ok")
	}
	dec, ok := m.CheckScoped(ctx, "s1", "cmd1", direct)
	if !ok || !dec.Approved || dec.Key != dir.Key {
		t.Fatalf("dir command-scoped approval did not match direct child: ok=%v dec=%+v", ok, dec)
	}
	if got := countEventsByType(em.events, "approval_command_scope_used"); got < 1 {
		t.Fatalf("approval_command_scope_used count = %d, want at least 1", got)
	}

	nested, ok := NewFileScopeWithRule("read", "/workspace/vendor/subdir/file.txt", "outside-read")
	if !ok {
		t.Fatal("NewFileScopeWithRule nested returned !ok")
	}
	if _, ok := m.CheckScoped(ctx, "s1", "cmd1", nested); ok {
		t.Fatal("first-level command-scoped directory approval must not match nested descendants")
	}
}

func TestFileDirAndTreeCommandScopedDecisionsDoNotMatchDifferentCommand(t *testing.T) {
	ctx := context.Background()
	m := New("api", 0, nil)

	tree, ok := NewFileTreeScope("read", "/workspace/pkg", "outside-read")
	if !ok {
		t.Fatal("NewFileTreeScope returned !ok")
	}
	dir, ok := NewFileDirScope("read", "/workspace/vendor", "outside-read")
	if !ok {
		t.Fatal("NewFileDirScope returned !ok")
	}
	m.SetCommandScoped(ctx, "s1", "cmd1", tree, true, "ok", "outside-read")
	m.SetCommandScoped(ctx, "s1", "cmd1", dir, true, "ok", "outside-read")

	pkgFile, _ := NewFileScopeWithRule("read", "/workspace/pkg/sub/file.go", "outside-read")
	vendorFile, _ := NewFileScopeWithRule("read", "/workspace/vendor/README.md", "outside-read")
	for _, file := range []Scope{pkgFile, vendorFile} {
		if _, ok := m.CheckScoped(ctx, "s1", "cmd2", file); ok {
			t.Fatalf("different command unexpectedly used command-scoped decision for %+v", file)
		}
	}
}

func TestFileTreeCommandScopedDecisionRequiresMatchingRule(t *testing.T) {
	ctx := context.Background()
	m := New("api", 0, nil)

	tree, ok := NewFileTreeScope("read", "/workspace/pkg", "outside-read")
	if !ok {
		t.Fatal("NewFileTreeScope returned !ok")
	}
	m.SetCommandScoped(ctx, "s1", "cmd1", tree, true, "ok", "outside-read")

	sensitive, ok := NewFileScopeWithRule("read", "/workspace/pkg/.env", "approve-env-files")
	if !ok {
		t.Fatal("NewFileScopeWithRule sensitive returned !ok")
	}
	if _, ok := m.CheckScoped(ctx, "s1", "cmd1", sensitive); ok {
		t.Fatal("command-scoped tree approval with one rule must not satisfy a different rule")
	}
}

func TestDeniedFileTreeCommandScopedDecisionDoesNotLeakToLaterCommands(t *testing.T) {
	ctx := context.Background()
	m := New("api", 0, nil)

	tree, ok := NewFileTreeScope("read", "/workspace/pkg", "outside-read")
	if !ok {
		t.Fatal("NewFileTreeScope returned !ok")
	}
	m.SetCommandScoped(ctx, "s1", "cmd1", tree, false, "denied", "outside-read")

	file, ok := NewFileScopeWithRule("read", "/workspace/pkg/sub/file.go", "outside-read")
	if !ok {
		t.Fatal("NewFileScopeWithRule returned !ok")
	}
	dec, ok := m.CheckScoped(ctx, "s1", "cmd1", file)
	if !ok || dec.Approved {
		t.Fatalf("denied command-scoped tree decision = %+v ok=%v, want denied hit", dec, ok)
	}
	if _, ok := m.CheckScoped(ctx, "s1", "cmd2", file); ok {
		t.Fatal("denied command-scoped tree decision leaked to later command")
	}
}

func countEventsByType(events []types.Event, eventType string) int {
	count := 0
	for _, ev := range events {
		if ev.Type == eventType {
			count++
		}
	}
	return count
}
