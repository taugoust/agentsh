package approvals

import (
	"context"
	"testing"
	"time"
)

func TestSessionCommandScopeResolutionCoversConcurrentPendingApprovals(t *testing.T) {
	m := New("api", time.Minute, nil)
	ctx := context.Background()
	command := "/nix/store/abc-sqlite/bin/sqlite3"
	rule := "approve-unknown-nix-store-executables"
	executable, ok := NewCommandExecutableScope(command, rule)
	if !ok {
		t.Fatal("NewCommandExecutableScope returned !ok")
	}

	request := func(id string, args []string) Request {
		fields := map[string]any{"command": command, "args": args}
		for k, v := range ScopeFields(executable) {
			fields[k] = v
		}
		options := []map[string]any{ScopeFields(executable)}
		if invocation, ok := NewCommandInvocationScope(command, args, rule); ok {
			options = append(options, ScopeFields(invocation))
		}
		fields["scope_options"] = options
		return Request{ID: id, SessionID: "s1", Kind: "command", Target: command, Rule: rule, Fields: fields}
	}

	done1 := make(chan Resolution, 1)
	go func() {
		res, _ := m.RequestApproval(ctx, request("a1", []string{"events.db", "select 1"}))
		done1 <- res
	}()
	done2 := make(chan Resolution, 1)
	go func() {
		res, _ := m.RequestApproval(ctx, request("a2", []string{"-readonly", "events.db", "select 2"}))
		done2 <- res
	}()
	waitForPending(t, m, 2)

	if ok := m.ResolveForSessionWithScopeTarget("s1", "a1", true, "operator", ScopeSession, executable); !ok {
		t.Fatal("ResolveForSessionWithScopeTarget returned false")
	}
	if pending := m.ListPendingForSession("s1"); len(pending) != 0 {
		t.Fatalf("covered pending approvals still listed immediately after resolve: %+v", pending)
	}

	for name, ch := range map[string]<-chan Resolution{"a1": done1, "a2": done2} {
		select {
		case res := <-ch:
			if !res.Approved || res.Scope != ScopeSession || res.ScopeKey != executable.Key {
				t.Fatalf("%s resolution = %+v, want approved session executable scope", name, res)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for %s to be resolved by session scope", name)
		}
	}
	if pending := m.ListPendingForSession("s1"); len(pending) != 0 {
		t.Fatalf("covered pending approvals were not cleared: %+v", pending)
	}
}

func TestExactCommandScopeResolutionOnlyCoversMatchingConcurrentPendingApproval(t *testing.T) {
	m := New("api", time.Minute, nil)
	ctx := context.Background()
	command := "sqlite3"
	rule := "approve-sqlite"
	args := []string{"events.db", "select 1"}
	executable, _ := NewCommandExecutableScope(command, rule)
	exact, ok := NewCommandInvocationScope(command, args, rule)
	if !ok {
		t.Fatal("NewCommandInvocationScope returned !ok")
	}

	request := func(id string, requestArgs []string) Request {
		fields := map[string]any{"command": command, "args": requestArgs}
		for k, v := range ScopeFields(executable) {
			fields[k] = v
		}
		options := []map[string]any{ScopeFields(executable)}
		if invocation, ok := NewCommandInvocationScope(command, requestArgs, rule); ok {
			options = append(options, ScopeFields(invocation))
		}
		fields["scope_options"] = options
		return Request{ID: id, SessionID: "s1", Kind: "command", Target: command, Rule: rule, Fields: fields}
	}

	doneSame := make(chan Resolution, 1)
	go func() {
		res, _ := m.RequestApproval(ctx, request("same", args))
		doneSame <- res
	}()
	doneDifferent := make(chan Resolution, 1)
	go func() {
		res, _ := m.RequestApproval(ctx, request("different", []string{"events.db", "select 2"}))
		doneDifferent <- res
	}()
	waitForPending(t, m, 2)

	if ok := m.ResolveForSessionWithScopeTarget("s1", "same", true, "operator", ScopeSession, exact); !ok {
		t.Fatal("ResolveForSessionWithScopeTarget returned false")
	}
	select {
	case res := <-doneSame:
		if !res.Approved || res.ScopeKey != exact.Key {
			t.Fatalf("same resolution = %+v, want exact scope", res)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for same invocation")
	}

	select {
	case res := <-doneDifferent:
		t.Fatalf("different invocation was unexpectedly covered by exact session scope: %+v", res)
	case <-time.After(100 * time.Millisecond):
	}
	pending := m.ListPendingForSession("s1")
	if len(pending) != 1 || pending[0].ID != "different" {
		t.Fatalf("different invocation should remain pending, got %+v", pending)
	}
	if ok := m.ResolveForSession("s1", "different", false, "no"); !ok {
		t.Fatal("ResolveForSession for different invocation returned false")
	}
}
