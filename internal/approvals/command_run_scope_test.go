package approvals

import (
	"context"
	"testing"
	"time"
)

func commandRunTestRequest(id, commandID, kind, target string, scope Scope) Request {
	fields := ScopeFields(scope)
	return Request{
		ID:        id,
		SessionID: "session-command-run",
		CommandID: commandID,
		Kind:      kind,
		Target:    target,
		Rule:      scope.Rule,
		Fields:    fields,
	}
}

func TestCommandRunScopeAdvertisedAsCommandLifetime(t *testing.T) {
	m := New("api", time.Minute, nil)
	scope, ok := NewFileScopeWithRule("read", "/workspace/input.txt", "approve-read")
	if !ok {
		t.Fatal("NewFileScopeWithRule returned !ok")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan Resolution, 1)
	go func() {
		res, _ := m.RequestApproval(ctx, commandRunTestRequest("advertised", "command-1", "file", scope.Path, scope))
		done <- res
	}()
	waitForPending(t, m, 1)
	pending := m.ListPendingForSession("session-command-run")
	if len(pending) != 1 {
		t.Fatalf("pending = %+v", pending)
	}
	options, ok := pending[0].Fields["scope_options"].([]map[string]any)
	if !ok {
		t.Fatalf("scope_options type = %T", pending[0].Fields["scope_options"])
	}
	found := false
	for _, option := range options {
		if option["scope_kind"] == CommandRunScopeKind && option["scope_key"] == CommandRunScopeKey {
			found = option["scope_lifetime"] == "command"
		}
	}
	if !found {
		t.Fatalf("command-run option missing from %#v", options)
	}
	if !m.ResolveForSession("session-command-run", "advertised", false, "test cleanup") {
		t.Fatal("cleanup resolution failed")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for cleanup resolution")
	}
}

func TestCommandRunScopeCoversPendingAndFutureRequestsOnlyForSameCommand(t *testing.T) {
	em := &stubEmitter{}
	m := New("api", time.Minute, em)
	ctx := context.Background()
	commandID := "command-compound"
	fileScope, _ := NewFileScopeWithRule("read", "/workspace/input.txt", "approve-read")
	networkScope, _ := NewNetworkScope("example.com", 443)

	requests := []Request{
		commandRunTestRequest("file-request", commandID, "file", fileScope.Path, fileScope),
		commandRunTestRequest("network-request", commandID, "network", networkScope.Label, networkScope),
	}
	results := make(chan Resolution, len(requests))
	for _, request := range requests {
		go func() {
			res, _ := m.RequestApproval(ctx, request)
			results <- res
		}()
	}
	waitForPending(t, m, len(requests))
	commandRun := NewCommandRunScope()
	if !m.ResolveForSessionWithScopeTarget("session-command-run", "file-request", true, "operator approved invocation", ScopeOnce, commandRun) {
		t.Fatal("command-run resolution failed")
	}
	if pending := m.ListPendingForSession("session-command-run"); len(pending) != 0 {
		t.Fatalf("same-command pending requests remain: %+v", pending)
	}
	for range requests {
		select {
		case res := <-results:
			if !res.Approved || res.Scope != ScopeOnce || res.ScopeKind != CommandRunScopeKind || res.ScopeKey != CommandRunScopeKey {
				t.Fatalf("covered resolution = %+v", res)
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for command-wide pending resolution")
		}
	}

	futureScope, _ := NewCommandExecutableScope("command2", "approve-command")
	future := commandRunTestRequest("future-request", commandID, "command", "command2", futureScope)
	start := time.Now()
	futureRes, err := m.RequestApproval(ctx, future)
	if err != nil || !futureRes.Approved || futureRes.ScopeKey != CommandRunScopeKey {
		t.Fatalf("future same-command request = %+v, err=%v", futureRes, err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("future same-command request was not resolved from cache")
	}
	if got := countEventsByType(em.events, "approval_command_scope_granted"); got < 1 {
		t.Fatalf("command-wide grant audit events = %d, want at least 1", got)
	}
	if got := countEventsByType(em.events, "approval_command_scope_used"); got < 1 {
		t.Fatalf("command-wide use audit events = %d, want at least 1", got)
	}

	otherCtx, cancelOther := context.WithCancel(context.Background())
	otherDone := make(chan Resolution, 1)
	other := commandRunTestRequest("other-command-request", "command-other", "command", "command2", futureScope)
	go func() {
		res, _ := m.RequestApproval(otherCtx, other)
		otherDone <- res
	}()
	waitForPending(t, m, 1)
	pending := m.ListPendingForSession("session-command-run")
	if len(pending) != 1 || pending[0].ID != other.ID {
		t.Fatalf("command-wide grant leaked to another command: %+v", pending)
	}
	cancelOther()
	select {
	case <-otherDone:
	case <-time.After(time.Second):
		t.Fatal("timed out cancelling other-command request")
	}
}

func TestCommandRunScopeCannotBecomeSessionGrant(t *testing.T) {
	m := New("api", time.Minute, nil)
	ctx := context.Background()
	commandRun := NewCommandRunScope()
	if m.SetScoped(ctx, "session-command-run", "command-1", commandRun, true, "bad session grant", "") {
		t.Fatal("command-run scope was accepted as a session grant")
	}
	if _, ok := m.CheckScoped(ctx, "session-command-run", "command-2", commandRun); ok {
		t.Fatal("command-run scope was usable at session lifetime")
	}
}
