package approvals

import (
	"context"
	"testing"
	"time"
)

func TestResolveSessionScopeStoresScopedDecision(t *testing.T) {
	m := New("api", time.Minute, nil)
	ctx := context.Background()
	scope, ok := NewNetworkScope("Example.COM", 443)
	if !ok {
		t.Fatal("failed to build scope")
	}

	done := make(chan Resolution, 1)
	go func() {
		res, _ := m.RequestApproval(ctx, Request{
			ID:        "a1",
			SessionID: "s1",
			Kind:      "network",
			Target:    scope.Label,
			Rule:      "approve-https",
			Fields:    scopeFields(scope),
		})
		done <- res
	}()
	waitForPending(t, m, 1)

	if ok := m.ResolveForSessionWithScope("s1", "a1", true, "operator", ScopeSession); !ok {
		t.Fatal("failed to resolve approval with session scope")
	}
	select {
	case res := <-done:
		if !res.Approved || res.Scope != ScopeSession {
			t.Fatalf("resolution = %+v, want approved session scope", res)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for resolution")
	}

	dec, ok := m.CheckScoped(ctx, "s1", "cmd2", scope)
	if !ok || !dec.Approved || dec.Key != scope.Key || dec.Rule != "approve-https" {
		t.Fatalf("scoped decision = %+v ok=%v", dec, ok)
	}
	if _, ok := m.CheckScoped(ctx, "s2", "cmd", scope); ok {
		t.Fatal("different session unexpectedly used scoped decision")
	}
	different, _ := NewNetworkScope("example.org", 443)
	if _, ok := m.CheckScoped(ctx, "s1", "cmd", different); ok {
		t.Fatal("different scope unexpectedly used scoped decision")
	}
}

func TestResolveOnceDoesNotStoreScopedDecision(t *testing.T) {
	m := New("api", time.Minute, nil)
	ctx := context.Background()
	scope, _ := NewNetworkScope("example.com", 443)

	done := make(chan Resolution, 1)
	go func() {
		res, _ := m.RequestApproval(ctx, Request{ID: "a1", SessionID: "s1", Kind: "network", Fields: scopeFields(scope)})
		done <- res
	}()
	waitForPending(t, m, 1)
	if ok := m.ResolveForSession("s1", "a1", true, "once"); !ok {
		t.Fatal("failed to resolve approval")
	}
	<-done
	if _, ok := m.CheckScoped(ctx, "s1", "cmd", scope); ok {
		t.Fatal("one-shot approval unexpectedly stored scoped decision")
	}
}

func TestDenyForSessionAndClearSession(t *testing.T) {
	m := New("api", time.Minute, nil)
	ctx := context.Background()
	scope, _ := NewNetworkScope("example.com", 443)
	m.SetScoped(ctx, "s1", "cmd", scope, false, "denied", "r")
	dec, ok := m.CheckScoped(ctx, "s1", "cmd2", scope)
	if !ok || dec.Approved {
		t.Fatalf("expected cached denial, got %+v ok=%v", dec, ok)
	}
	m.ClearSession(ctx, "s1")
	if _, ok := m.CheckScoped(ctx, "s1", "cmd3", scope); ok {
		t.Fatal("scoped decision was not cleared")
	}
}

func TestInvalidResolutionScopeRejected(t *testing.T) {
	m := New("api", time.Minute, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timed out waiting for pending approval cleanup")
		}
	})
	go func() {
		defer close(done)
		_, _ = m.RequestApproval(ctx, Request{ID: "a1", SessionID: "s1", Kind: "network"})
	}()
	waitForPending(t, m, 1)
	if ok := m.ResolveForSessionWithScope("s1", "a1", true, "bad", "forever"); ok {
		t.Fatal("invalid scope unexpectedly resolved approval")
	}
	if got := m.ListPendingForSession("s1"); len(got) != 1 || got[0].ID != "a1" {
		t.Fatalf("approval should still be pending, got %+v", got)
	}
}
