package approvals

import (
	"context"
	"testing"
	"time"
)

func TestManagerListPendingForSessionFilters(t *testing.T) {
	m := New("api", time.Minute, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{}, 2)
	t.Cleanup(func() {
		cancel()
		for range 2 {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("timed out waiting for pending approval cleanup")
			}
		}
	})

	go func() {
		defer func() { done <- struct{}{} }()
		_, _ = m.RequestApproval(ctx, Request{ID: "a1", SessionID: "s1", Kind: "command"})
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		_, _ = m.RequestApproval(ctx, Request{ID: "a2", SessionID: "s2", Kind: "network"})
	}()

	waitForPending(t, m, 2)

	got := m.ListPendingForSession("s1")
	if len(got) != 1 || got[0].ID != "a1" {
		t.Fatalf("ListPendingForSession(s1) = %+v, want only a1", got)
	}
}

func TestManagerResolveForSessionRejectsOtherSession(t *testing.T) {
	m := New("api", time.Minute, nil)
	ctx := context.Background()

	done := make(chan Resolution, 1)
	go func() {
		res, _ := m.RequestApproval(ctx, Request{ID: "a1", SessionID: "s1", Kind: "command"})
		done <- res
	}()
	waitForPending(t, m, 1)

	if ok := m.ResolveForSession("s2", "a1", true, "wrong session"); ok {
		t.Fatal("ResolveForSession unexpectedly resolved approval for another session")
	}
	if got := m.ListPendingForSession("s1"); len(got) != 1 || got[0].ID != "a1" {
		t.Fatalf("approval should remain pending for s1, got %+v", got)
	}
	if ok := m.ResolveForSession("s1", "a1", true, "right session"); !ok {
		t.Fatal("ResolveForSession did not resolve approval for matching session")
	}

	select {
	case res := <-done:
		if !res.Approved || res.Reason != "right session" {
			t.Fatalf("resolution = %+v, want approved with matching reason", res)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for approval resolution")
	}
}

func waitForPending(t *testing.T, m *Manager, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if got := len(m.ListPending()); got == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d pending approvals, got %d", want, len(m.ListPending()))
}
