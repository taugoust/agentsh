package api

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestApplyCommandApproval_UsesSessionScopedCommandApproval(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	app := newTestApp(t, sessions, store)
	app.approvals = approvals.New("api", time.Minute, nil)

	sess, err := sessions.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}
	scope, ok := approvals.NewCommandScope("git", []string{"status", "--short"}, "approve-git")
	if !ok {
		t.Fatal("NewCommandScope returned !ok")
	}
	app.approvals.SetScoped(context.Background(), sess.ID, "cmd-prev", scope, true, "ok", "approve-git")

	pre := policy.Decision{
		PolicyDecision:    types.DecisionApprove,
		EffectiveDecision: types.DecisionApprove,
		Rule:              "approve-git",
		Approval:          &types.ApprovalInfo{Required: true, Mode: types.ApprovalModeEnforced},
	}
	if err := app.applyCommandApproval(context.Background(), sess.ID, "cmd-now", "git", []string{"status", "--short"}, nil, &pre); err != nil {
		t.Fatalf("applyCommandApproval: %v", err)
	}
	if pre.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("effective decision = %s, want allow", pre.EffectiveDecision)
	}
}

func TestApplyCommandApproval_RequestIncludesCommandSessionScope(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	app := newTestApp(t, sessions, store)
	app.approvals = approvals.New("api", time.Minute, nil)

	sess, err := sessions.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}

	pre := policy.Decision{
		PolicyDecision:    types.DecisionApprove,
		EffectiveDecision: types.DecisionApprove,
		Rule:              "approve-git",
		Approval:          &types.ApprovalInfo{Required: true, Mode: types.ApprovalModeEnforced},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- app.applyCommandApproval(ctx, sess.ID, "cmd-now", "git", []string{"status", "--short"}, map[string]any{"kind": "test"}, &pre)
	}()

	req := waitPendingCommandApproval(t, ctx, app.approvals, sess.ID)
	if req.Kind != "command" || req.Target != "git" || req.Rule != "approve-git" {
		t.Fatalf("unexpected approval request: %+v", req)
	}
	if req.Fields["command"] != "git" {
		t.Fatalf("command field = %#v", req.Fields["command"])
	}
	if req.Fields["scope_kind"] != "command" || req.Fields["scope_operation"] != "exec" || req.Fields["scope_rule"] != "approve-git" {
		t.Fatalf("missing command scope fields: %#v", req.Fields)
	}
	scope := approvals.Scope{
		Kind:      req.Fields["scope_kind"].(string),
		Key:       req.Fields["scope_key"].(string),
		Label:     req.Fields["scope_label"].(string),
		Operation: req.Fields["scope_operation"].(string),
		Rule:      req.Fields["scope_rule"].(string),
	}
	if !app.approvals.ResolveForSessionWithScopeTarget(sess.ID, req.ID, true, "ok", approvals.ScopeSession, scope) {
		t.Fatal("ResolveForSessionWithScopeTarget returned false")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("applyCommandApproval returned error: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for command approval")
	}
	if pre.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("effective decision = %s, want allow", pre.EffectiveDecision)
	}
	if pre.Approval == nil || pre.Approval.ID != req.ID {
		t.Fatalf("approval ID not recorded: %+v", pre.Approval)
	}
	if cached, ok := app.approvals.CheckScoped(context.Background(), sess.ID, "cmd-next", scope); !ok || !cached.Approved {
		t.Fatalf("session-scoped command approval was not cached: ok=%v cached=%+v", ok, cached)
	}
}

func waitPendingCommandApproval(t *testing.T, ctx context.Context, mgr *approvals.Manager, sessionID string) approvals.Request {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		pending := mgr.ListPendingForSession(sessionID)
		if len(pending) > 0 {
			return pending[0]
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for pending approval: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}
