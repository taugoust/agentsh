package api

import (
	"context"
	"encoding/json"
	"strings"
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
	scope, ok := approvals.NewCommandExecutableScope("git", "approve-git")
	if !ok {
		t.Fatal("NewCommandExecutableScope returned !ok")
	}
	app.approvals.SetScoped(context.Background(), sess.ID, "cmd-prev", scope, true, "ok", "approve-git")

	pre := commandApprovalDecision("approve-git")
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

	pre := commandApprovalDecision("approve-git")
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
	if req.Fields["scope_kind"] != "command" || req.Fields["scope_operation"] != "exec" || req.Fields["scope_rule"] != "approve-git" || req.Fields["scope_path"] != "git" {
		t.Fatalf("missing command executable scope fields: %#v", req.Fields)
	}
	if key, _ := req.Fields["scope_key"].(string); !strings.HasPrefix(key, "command-executable:") {
		t.Fatalf("scope_key = %q, want executable scope", key)
	}
	options := commandScopeOptionsFromRequest(t, req)
	if len(options) != 3 {
		t.Fatalf("scope_options len = %d, want 3: %#v", len(options), options)
	}
	if key, _ := options[0]["scope_key"].(string); !strings.HasPrefix(key, "command-executable:") {
		t.Fatalf("first option key = %q, want executable", key)
	}
	if key, _ := options[1]["scope_key"].(string); !strings.HasPrefix(key, "command-invocation:") {
		t.Fatalf("second option key = %q, want invocation", key)
	}
	if key, _ := options[2]["scope_key"].(string); !strings.HasPrefix(key, "command-run:") {
		t.Fatalf("third option key = %q, want command-run", key)
	}
	if !app.approvals.ResolveForSessionWithScope(sess.ID, req.ID, true, "ok", approvals.ScopeSession) {
		t.Fatal("ResolveForSessionWithScope returned false")
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
	scope, ok := approvals.NewCommandExecutableScope("git", "approve-git")
	if !ok {
		t.Fatal("NewCommandExecutableScope returned !ok")
	}
	if cached, ok := app.approvals.CheckScoped(context.Background(), sess.ID, "cmd-next", scope); !ok || !cached.Approved {
		t.Fatalf("session-scoped command approval was not cached: ok=%v cached=%+v", ok, cached)
	}
}

func TestApplyCommandApproval_ApproveExecutableForSessionAllowsDifferentArgs(t *testing.T) {
	app, sess := newCommandApprovalTestApp(t)
	command := "/nix/store/abc-sqlite/bin/sqlite3"

	pre := commandApprovalDecision("approve-unknown-nix-store-executables")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- app.applyCommandApproval(ctx, sess.ID, "cmd-1", command, []string{"events.db", "select * from events limit 10"}, nil, &pre)
	}()

	req := waitPendingCommandApproval(t, ctx, app.approvals, sess.ID)
	if req.Fields["scope_path"] != command || req.Fields["scope_label"] != command {
		t.Fatalf("default scope should identify executable path, fields=%#v", req.Fields)
	}
	if key, _ := req.Fields["scope_key"].(string); !strings.HasPrefix(key, "command-executable:") {
		t.Fatalf("scope_key = %q, want executable scope", key)
	}
	if !app.approvals.ResolveForSessionWithScope(sess.ID, req.ID, true, "ok", approvals.ScopeSession) {
		t.Fatal("ResolveForSessionWithScope returned false")
	}
	waitApplyDone(t, ctx, done)

	pre2 := commandApprovalDecision("approve-unknown-nix-store-executables")
	if err := app.applyCommandApproval(ctx, sess.ID, "cmd-2", command, []string{"-readonly", "events.db", "select * from events limit 50"}, nil, &pre2); err != nil {
		t.Fatalf("second applyCommandApproval: %v", err)
	}
	if pre2.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("second effective decision = %s, want allow", pre2.EffectiveDecision)
	}
	if pending := app.approvals.ListPendingForSession(sess.ID); len(pending) != 0 {
		t.Fatalf("unexpected pending approvals after cached executable approval: %+v", pending)
	}
}

func TestApplyCommandApproval_DifferentExecutableStillPrompts(t *testing.T) {
	app, sess := newCommandApprovalTestApp(t)
	sqlite := "/nix/store/abc-sqlite/bin/sqlite3"
	psql := "/nix/store/def-postgresql/bin/psql"
	scope, ok := approvals.NewCommandExecutableScope(sqlite, "approve-unknown-nix-store-executables")
	if !ok {
		t.Fatal("NewCommandExecutableScope returned !ok")
	}
	app.approvals.SetScoped(context.Background(), sess.ID, "cmd-prev", scope, true, "ok", "approve-unknown-nix-store-executables")

	pre := commandApprovalDecision("approve-unknown-nix-store-executables")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- app.applyCommandApproval(ctx, sess.ID, "cmd-psql", psql, []string{"events.db", "select 1"}, nil, &pre)
	}()

	req := waitPendingCommandApproval(t, ctx, app.approvals, sess.ID)
	if req.Target != psql {
		t.Fatalf("pending target = %q, want %q", req.Target, psql)
	}
	if !app.approvals.ResolveForSession(sess.ID, req.ID, false, "no") {
		t.Fatal("ResolveForSession returned false")
	}
	_ = waitApplyDone(t, ctx, done)
}

func TestResolveApprovalLocal_PiSelectedExecutableSessionScopeResolvesConcurrentPending(t *testing.T) {
	app, sess := newCommandApprovalTestApp(t)
	command := "/nix/store/abc-sqlite/bin/sqlite3"
	rule := "approve-unknown-nix-store-executables"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pre1 := commandApprovalDecision(rule)
	done1 := make(chan error, 1)
	go func() {
		done1 <- app.applyCommandApproval(ctx, sess.ID, "cmd-1", command, []string{"events.db", "select 1"}, nil, &pre1)
	}()
	pre2 := commandApprovalDecision(rule)
	done2 := make(chan error, 1)
	go func() {
		done2 <- app.applyCommandApproval(ctx, sess.ID, "cmd-2", command, []string{"-readonly", "events.db", "select 2"}, nil, &pre2)
	}()

	reqs := waitPendingCommandApprovals(t, ctx, app.approvals, sess.ID, 2)
	executable := findCommandScopeOption(t, reqs[0], "command-executable:")
	status, body, handled := app.resolveApprovalLocal(reqs[0].ID, approvalResolutionJSON(t, "approve", approvals.ScopeSession, executable))
	if !handled || status != 200 || body["ok"] != true {
		t.Fatalf("resolveApprovalLocal status=%d handled=%v body=%#v", status, handled, body)
	}
	if pending := app.approvals.ListPendingForSession(sess.ID); len(pending) != 0 {
		t.Fatalf("covered pending approvals still listed immediately after local resolve: %+v", pending)
	}

	waitApplyDone(t, ctx, done1)
	waitApplyDone(t, ctx, done2)
	if pre1.EffectiveDecision != types.DecisionAllow || pre2.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("effective decisions = %s/%s, want allow/allow", pre1.EffectiveDecision, pre2.EffectiveDecision)
	}
	if pending := app.approvals.ListPendingForSession(sess.ID); len(pending) != 0 {
		t.Fatalf("covered pending approvals were not cleared: %+v", pending)
	}
}

func TestApprovalUIResolve_PiSelectedExecutableSessionScopeResolvesConcurrentPending(t *testing.T) {
	app, sess := newCommandApprovalTestApp(t)
	command := "/nix/store/abc-sqlite/bin/sqlite3"
	rule := "approve-unknown-nix-store-executables"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pre1 := commandApprovalDecision(rule)
	done1 := make(chan error, 1)
	go func() {
		done1 <- app.applyCommandApproval(ctx, sess.ID, "cmd-1", command, []string{"events.db", "select 1"}, nil, &pre1)
	}()
	pre2 := commandApprovalDecision(rule)
	done2 := make(chan error, 1)
	go func() {
		done2 <- app.applyCommandApproval(ctx, sess.ID, "cmd-2", command, []string{"-readonly", "events.db", "select 2"}, nil, &pre2)
	}()

	reqs := waitPendingCommandApprovals(t, ctx, app.approvals, sess.ID, 2)
	executable := findCommandScopeOption(t, reqs[0], "command-executable:")
	ui := &approvalUIEndpoint{sessionID: sess.ID, app: app}
	resp := ui.handleRequest(approvalUIRequest{
		Op:             "resolve",
		ID:             reqs[0].ID,
		Decision:       "approve",
		Scope:          approvals.ScopeSession,
		Reason:         "approved in parent Pi",
		ScopeKind:      executable.Kind,
		ScopeKey:       executable.Key,
		ScopeLabel:     executable.Label,
		ScopeOperation: executable.Operation,
		ScopePath:      executable.Path,
		ScopeRule:      executable.Rule,
		ScopePrefix:    executable.Prefix,
	})
	if !resp.OK {
		t.Fatalf("approval UI resolve failed: %+v", resp)
	}
	if pending := app.approvals.ListPendingForSession(sess.ID); len(pending) != 0 {
		t.Fatalf("covered pending approvals still listed immediately after approval UI resolve: %+v", pending)
	}

	waitApplyDone(t, ctx, done1)
	waitApplyDone(t, ctx, done2)
	if pre1.EffectiveDecision != types.DecisionAllow || pre2.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("effective decisions = %s/%s, want allow/allow", pre1.EffectiveDecision, pre2.EffectiveDecision)
	}
	if pending := app.approvals.ListPendingForSession(sess.ID); len(pending) != 0 {
		t.Fatalf("covered pending approvals were not cleared: %+v", pending)
	}
}

func TestApplyCommandApproval_ExactInvocationSessionScopeIsNarrow(t *testing.T) {
	app, sess := newCommandApprovalTestApp(t)
	command := "sqlite3"
	rule := "approve-sqlite"
	args := []string{"events.db", "select 1"}

	pre := commandApprovalDecision(rule)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- app.applyCommandApproval(ctx, sess.ID, "cmd-1", command, args, nil, &pre)
	}()

	req := waitPendingCommandApproval(t, ctx, app.approvals, sess.ID)
	exact := findCommandScopeOption(t, req, "command-invocation:")
	if !app.approvals.ResolveForSessionWithScopeTarget(sess.ID, req.ID, true, "exact", approvals.ScopeSession, exact) {
		t.Fatal("ResolveForSessionWithScopeTarget returned false")
	}
	waitApplyDone(t, ctx, done)

	preSame := commandApprovalDecision(rule)
	if err := app.applyCommandApproval(ctx, sess.ID, "cmd-2", command, args, nil, &preSame); err != nil {
		t.Fatalf("same invocation applyCommandApproval: %v", err)
	}
	if preSame.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("same invocation effective decision = %s, want allow", preSame.EffectiveDecision)
	}

	preDifferent := commandApprovalDecision(rule)
	differentDone := make(chan error, 1)
	go func() {
		differentDone <- app.applyCommandApproval(ctx, sess.ID, "cmd-3", command, []string{"events.db", "select 2"}, nil, &preDifferent)
	}()
	differentReq := waitPendingCommandApproval(t, ctx, app.approvals, sess.ID)
	if differentReq.ID == req.ID {
		t.Fatal("different invocation reused original approval request")
	}
	if !app.approvals.ResolveForSession(sess.ID, differentReq.ID, false, "no") {
		t.Fatal("ResolveForSession returned false")
	}
	_ = waitApplyDone(t, ctx, differentDone)
}

func newCommandApprovalTestApp(t *testing.T) (*App, *session.Session) {
	t.Helper()
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	app := newTestApp(t, sessions, store)
	app.approvals = approvals.New("api", time.Minute, nil)
	sess, err := sessions.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}
	return app, sess
}

func commandApprovalDecision(rule string) policy.Decision {
	return policy.Decision{
		PolicyDecision:    types.DecisionApprove,
		EffectiveDecision: types.DecisionApprove,
		Rule:              rule,
		Approval:          &types.ApprovalInfo{Required: true, Mode: types.ApprovalModeEnforced},
	}
}

func commandScopeOptionsFromRequest(t *testing.T, req approvals.Request) []map[string]any {
	t.Helper()
	options, ok := req.Fields["scope_options"].([]map[string]any)
	if !ok {
		t.Fatalf("scope_options has type %T: %#v", req.Fields["scope_options"], req.Fields["scope_options"])
	}
	return options
}

func findCommandScopeOption(t *testing.T, req approvals.Request, keyPrefix string) approvals.Scope {
	t.Helper()
	for _, option := range commandScopeOptionsFromRequest(t, req) {
		key, _ := option["scope_key"].(string)
		if strings.HasPrefix(key, keyPrefix) {
			return approvalScopeFromFields(t, option)
		}
	}
	t.Fatalf("scope option with prefix %q not found in %#v", keyPrefix, req.Fields["scope_options"])
	return approvals.Scope{}
}

func approvalScopeFromFields(t *testing.T, fields map[string]any) approvals.Scope {
	t.Helper()
	scope := approvals.Scope{
		Kind:      stringField(t, fields, "scope_kind"),
		Key:       stringField(t, fields, "scope_key"),
		Label:     stringField(t, fields, "scope_label"),
		Operation: optionalStringField(fields, "scope_operation"),
		Path:      optionalStringField(fields, "scope_path"),
		Rule:      optionalStringField(fields, "scope_rule"),
	}
	if prefix, ok := fields["scope_prefix"].(bool); ok {
		scope.Prefix = prefix
	}
	return scope
}

func stringField(t *testing.T, fields map[string]any, key string) string {
	t.Helper()
	value, ok := fields[key].(string)
	if !ok || value == "" {
		t.Fatalf("field %q = %#v", key, fields[key])
	}
	return value
}

func optionalStringField(fields map[string]any, key string) string {
	value, _ := fields[key].(string)
	return value
}

func waitApplyDone(t *testing.T, ctx context.Context, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("applyCommandApproval returned error: %v", err)
		}
		return err
	case <-ctx.Done():
		t.Fatalf("timed out waiting for command approval: %v", ctx.Err())
		return ctx.Err()
	}
}

func approvalResolutionJSON(t *testing.T, decision string, scope string, target approvals.Scope) []byte {
	t.Helper()
	body := map[string]any{
		"decision":        decision,
		"scope":           scope,
		"reason":          "approved in parent Pi",
		"scope_kind":      target.Kind,
		"scope_key":       target.Key,
		"scope_label":     target.Label,
		"scope_operation": target.Operation,
		"scope_path":      target.Path,
		"scope_rule":      target.Rule,
		"scope_prefix":    target.Prefix,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal approval resolution: %v", err)
	}
	return raw
}

func waitPendingCommandApproval(t *testing.T, ctx context.Context, mgr *approvals.Manager, sessionID string) approvals.Request {
	t.Helper()
	return waitPendingCommandApprovals(t, ctx, mgr, sessionID, 1)[0]
}

func waitPendingCommandApprovals(t *testing.T, ctx context.Context, mgr *approvals.Manager, sessionID string, want int) []approvals.Request {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		pending := mgr.ListPendingForSession(sessionID)
		if len(pending) >= want {
			return pending
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %d pending approvals: %v (got %d)", want, ctx.Err(), len(pending))
		case <-ticker.C:
		}
	}
}
