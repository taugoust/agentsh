//go:build linux && cgo

// internal/netmonitor/unix/execve_handler_test.go
package unix

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestExecPathMissing(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "tool")
	if err := os.WriteFile(file, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if execPathMissing(file, ExecveArgs{}) {
		t.Fatalf("existing file reported missing")
	}
	if !execPathMissing(filepath.Join(dir, "missing"), ExecveArgs{}) {
		t.Fatalf("missing file not reported missing")
	}
	if execPathMissing(filepath.Join(dir, "missing"), ExecveArgs{IsExecveat: true, Flags: 0x1000}) {
		t.Fatalf("execveat AT_EMPTY_PATH should not use path existence")
	}
}

func TestResolveExecveRelativePath(t *testing.T) {
	oldwd, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.Chdir(oldwd)) })

	dir := t.TempDir()
	require.NoError(t, os.Chdir(dir))

	got, err := resolveExecveRelativePath(os.Getpid(), "./test-runs/hello")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dir, "test-runs", "hello"), got)

	got, err = resolveExecveRelativePath(os.Getpid(), "result/bin/tool")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dir, "result", "bin", "tool"), got)
}

// mockPolicy implements PolicyChecker for testing
type mockPolicy struct {
	decision PolicyDecision
}

func (m *mockPolicy) CheckExecve(filename string, argv []string, depth int) PolicyDecision {
	return m.decision
}

type mockAliasPolicy struct {
	filename string
	aliases  []string
	argv     []string
	depth    int
	decision PolicyDecision
}

func (m *mockAliasPolicy) CheckExecve(filename string, argv []string, depth int) PolicyDecision {
	m.filename = filename
	m.argv = argv
	m.depth = depth
	return m.decision
}

func (m *mockAliasPolicy) CheckExecveWithAliases(filename string, aliases []string, argv []string, depth int) PolicyDecision {
	m.filename = filename
	m.aliases = aliases
	m.argv = argv
	m.depth = depth
	return m.decision
}

func TestExecveHandler_TrustedAliases(t *testing.T) {
	cfg := ExecveHandlerConfig{MaxArgc: 1000, MaxArgvBytes: 65536}
	pol := &mockAliasPolicy{decision: PolicyDecision{Decision: "allow", EffectiveDecision: "allow", Rule: "allow-rm"}}
	h := NewExecveHandler(cfg, pol, NewDepthTracker(), nil)

	ctx := ExecveContext{
		PID:         1001,
		ParentPID:   1000,
		Filename:    "/nix/store/abc-coreutils-9.11/bin/coreutils",
		RawFilename: "/nix/store/abc-coreutils-9.11/bin/rm",
		Argv:        []string{"rm", "file.txt"},
	}

	result, _ := h.Handle(context.Background(), ctx)
	require.True(t, result.Allow)
	require.Equal(t, "/nix/store/abc-coreutils-9.11/bin/coreutils", pol.filename)
	require.Contains(t, pol.aliases, "/nix/store/abc-coreutils-9.11/bin/rm")
	require.Contains(t, pol.aliases, "rm")
}

func TestExecveHandler_RejectsUncorroboratedArgv0Alias(t *testing.T) {
	aliases := trustedExecveAliases("/tmp/malware", "/tmp/malware", []string{"rm", "file.txt"})
	require.NotContains(t, aliases, "rm")
}

func TestExecveHandler_RejectsUntrustedRawSymlinkAlias(t *testing.T) {
	aliases := trustedExecveAliases("/tmp/malware", "/tmp/rm", []string{"rm", "file.txt"})
	require.NotContains(t, aliases, "/tmp/rm")
	require.NotContains(t, aliases, "rm")
}

func TestExecveHandler_Handle_Allow(t *testing.T) {
	cfg := ExecveHandlerConfig{
		MaxArgc:      1000,
		MaxArgvBytes: 65536,
	}
	pol := &mockPolicy{decision: PolicyDecision{Decision: "allow", Rule: "allow-git"}}
	dt := NewDepthTracker()
	dt.RegisterSession(1000, "sess-123")

	h := NewExecveHandler(cfg, pol, dt, nil)

	ctx := ExecveContext{
		PID:       1001,
		ParentPID: 1000,
		Filename:  "/usr/bin/git",
		Argv:      []string{"git", "status"},
		Truncated: false,
	}

	result, _ := h.Handle(context.Background(), ctx)
	assert.True(t, result.Allow)
	assert.Equal(t, "allow-git", result.Rule)
}

func TestExecveHandler_Handle_Deny(t *testing.T) {
	cfg := ExecveHandlerConfig{
		MaxArgc:      1000,
		MaxArgvBytes: 65536,
	}
	pol := &mockPolicy{decision: PolicyDecision{Decision: "deny", Rule: "block-curl"}}
	dt := NewDepthTracker()
	dt.RegisterSession(1000, "sess-123")

	h := NewExecveHandler(cfg, pol, dt, nil)

	ctx := ExecveContext{
		PID:       1001,
		ParentPID: 1000,
		Filename:  "/usr/bin/curl",
		Argv:      []string{"curl", "http://evil.com"},
		Truncated: false,
	}

	result, _ := h.Handle(context.Background(), ctx)
	assert.False(t, result.Allow)
}

func TestExecveHandler_Handle_TruncatedDeny(t *testing.T) {
	cfg := ExecveHandlerConfig{
		MaxArgc:      1000,
		MaxArgvBytes: 65536,
		OnTruncated:  "deny",
	}
	pol := &mockPolicy{decision: PolicyDecision{Decision: "allow", Rule: "test"}}
	dt := NewDepthTracker()

	h := NewExecveHandler(cfg, pol, dt, nil)

	ctx := ExecveContext{
		PID:       1001,
		ParentPID: 1000,
		Filename:  "/usr/bin/something",
		Argv:      []string{"something"},
		Truncated: true,
	}

	result, _ := h.Handle(context.Background(), ctx)
	assert.False(t, result.Allow)
	assert.Equal(t, "truncated", result.Reason)
}

func TestExecveHandler_Handle_InternalBypass(t *testing.T) {
	cfg := ExecveHandlerConfig{
		InternalBypass: []string{"/usr/local/bin/agentsh"},
	}
	// Policy should NOT be called for internal bypass
	dt := NewDepthTracker()

	h := NewExecveHandler(cfg, nil, dt, nil)

	ctx := ExecveContext{
		PID:       1001,
		ParentPID: 1000,
		Filename:  "/usr/local/bin/agentsh",
		Argv:      []string{"agentsh", "exec"},
		Truncated: false,
	}

	result, _ := h.Handle(context.Background(), ctx)
	assert.True(t, result.Allow)
	assert.Equal(t, "internal_bypass", result.Rule)
}

func TestExecveHandler_InternalBypass(t *testing.T) {
	cfg := ExecveHandlerConfig{
		InternalBypass: []string{
			"/usr/local/bin/agentsh",
			"/usr/local/bin/agentsh-*",
			"*.real",
		},
	}
	h := NewExecveHandler(cfg, nil, nil, nil)

	tests := []struct {
		filename string
		bypass   bool
	}{
		{"/usr/local/bin/agentsh", true},
		{"/usr/local/bin/agentsh-unixwrap", true},
		{"/bin/bash.real", true},
		{"/usr/bin/sh.real", true},
		{"/usr/bin/git", false},
		{"/bin/bash", false},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			assert.Equal(t, tt.bypass, h.isInternalBypass(tt.filename))
		})
	}
}

// TestExecveHandler_Action tests that the Action field is set correctly
// for all decision types in the exec pipeline.
func TestExecveHandler_Action(t *testing.T) {
	t.Run("allow produces ActionContinue", func(t *testing.T) {
		cfg := ExecveHandlerConfig{}
		pol := &mockPolicy{decision: PolicyDecision{
			Decision:          "allow",
			EffectiveDecision: "allow",
			Rule:              "allow-git",
		}}
		dt := NewDepthTracker()
		dt.RegisterSession(1000, "sess-1")
		h := NewExecveHandler(cfg, pol, dt, nil)

		result, _ := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/git",
			Argv:      []string{"git", "status"},
		})

		require.True(t, result.Allow)
		assert.Equal(t, ActionContinue, result.Action)
		assert.Equal(t, "allow", result.Decision)
	})

	t.Run("deny produces ActionDeny with EACCES", func(t *testing.T) {
		cfg := ExecveHandlerConfig{}
		pol := &mockPolicy{decision: PolicyDecision{
			Decision:          "deny",
			EffectiveDecision: "deny",
			Rule:              "block-curl",
			Message:           "not allowed",
		}}
		dt := NewDepthTracker()
		dt.RegisterSession(1000, "sess-1")
		h := NewExecveHandler(cfg, pol, dt, nil)

		result, _ := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/curl",
			Argv:      []string{"curl", "http://evil.com"},
		})

		require.False(t, result.Allow)
		assert.Equal(t, ActionDeny, result.Action)
		assert.Equal(t, int32(unix.EACCES), result.Errno)
		assert.Equal(t, "deny", result.Decision)
	})

	t.Run("approve requests approval and continues when approved", func(t *testing.T) {
		cfg := ExecveHandlerConfig{}
		pol := &mockPolicy{decision: PolicyDecision{
			Decision:          "approve",
			EffectiveDecision: "approve",
			Rule:              "needs-approval",
			Message:           "requires human approval",
		}}
		dt := NewDepthTracker()
		dt.RegisterSession(1000, "sess-1")
		approver := &mockApprover{approved: true}
		h := NewExecveHandler(cfg, pol, dt, nil)
		h.SetApprover(approver)

		result, _ := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/rm",
			Argv:      []string{"rm", "-rf", "/important"},
		})

		require.True(t, approver.called)
		assert.Equal(t, "sess-1", approver.gotReq.SessionID)
		assert.Equal(t, "/usr/bin/rm", approver.gotReq.Command)
		assert.Equal(t, []string{"rm", "-rf", "/important"}, approver.gotReq.Args)
		require.True(t, result.Allow)
		assert.Equal(t, ActionContinue, result.Action)
		assert.Equal(t, "approve", result.Decision)
	})

	t.Run("approve preserves notify session for nested exec when parent was first seen without ancestry", func(t *testing.T) {
		cfg := ExecveHandlerConfig{}
		pol := &mockPolicy{decision: PolicyDecision{
			Decision:          "approve",
			EffectiveDecision: "approve",
			Rule:              "needs-approval",
			Message:           "requires human approval",
		}}
		dt := NewDepthTracker()
		approver := &mockApprover{approved: true}
		h := NewExecveHandler(cfg, pol, dt, nil)
		h.SetApprover(approver)

		result, _ := h.Handle(context.Background(), ExecveContext{
			PID:       2000,
			ParentPID: 9999,
			Filename:  "/nix/store/bash/bin/bash",
			Argv:      []string{"bash", "-c", "sqlite3 -batch :memory: 'select 1'"},
			SessionID: "sess-loop",
		})
		require.True(t, result.Allow)
		require.True(t, approver.called)
		assert.Equal(t, "sess-loop", approver.gotReq.SessionID)

		approver.called = false
		approver.gotReq = ApprovalRequest{}
		result, _ = h.Handle(context.Background(), ExecveContext{
			PID:       2001,
			ParentPID: 2000,
			Filename:  "/nix/store/sqlite/bin/sqlite3",
			Argv:      []string{"sqlite3", "-batch", ":memory:", "select 'run-2', 2 * 2;"},
			SessionID: "sess-loop",
		})
		require.True(t, result.Allow)
		require.True(t, approver.called)
		assert.Equal(t, "sess-loop", approver.gotReq.SessionID)

		state, ok := dt.Get(2001)
		require.True(t, ok)
		assert.Equal(t, "sess-loop", state.SessionID)
	})

	t.Run("approve denies when user denies", func(t *testing.T) {
		cfg := ExecveHandlerConfig{}
		pol := &mockPolicy{decision: PolicyDecision{
			Decision:          "approve",
			EffectiveDecision: "approve",
			Rule:              "needs-approval",
			Message:           "requires human approval",
		}}
		dt := NewDepthTracker()
		dt.RegisterSession(1000, "sess-1")
		approver := &mockApprover{approved: false}
		h := NewExecveHandler(cfg, pol, dt, nil)
		h.SetApprover(approver)

		result, _ := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/rm",
			Argv:      []string{"rm", "-rf", "/important"},
		})

		require.True(t, approver.called)
		require.False(t, result.Allow)
		assert.Equal(t, ActionDeny, result.Action)
		assert.Equal(t, int32(unix.EACCES), result.Errno)
		assert.Equal(t, "approval denied", result.Reason)
	})

	t.Run("redirect produces ActionRedirect", func(t *testing.T) {
		cfg := ExecveHandlerConfig{}
		pol := &mockPolicy{decision: PolicyDecision{
			Decision:          "redirect",
			EffectiveDecision: "redirect",
			Rule:              "redirect-rm",
			Message:           "redirecting to trash",
		}}
		dt := NewDepthTracker()
		dt.RegisterSession(1000, "sess-1")
		h := NewExecveHandler(cfg, pol, dt, nil)

		result, _ := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/rm",
			Argv:      []string{"rm", "file.txt"},
		})

		require.False(t, result.Allow)
		assert.Equal(t, ActionRedirect, result.Action)
		assert.Equal(t, "redirect", result.Decision)
	})

	t.Run("audit with effective allow produces ActionContinue", func(t *testing.T) {
		cfg := ExecveHandlerConfig{}
		pol := &mockPolicy{decision: PolicyDecision{
			Decision:          "audit",
			EffectiveDecision: "allow",
			Rule:              "audit-npm",
			Message:           "logging npm usage",
		}}
		dt := NewDepthTracker()
		dt.RegisterSession(1000, "sess-1")
		h := NewExecveHandler(cfg, pol, dt, nil)

		result, _ := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/npm",
			Argv:      []string{"npm", "install"},
		})

		require.True(t, result.Allow)
		assert.Equal(t, ActionContinue, result.Action)
		assert.Equal(t, "audit", result.Decision)
	})

	t.Run("internal bypass produces ActionContinue", func(t *testing.T) {
		cfg := ExecveHandlerConfig{
			InternalBypass: []string{"/usr/local/bin/agentsh"},
		}
		dt := NewDepthTracker()
		h := NewExecveHandler(cfg, nil, dt, nil)

		result, _ := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/local/bin/agentsh",
			Argv:      []string{"agentsh", "exec"},
		})

		require.True(t, result.Allow)
		assert.Equal(t, ActionContinue, result.Action)
		assert.Equal(t, "internal_bypass", result.Rule)
	})

	t.Run("no policy produces ActionContinue", func(t *testing.T) {
		cfg := ExecveHandlerConfig{}
		dt := NewDepthTracker()
		dt.RegisterSession(1000, "sess-1")
		h := NewExecveHandler(cfg, nil, dt, nil)

		result, _ := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/ls",
			Argv:      []string{"ls"},
		})

		require.True(t, result.Allow)
		assert.Equal(t, ActionContinue, result.Action)
		assert.Equal(t, "no_policy", result.Rule)
	})

	t.Run("truncated deny produces ActionDeny", func(t *testing.T) {
		cfg := ExecveHandlerConfig{OnTruncated: "deny"}
		dt := NewDepthTracker()
		h := NewExecveHandler(cfg, nil, dt, nil)

		result, _ := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/something",
			Argv:      []string{"something"},
			Truncated: true,
		})

		require.False(t, result.Allow)
		assert.Equal(t, ActionDeny, result.Action)
		assert.Equal(t, int32(unix.EACCES), result.Errno)
	})

	t.Run("truncated approval no approver produces ActionDeny", func(t *testing.T) {
		cfg := ExecveHandlerConfig{OnTruncated: "approval"}
		dt := NewDepthTracker()
		h := NewExecveHandler(cfg, nil, dt, nil)

		result, _ := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/something",
			Argv:      []string{"something"},
			Truncated: true,
		})

		require.False(t, result.Allow)
		assert.Equal(t, ActionDeny, result.Action)
		assert.Equal(t, "truncated_no_approver", result.Reason)
	})

	t.Run("unknown effective decision produces ActionDeny (fail-secure)", func(t *testing.T) {
		cfg := ExecveHandlerConfig{}
		pol := &mockPolicy{decision: PolicyDecision{
			Decision:          "some_future_decision",
			EffectiveDecision: "some_future_decision",
			Rule:              "unknown-rule",
		}}
		dt := NewDepthTracker()
		dt.RegisterSession(1000, "sess-1")
		h := NewExecveHandler(cfg, pol, dt, nil)

		result, _ := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/mystery",
			Argv:      []string{"mystery"},
		})

		require.False(t, result.Allow)
		assert.Equal(t, ActionDeny, result.Action)
		assert.Equal(t, int32(unix.EACCES), result.Errno)
	})
}

// mockApprover implements ApprovalRequester for testing
type mockApprover struct {
	approved bool
	err      error
	called   bool
	gotReq   ApprovalRequest
}

func (m *mockApprover) RequestExecApproval(ctx context.Context, req ApprovalRequest) (bool, error) {
	m.called = true
	m.gotReq = req
	return m.approved, m.err
}

func TestExecveHandler_TruncatedApproval_Approved(t *testing.T) {
	cfg := ExecveHandlerConfig{
		OnTruncated:     "approval",
		ApprovalTimeout: 5 * time.Second,
	}
	pol := &mockPolicy{decision: PolicyDecision{
		Decision:          "allow",
		EffectiveDecision: "allow",
		Rule:              "test-rule",
	}}
	dt := NewDepthTracker()
	dt.RegisterSession(1000, "sess-1")
	approver := &mockApprover{approved: true}
	h := NewExecveHandler(cfg, pol, dt, nil)
	h.SetApprover(approver)

	result, _ := h.Handle(context.Background(), ExecveContext{
		PID:       1001,
		ParentPID: 1000,
		Filename:  "/usr/bin/something",
		Argv:      []string{"something", "arg1"},
		Truncated: true,
	})

	require.True(t, approver.called)
	assert.Equal(t, "/usr/bin/something", approver.gotReq.Command)
	assert.Equal(t, []string{"something", "arg1"}, approver.gotReq.Args)
	// Approved — falls through to policy check → ActionContinue
	assert.True(t, result.Allow)
	assert.Equal(t, ActionContinue, result.Action)
}

func TestExecveHandler_TruncatedApproval_Denied(t *testing.T) {
	cfg := ExecveHandlerConfig{
		OnTruncated:     "approval",
		ApprovalTimeout: 5 * time.Second,
	}
	dt := NewDepthTracker()
	approver := &mockApprover{approved: false}
	h := NewExecveHandler(cfg, nil, dt, nil)
	h.SetApprover(approver)

	result, _ := h.Handle(context.Background(), ExecveContext{
		PID:       1001,
		ParentPID: 1000,
		Filename:  "/usr/bin/something",
		Argv:      []string{"something"},
		Truncated: true,
	})

	require.True(t, approver.called)
	assert.False(t, result.Allow)
	assert.Equal(t, ActionDeny, result.Action)
	assert.Equal(t, "truncated_approval_denied", result.Reason)
}

func TestExecveHandler_TruncatedApproval_Timeout(t *testing.T) {
	t.Run("timeout action deny", func(t *testing.T) {
		cfg := ExecveHandlerConfig{
			OnTruncated:           "approval",
			ApprovalTimeout:       5 * time.Second,
			ApprovalTimeoutAction: "deny",
		}
		dt := NewDepthTracker()
		approver := &mockApprover{err: context.DeadlineExceeded}
		h := NewExecveHandler(cfg, nil, dt, nil)
		h.SetApprover(approver)

		result, _ := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/something",
			Argv:      []string{"something"},
			Truncated: true,
		})

		require.True(t, approver.called)
		assert.False(t, result.Allow)
		assert.Equal(t, ActionDeny, result.Action)
		assert.Equal(t, "truncated_approval_timeout", result.Reason)
	})

	t.Run("timeout action allow", func(t *testing.T) {
		cfg := ExecveHandlerConfig{
			OnTruncated:           "approval",
			ApprovalTimeout:       5 * time.Second,
			ApprovalTimeoutAction: "allow",
		}
		pol := &mockPolicy{decision: PolicyDecision{
			Decision:          "allow",
			EffectiveDecision: "allow",
			Rule:              "test-rule",
		}}
		dt := NewDepthTracker()
		dt.RegisterSession(1000, "sess-1")
		approver := &mockApprover{err: context.DeadlineExceeded}
		h := NewExecveHandler(cfg, pol, dt, nil)
		h.SetApprover(approver)

		result, _ := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/something",
			Argv:      []string{"something"},
			Truncated: true,
		})

		require.True(t, approver.called)
		// Timeout with "allow" action — falls through to policy check
		assert.True(t, result.Allow)
		assert.Equal(t, ActionContinue, result.Action)
	})

	t.Run("non-timeout error always denies even with allow action", func(t *testing.T) {
		cfg := ExecveHandlerConfig{
			OnTruncated:           "approval",
			ApprovalTimeout:       5 * time.Second,
			ApprovalTimeoutAction: "allow",
		}
		dt := NewDepthTracker()
		approver := &mockApprover{err: fmt.Errorf("transport error")}
		h := NewExecveHandler(cfg, nil, dt, nil)
		h.SetApprover(approver)

		result, _ := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/something",
			Argv:      []string{"something"},
			Truncated: true,
		})

		require.True(t, approver.called)
		// Non-timeout error with "allow" action — still denies (fail-secure)
		assert.False(t, result.Allow)
		assert.Equal(t, ActionDeny, result.Action)
		assert.Equal(t, "truncated_approval_error", result.Reason)
	})
}

func TestExecveContext_RawFilename(t *testing.T) {
	// Verify RawFilename is preserved through Handle
	cfg := ExecveHandlerConfig{}
	pol := &mockPolicy{decision: PolicyDecision{Decision: "allow", EffectiveDecision: "allow", Rule: "allow-all"}}
	dt := NewDepthTracker()
	dt.RegisterSession(1000, "sess-1")
	h := NewExecveHandler(cfg, pol, dt, nil)

	ctx := ExecveContext{
		PID:         1001,
		ParentPID:   1000,
		Filename:    "/usr/bin/git",
		RawFilename: "/proc/self/root/usr/bin/git",
		Argv:        []string{"git", "status"},
	}

	result, _ := h.Handle(context.Background(), ctx)
	assert.True(t, result.Allow)
	// RawFilename should be accessible on the context
	assert.Equal(t, "/proc/self/root/usr/bin/git", ctx.RawFilename)
}

func TestExecveHandler_TruncatedApproval_NoApprover(t *testing.T) {
	cfg := ExecveHandlerConfig{OnTruncated: "approval"}
	dt := NewDepthTracker()
	h := NewExecveHandler(cfg, nil, dt, nil)
	// No approver set — fail-secure

	result, _ := h.Handle(context.Background(), ExecveContext{
		PID:       1001,
		ParentPID: 1000,
		Filename:  "/usr/bin/something",
		Argv:      []string{"something"},
		Truncated: true,
	})

	assert.False(t, result.Allow)
	assert.Equal(t, ActionDeny, result.Action)
	assert.Equal(t, "truncated_no_approver", result.Reason)
}

// mockPolicyWithUnwrap returns different decisions based on filename.
type mockPolicyWithUnwrap struct {
	decisions map[string]PolicyDecision
}

func (m *mockPolicyWithUnwrap) CheckExecve(filename string, argv []string, depth int) PolicyDecision {
	if dec, ok := m.decisions[filename]; ok {
		return dec
	}
	base := filepath.Base(filename)
	if dec, ok := m.decisions[base]; ok {
		return dec
	}
	return PolicyDecision{Decision: "deny", EffectiveDecision: "deny", Rule: "default-deny"}
}

// mockEmitter collects emitted events for test inspection.
type mockEmitter struct {
	events []types.Event
}

func (m *mockEmitter) AppendEvent(ctx context.Context, ev types.Event) error {
	m.events = append(m.events, ev)
	return nil
}

func (m *mockEmitter) Publish(ev types.Event) {}

func TestExecveHandler_TransparentUnwrap_DenyPayload(t *testing.T) {
	pol := &mockPolicyWithUnwrap{decisions: map[string]PolicyDecision{
		"/usr/bin/env": {Decision: "allow", EffectiveDecision: "allow", Rule: "allow-env"},
		"wget":         {Decision: "deny", EffectiveDecision: "deny", Rule: "block-wget", Message: "wget not allowed"},
	}}
	dt := NewDepthTracker()
	dt.RegisterSession(1000, "sess-1")
	h := NewExecveHandler(ExecveHandlerConfig{}, pol, dt, nil)

	result, _ := h.Handle(context.Background(), ExecveContext{
		PID:       1001,
		ParentPID: 1000,
		Filename:  "/usr/bin/env",
		Argv:      []string{"env", "wget", "http://evil.com"},
	})

	assert.False(t, result.Allow)
	assert.Equal(t, ActionDeny, result.Action)
	assert.Equal(t, "block-wget", result.Rule)
	assert.Contains(t, result.Reason, "wget")
}

func TestExecveHandler_TransparentUnwrap_AllowPayload(t *testing.T) {
	pol := &mockPolicyWithUnwrap{decisions: map[string]PolicyDecision{
		"/usr/bin/env": {Decision: "allow", EffectiveDecision: "allow", Rule: "allow-env"},
		"git":          {Decision: "allow", EffectiveDecision: "allow", Rule: "allow-git"},
	}}
	dt := NewDepthTracker()
	dt.RegisterSession(1000, "sess-1")
	h := NewExecveHandler(ExecveHandlerConfig{}, pol, dt, nil)

	result, _ := h.Handle(context.Background(), ExecveContext{
		PID:       1001,
		ParentPID: 1000,
		Filename:  "/usr/bin/env",
		Argv:      []string{"env", "git", "status"},
	})

	assert.True(t, result.Allow)
	assert.Equal(t, ActionContinue, result.Action)
}

func TestExecveHandler_TransparentUnwrap_DenyWrapper(t *testing.T) {
	pol := &mockPolicyWithUnwrap{decisions: map[string]PolicyDecision{
		"/usr/bin/sudo": {Decision: "deny", EffectiveDecision: "deny", Rule: "block-sudo", Message: "sudo not allowed"},
		"git":           {Decision: "allow", EffectiveDecision: "allow", Rule: "allow-git"},
	}}
	dt := NewDepthTracker()
	dt.RegisterSession(1000, "sess-1")
	h := NewExecveHandler(ExecveHandlerConfig{}, pol, dt, nil)

	result, _ := h.Handle(context.Background(), ExecveContext{
		PID:       1001,
		ParentPID: 1000,
		Filename:  "/usr/bin/sudo",
		Argv:      []string{"sudo", "git", "push"},
	})

	assert.False(t, result.Allow)
	assert.Equal(t, ActionDeny, result.Action)
	assert.Equal(t, "block-sudo", result.Rule)
}

func TestExecveHandler_TransparentUnwrap_NonTransparent(t *testing.T) {
	pol := &mockPolicyWithUnwrap{decisions: map[string]PolicyDecision{
		"/usr/bin/git": {Decision: "allow", EffectiveDecision: "allow", Rule: "allow-git"},
	}}
	dt := NewDepthTracker()
	dt.RegisterSession(1000, "sess-1")
	h := NewExecveHandler(ExecveHandlerConfig{}, pol, dt, nil)

	result, _ := h.Handle(context.Background(), ExecveContext{
		PID:       1001,
		ParentPID: 1000,
		Filename:  "/usr/bin/git",
		Argv:      []string{"git", "status"},
	})

	assert.True(t, result.Allow)
	assert.Equal(t, ActionContinue, result.Action)
	assert.Equal(t, "allow-git", result.Rule)
}

func TestExecveHandler_TransparentUnwrap_AuditFields(t *testing.T) {
	pol := &mockPolicyWithUnwrap{decisions: map[string]PolicyDecision{
		"/usr/bin/env": {Decision: "allow", EffectiveDecision: "allow", Rule: "allow-env"},
		"git":          {Decision: "allow", EffectiveDecision: "allow", Rule: "allow-git"},
	}}
	dt := NewDepthTracker()
	dt.RegisterSession(1000, "sess-1")
	emitter := &mockEmitter{}
	h := NewExecveHandler(ExecveHandlerConfig{}, pol, dt, emitter)

	_, ev := h.Handle(context.Background(), ExecveContext{
		PID:       1001,
		ParentPID: 1000,
		Filename:  "/usr/bin/env",
		Argv:      []string{"env", "git", "status"},
	})

	// Handle() no longer emits directly — the caller is responsible.
	// Verify the returned event carries the unwrap audit fields.
	require.NotNil(t, ev)
	assert.Equal(t, "/usr/bin/env", ev.UnwrappedFrom)
	assert.Equal(t, "git", ev.PayloadCommand)
}
