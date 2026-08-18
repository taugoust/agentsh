//go:build linux && cgo

package api

import (
	"context"
	"log/slog"
	"sync"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

var (
	globalMountRegistry     *unixmon.MountRegistry
	globalMountRegistryOnce sync.Once
)

func getMountRegistry() *unixmon.MountRegistry {
	globalMountRegistryOnce.Do(func() {
		globalMountRegistry = unixmon.NewMountRegistry()
	})
	return globalMountRegistry
}

// filePolicyEngineWrapper adapts policy.Engine to unixmon.FilePolicyChecker.
type filePolicyEngineWrapper struct {
	engine       *policy.Engine
	approvals    *approvals.Manager
	sessionID    string
	session      *session.Session // legacy constructor/test compatibility
	runtimeState session.CommandRuntimeState
}

func (w *filePolicyEngineWrapper) CheckFile(ctx context.Context, path, operation string) unixmon.FilePolicyDecision {
	dec := w.engine.CheckFile(path, operation)
	out := unixmon.FilePolicyDecision{
		Decision:          string(dec.PolicyDecision),
		EffectiveDecision: string(dec.EffectiveDecision),
		Rule:              dec.Rule,
		Message:           dec.Message,
		CacheOutcome:      unixmon.FileApprovalCacheNotApplicable,
	}
	if dec.PolicyDecision != types.DecisionApprove || dec.EffectiveDecision != types.DecisionApprove {
		return out
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if w.approvals == nil || w.sessionID == "" {
		out.EffectiveDecision = string(types.DecisionDeny)
		out.CacheOutcome = unixmon.FileApprovalCacheUnsupported
		return out
	}
	scope, ok := fileApprovalScope(operation, path, dec.Rule)
	if !ok {
		out.EffectiveDecision = string(types.DecisionDeny)
		out.CacheOutcome = unixmon.FileApprovalCacheUnsupported
		return out
	}
	commandID := w.currentCommandID()
	out.ApprovalScopeKey = scope.Key
	out.ApprovalCommandID = commandID
	if cached, ok := w.approvals.CheckScoped(ctx, w.sessionID, commandID, scope); ok {
		if cached.Approved {
			out.EffectiveDecision = string(types.DecisionAllow)
			out.CacheOutcome = unixmon.FileApprovalCacheAllow
		} else {
			out.EffectiveDecision = string(types.DecisionDeny)
			out.CacheOutcome = unixmon.FileApprovalCacheDeny
		}
		return out
	}
	out.CacheOutcome = unixmon.FileApprovalCacheMiss
	return out
}

// ResolveFileApproval performs the blocking half of file approval handling.
// RequestApprovalScoped repeats the exact prepared cache lookup and registers a
// pending request atomically if it still misses.
func (w *filePolicyEngineWrapper) ResolveFileApproval(ctx context.Context, path, operation string, prepared unixmon.FilePolicyDecision) (unixmon.FilePolicyDecision, error) {
	out := prepared
	if prepared.Decision != string(types.DecisionApprove) || prepared.EffectiveDecision != string(types.DecisionApprove) {
		return out, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		out.EffectiveDecision = string(types.DecisionDeny)
		return out, err
	}
	if w.approvals == nil || w.sessionID == "" {
		out.EffectiveDecision = string(types.DecisionDeny)
		out.CacheOutcome = unixmon.FileApprovalCacheUnsupported
		return out, nil
	}
	scope, ok, scopeOptions := fileApprovalScopeOptions(operation, path, prepared.Rule)
	if !ok || prepared.ApprovalScopeKey == "" || scope.Key != prepared.ApprovalScopeKey {
		out.EffectiveDecision = string(types.DecisionDeny)
		out.CacheOutcome = unixmon.FileApprovalCacheUnsupported
		return out, nil
	}
	fields := approvals.ScopeFields(scope)
	fields["operation"] = operation
	fields["path"] = path
	fields["scope_options"] = scopeOptions
	res, err := w.approvals.RequestApprovalScoped(ctx, approvals.Request{
		SessionID: w.sessionID,
		CommandID: prepared.ApprovalCommandID,
		Kind:      "file",
		Target:    path,
		Rule:      prepared.Rule,
		Message:   prepared.Message,
		Fields:    fields,
	}, scope)
	if err != nil || !res.Approved {
		out.EffectiveDecision = string(types.DecisionDeny)
		return out, err
	}
	out.EffectiveDecision = string(types.DecisionAllow)
	return out, nil
}

func (w *filePolicyEngineWrapper) currentCommandID() string {
	switch runtimeState := w.runtimeState.(type) {
	case nil:
	case *session.Session:
		if runtimeState != nil {
			return runtimeState.CurrentCommandID()
		}
	case *session.CommandRuntime:
		if runtimeState != nil {
			return runtimeState.CurrentCommandID()
		}
	default:
		return runtimeState.CurrentCommandID()
	}
	if w.session != nil {
		return w.session.CurrentCommandID()
	}
	return ""
}

// createFileHandler creates a FileHandler from configuration.
// landlockEnabled indicates whether Landlock enforcement is configured (not just kernel-available).
func createFileHandler(cfg config.SandboxSeccompFileMonitorConfig, pol *policy.Engine, emitter unixmon.Emitter, landlockEnabled bool, approvalsMgr *approvals.Manager, sess *session.Session) *unixmon.FileHandler {
	return createFileHandlerForState(cfg, pol, emitter, landlockEnabled, approvalsMgr, sess, sess)
}

func createFileHandlerForState(cfg config.SandboxSeccompFileMonitorConfig, pol *policy.Engine, emitter unixmon.Emitter, landlockEnabled bool, approvalsMgr *approvals.Manager, sess *session.Session, runtimeState session.CommandRuntimeState) *unixmon.FileHandler {
	if !config.FileMonitorBoolWithDefault(cfg.Enabled, false) {
		return nil
	}

	var policyChecker unixmon.FilePolicyChecker
	if pol != nil {
		sessionID := ""
		if sess != nil {
			sessionID = sess.ID
		}
		policyChecker = &filePolicyEngineWrapper{engine: pol, approvals: approvalsMgr, sessionID: sessionID, runtimeState: runtimeState}
	}

	registry := getMountRegistry()
	enforce := config.FileMonitorBoolWithDefault(cfg.EnforceWithoutFUSE, false)
	handler := unixmon.NewFileHandler(policyChecker, registry, emitter, enforce)

	// Enable AddFD emulation when configured and the kernel supports it.
	// IMPORTANT: emulated opens run in the supervisor's context, outside the
	// tracee's Landlock/FUSE restrictions. Only enable when seccomp-notify is
	// the sole enforcement backend (no Landlock, no FUSE).
	defaultVal := config.FileMonitorBoolWithDefault(cfg.EnforceWithoutFUSE, false)
	openatEmulation := config.FileMonitorBoolWithDefault(cfg.OpenatEmulation, defaultVal)
	if openatEmulation && enforce && unixmon.ProbeAddFDSupport() {
		landlockActive := landlockEnabled && capabilities.DetectLandlock().Available
		fuseActive := registry.HasAnyMounts()
		if !landlockActive && !fuseActive {
			handler.SetEmulateOpen(true)
		} else {
			slog.Info("seccomp openat emulation disabled: other backend active",
				"landlock", landlockActive, "fuse_mounts", fuseActive)
		}
	}

	return handler
}

// registerFUSEMount records a FUSE mount point in the global MountRegistry
// so the seccomp FileHandler defers enforcement for paths under the FUSE mount.
func registerFUSEMount(sessionID, mountPoint string) {
	getMountRegistry().Register(sessionID, mountPoint)
	slog.Debug("registered FUSE mount in MountRegistry",
		"session_id", sessionID,
		"mount_point", mountPoint)
}

// deregisterFUSEMount removes a FUSE mount point from the global MountRegistry
// during session teardown.
func deregisterFUSEMount(sessionID, mountPoint string) {
	getMountRegistry().Deregister(sessionID, mountPoint)
	slog.Debug("deregistered FUSE mount from MountRegistry",
		"session_id", sessionID,
		"mount_point", mountPoint)
}
