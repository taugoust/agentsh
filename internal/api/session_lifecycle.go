package api

import (
	"context"
	"fmt"
	"time"

	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/session"
)

// ReapExpiredSessionsResult carries the lifecycle decision that the server
// needs in addition to the expired session resources themselves.
type ReapExpiredSessionsResult struct {
	Sessions                  []*session.Session
	DetachedSupervisorExpired bool
	Err                       error
}

// ReapExpiredSessions serializes hard/idle expiry with session topology and
// helper rebinding. It intentionally leaves expired sessions installed while a
// staged candidate's cleanup cannot be authenticated as complete.
func (a *App) ReapExpiredSessions(now time.Time, sessionTimeout, idleTimeout time.Duration) []*session.Session {
	return a.ReapExpiredSessionsWithResult(now, sessionTimeout, idleTimeout).Sessions
}

// ReapExpiredSessionsWithResult additionally reports whether expiry removed
// the exact session owned by this detached supervisor. Its durable stopping
// transition is committed before the manager removes that session.
func (a *App) ReapExpiredSessionsWithResult(now time.Time, sessionTimeout, idleTimeout time.Duration) ReapExpiredSessionsResult {
	var result ReapExpiredSessionsResult
	if a == nil || a.sessions == nil {
		return result
	}

	a.sessionTopologyMu.Lock()
	defer a.sessionTopologyMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := a.resolveCandidateCleanup(ctx); err != nil {
		result.Err = err
		return result
	}

	runtime := a.detachedRuntime
	detachedSessionID := ""
	if runtime != nil {
		detachedSessionID = runtime.Manifest().SessionID
	}

	reaped, err := a.sessions.ReapExpiredGuarded(now, sessionTimeout, idleTimeout, func(sess *session.Session) error {
		if sess != nil && !sess.WorkspaceTeardownAllowed() {
			return fmt.Errorf("session %s workspace finalization is running or pending", sess.ID)
		}
		isDetached := runtime != nil && sess != nil && sess.ID == detachedSessionID
		if isDetached {
			if err := runtime.MarkStopping(); err != nil {
				return fmt.Errorf("persist detached session expiry for %s: %w", sess.ID, err)
			}
		}
		if sess != nil {
			if err := sess.UnmountWorkspace(); err != nil {
				return fmt.Errorf("session %s workspace teardown: %w", sess.ID, err)
			}
		}
		if isDetached {
			result.DetachedSupervisorExpired = true
		}
		return nil
	})
	result.Sessions = reaped
	for _, sess := range reaped {
		if sess == nil {
			continue
		}
		a.closeApprovalUI(sess.ID)
		a.revokeChildCapabilitiesForSession(sess.ID, errChildCapabilityRevoked)
		if a.approvals != nil {
			a.approvals.ClearSession(ctx, sess.ID)
		}
	}
	if err != nil {
		result.DetachedSupervisorExpired = false
		result.Err = err
	}
	return result
}

func (a *App) detachedRuntimeStatus() detached.RuntimeStatus {
	status := a.detachedRuntime.RuntimeStatus()
	switch status.LifecycleState {
	case detached.LifecycleProvisioning, detached.LifecycleRecovering, detached.LifecycleReady, detached.LifecycleDegraded:
		if _, ok := a.sessions.Get(status.SessionID); !ok {
			status.LifecycleState = detached.LifecycleFailed
			status.Recoverable = false
			status.LastError = "detached runtime's exact session is absent"
		}
	}
	return status
}
