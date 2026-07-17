package api

import (
	"context"
	"time"

	"github.com/agentsh/agentsh/internal/session"
)

// ReapExpiredSessions serializes hard/idle expiry with session topology and
// helper rebinding. It intentionally leaves expired sessions installed while a
// staged candidate's cleanup cannot be authenticated as complete.
func (a *App) ReapExpiredSessions(now time.Time, sessionTimeout, idleTimeout time.Duration) []*session.Session {
	if a == nil || a.sessions == nil {
		return nil
	}
	a.sessionTopologyMu.Lock()
	defer a.sessionTopologyMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if a.resolveCandidateCleanup(ctx) != nil {
		return nil
	}
	return a.sessions.ReapExpired(now, sessionTimeout, idleTimeout)
}
