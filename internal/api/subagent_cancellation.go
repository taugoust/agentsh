package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

type subagentCancellationEntry struct {
	cancel context.CancelCauseFunc
}

type cancelSubagentRequest struct {
	Cause subagentCancellationCause `json:"cause"`
}

func subagentCancellationKey(sessionID, requestID string) string {
	return sessionID + "\x00" + requestID
}

func validSubagentRequestID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9', char == '-', char == '_', char == '.', char == ':':
		default:
			return false
		}
	}
	return true
}

func (a *App) subagentLifecycleContext() context.Context {
	if a == nil {
		return context.Background()
	}
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	if a.lifecycleCtx == nil || a.lifecycleCancel == nil {
		a.lifecycleCtx, a.lifecycleCancel = context.WithCancelCause(context.Background())
	}
	return a.lifecycleCtx
}

func (a *App) registerSubagentCancellation(sessionID, requestID string, cancel context.CancelCauseFunc) error {
	if a == nil || cancel == nil {
		return errors.New("subagent cancellation registry is unavailable")
	}
	key := subagentCancellationKey(sessionID, requestID)
	a.subagentCancellationMu.Lock()
	defer a.subagentCancellationMu.Unlock()
	if a.subagentCancellations == nil {
		a.subagentCancellations = make(map[string]subagentCancellationEntry)
	}
	if _, exists := a.subagentCancellations[key]; exists {
		return fmt.Errorf("subagent request %s is already active", requestID)
	}
	a.subagentCancellations[key] = subagentCancellationEntry{cancel: cancel}
	return nil
}

func (a *App) unregisterSubagentCancellation(sessionID, requestID string) {
	if a == nil {
		return
	}
	a.subagentCancellationMu.Lock()
	delete(a.subagentCancellations, subagentCancellationKey(sessionID, requestID))
	a.subagentCancellationMu.Unlock()
}

func (a *App) cancelRegisteredSubagent(sessionID, requestID string, cause error) bool {
	if a == nil {
		return false
	}
	a.subagentCancellationMu.Lock()
	entry, ok := a.subagentCancellations[subagentCancellationKey(sessionID, requestID)]
	a.subagentCancellationMu.Unlock()
	if !ok || entry.cancel == nil {
		return false
	}
	entry.cancel(cause)
	return true
}

// newSubagentRequestContext gives timeout, explicit cancellation, transport
// disconnect, and supervisor shutdown separate causes. It intentionally does
// not derive directly from the HTTP context because a cancel control request
// must be able to win before the original response stream is closed.
func (a *App) newSubagentRequestContext(requestCtx context.Context, timeout time.Duration) (context.Context, context.CancelCauseFunc, func()) {
	baseCtx, cancelCause := context.WithCancelCause(context.Background())
	ctx := context.Context(baseCtx)
	timeoutCancel := func() {}
	if timeout > 0 {
		ctx, timeoutCancel = context.WithTimeoutCause(baseCtx, timeout, errSubagentRequestTimeout)
	}
	if requestCtx == nil {
		requestCtx = context.Background()
	}
	stopRequest := context.AfterFunc(requestCtx, func() { cancelCause(errSubagentClientDisconnected) })
	stopLifecycle := context.AfterFunc(a.subagentLifecycleContext(), func() { cancelCause(errSubagentSupervisorShutdown) })
	cleanup := func() {
		stopRequest()
		stopLifecycle()
		cancelCause(errSubagentRequestComplete)
		timeoutCancel()
	}
	return ctx, cancelCause, cleanup
}

func explicitSubagentCancellationError(cause subagentCancellationCause) (error, bool) {
	switch cause {
	case subagentCancelUser:
		return errSubagentUserCancelled, true
	case subagentCancelParent:
		return errSubagentParentCancelled, true
	default:
		return nil, false
	}
}

func (a *App) cancelSubagentTool(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	requestID := strings.TrimSpace(chi.URLParam(r, "requestID"))
	if _, ok := a.sessions.Get(sessionID); !ok {
		writeToolError(w, http.StatusNotFound, "session not found")
		return
	}
	if !validSubagentRequestID(requestID) {
		writeToolError(w, http.StatusBadRequest, "invalid subagent request id")
		return
	}
	var req cancelSubagentRequest
	if ok := decodeJSON(w, r, &req, "invalid json"); !ok {
		return
	}
	cause, ok := explicitSubagentCancellationError(req.Cause)
	if !ok {
		writeToolError(w, http.StatusBadRequest, "cancellation cause must be user_cancelled or parent_cancelled")
		return
	}
	if !a.cancelRegisteredSubagent(sessionID, requestID, cause) {
		writeToolError(w, http.StatusConflict, "subagent request is not active")
		return
	}
	writeJSON(w, http.StatusAccepted, toolResponse{OK: true, Result: map[string]any{
		"request_id": requestID,
		"cause":      req.Cause,
		"accepted":   true,
	}})
}
