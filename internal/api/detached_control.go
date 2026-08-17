package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/detachedtransport"
)

func (a *App) authorizeDetachedOperatorRequest(r *http.Request) bool {
	if a == nil || a.detachedRuntime == nil || r == nil || !isUnixSocketRequest(r) {
		return false
	}
	path := r.URL.Path
	approvalOperator := (path == "/api/v1/approvals" && r.Method == http.MethodGet) ||
		(strings.HasPrefix(path, "/api/v1/approvals/") && r.Method == http.MethodPost)
	allowed := approvalOperator || strings.HasSuffix(path, "/overlay/accept") || strings.HasSuffix(path, "/overlay/reject") ||
		path == "/api/v1/session-events" || (strings.HasPrefix(path, "/api/v1/session-events/") && (strings.HasSuffix(path, "/ack") || strings.HasSuffix(path, "/answer")))
	if !allowed {
		return false
	}
	expected := strings.TrimSpace(a.detachedRuntime.Metadata().EventToken)
	token := strings.TrimSpace(r.Header.Get(detachedtransport.ControlTokenHeader))
	return expected != "" && token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

func (a *App) exchangeDetachedControl(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.detachedRuntime == nil || a.detachedControl == nil || a.detachedResolutions == nil || !isUnixSocketRequest(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "detached control exchange requires the exact local supervisor channel"})
		return
	}
	metadata := a.detachedRuntime.Metadata()
	token := strings.TrimSpace(r.Header.Get(detachedtransport.ControlTokenHeader))
	if token == "" || strings.TrimSpace(metadata.EventToken) == "" || subtle.ConstantTimeCompare([]byte(token), []byte(metadata.EventToken)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid detached control credential"})
		return
	}
	var request detachedtransport.ExchangeRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid detached control exchange"})
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid trailing detached control data"})
		return
	}
	if err := request.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if subtle.ConstantTimeCompare([]byte(request.Credential), []byte(token)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "detached control schema credential mismatch"})
		return
	}
	status := a.detachedRuntime.RuntimeStatus()
	identity := detachedtransport.Identity{SessionID: status.SessionID, Generation: status.Generation, IncarnationID: status.IncarnationID}
	if request.Identity != identity {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "detached control incarnation mismatch"})
		return
	}
	ack, err := a.detachedResolutions.Apply(identity, request.AckFloor, request.Records, func(record detachedtransport.Record) detachedtransport.ResolveResult {
		resolution := *record.Resolution
		target := approvals.Scope{
			Kind: resolution.ScopeKind, Key: resolution.ScopeKey, Label: resolution.ScopeLabel,
			Operation: resolution.ScopeOperation, Path: resolution.ScopePath, Rule: resolution.ScopeRule,
			Prefix: resolution.ScopePrefix,
		}
		if a.approvals.ResolveForSessionWithScopeTarget(identity.SessionID, record.ID, resolution.Approved, resolution.Reason, resolution.Scope, target) {
			return detachedtransport.ResolveApplied
		}
		if !a.approvals.HasPendingForSession(identity.SessionID, record.ID) {
			// Timeout, cancellation, or another trusted resolver won. Consume the
			// stale record so it cannot poison all later ordered resolutions.
			return detachedtransport.ResolveAlreadyTerminal
		}
		return detachedtransport.ResolveRejected
	})
	if err != nil {
		code := http.StatusConflict
		if strings.Contains(err.Error(), "not pending") {
			code = http.StatusNotFound
		}
		writeJSON(w, code, map[string]any{"error": err.Error(), "ack": ack})
		return
	}
	if err := a.detachedControl.Acknowledge(identity, request.Cursor); err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
		return
	}
	out := a.detachedControl.Since(identity, request.Cursor, request.Limit, "")
	cursor := request.Cursor
	if len(out) > 0 {
		cursor = out[len(out)-1].Sequence
	}
	pending := a.approvals.ListPendingForSession(identity.SessionID)
	writeJSON(w, http.StatusOK, detachedtransport.ExchangeResponse{
		Version: detachedtransport.Version, Identity: identity, Ack: ack, Cursor: cursor, Records: out, Pending: pending,
	})
}
