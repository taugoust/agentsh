package api

import (
	"encoding/json"
	"net/http"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/detachedtransport"
)

func (a *App) exchangeDetachedControl(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.detachedRuntime == nil || a.detachedControl == nil || !isUnixSocketRequest(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "detached control exchange requires the exact local supervisor channel"})
		return
	}
	var request detachedtransport.ExchangeRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid detached control exchange"})
		return
	}
	if err := request.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	status := a.detachedRuntime.RuntimeStatus()
	identity := detachedtransport.Identity{SessionID: status.SessionID, Generation: status.Generation, IncarnationID: status.IncarnationID}
	if request.Identity != identity {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "detached control incarnation mismatch"})
		return
	}
	ack := request.Cursor
	for _, record := range request.Records {
		if record.Kind != detachedtransport.KindApprovalResolved || record.Resolution == nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "parent may send only approval resolution records"})
			return
		}
		resolution := *record.Resolution
		target := approvals.Scope{
			Kind: resolution.ScopeKind, Key: resolution.ScopeKey, Label: resolution.ScopeLabel,
			Operation: resolution.ScopeOperation, Path: resolution.ScopePath, Rule: resolution.ScopeRule,
			Prefix: resolution.ScopePrefix,
		}
		if !a.approvals.ResolveForSessionWithScopeTarget(identity.SessionID, record.ID, resolution.Approved, resolution.Reason, resolution.Scope, target) {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "approval not pending in exact detached incarnation"})
			return
		}
		ack = record.Sequence
	}
	out := a.detachedControl.Since(identity, request.Cursor, request.Limit, detachedtransport.KindApprovalRequested)
	cursor := request.Cursor
	if len(out) > 0 {
		cursor = out[len(out)-1].Sequence
	}
	writeJSON(w, http.StatusOK, detachedtransport.ExchangeResponse{
		Version: detachedtransport.Version, Identity: identity, Ack: ack, Cursor: cursor, Records: out,
	})
}
