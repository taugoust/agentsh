package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/go-chi/chi/v5"
)

const guestEgressApprovalHeader = "X-AgentSH-Guest-Egress-Approval"

type guestEgressApprovalDelegation struct {
	digest         [32]byte
	sessionID      string
	requestID      string
	commandID      string
	draftSessionID string
	lifecycle      context.Context
	cancel         context.CancelCauseFunc
}

type guestEgressApprovalHandle struct {
	digest [32]byte
	token  string
}

type guestEgressApprovalRequest struct {
	DraftSessionID string `json:"draft_session_id"`
	Kind           string `json:"kind"`
	Target         string `json:"target"`
	Rule           string `json:"rule"`
	Message        string `json:"message,omitempty"`
}

func (a *App) mintGuestEgressApprovalDelegation(parent context.Context, sessionID, requestID string) (*guestEgressApprovalHandle, error) {
	if a == nil || parent == nil || a.approvals == nil || !validSubagentRequestID(requestID) {
		return nil, fmt.Errorf("guest egress approval delegation is unavailable")
	}
	if _, ok := a.sessions.Get(sessionID); !ok {
		return nil, fmt.Errorf("guest egress approval parent session is unavailable")
	}
	token, digest, err := mintChildCapabilityToken()
	if err != nil {
		return nil, err
	}
	lifecycle, cancel := context.WithCancelCause(parent)
	record := &guestEgressApprovalDelegation{
		digest: digest, sessionID: sessionID, requestID: requestID,
		commandID: requestID + "/egress/" + hex.EncodeToString(digest[:8]),
		lifecycle: lifecycle, cancel: cancel,
	}
	a.guestEgressApprovalMu.Lock()
	if a.guestEgressApprovalDelegations == nil {
		a.guestEgressApprovalDelegations = make(map[[32]byte]*guestEgressApprovalDelegation)
	}
	if _, exists := a.guestEgressApprovalDelegations[digest]; exists {
		a.guestEgressApprovalMu.Unlock()
		cancel(fmt.Errorf("duplicate guest egress approval delegation"))
		return nil, fmt.Errorf("guest egress approval capability collision")
	}
	a.guestEgressApprovalDelegations[digest] = record
	a.guestEgressApprovalMu.Unlock()
	return &guestEgressApprovalHandle{digest: digest, token: token}, nil
}

func (a *App) revokeGuestEgressApprovalDelegation(handle *guestEgressApprovalHandle) {
	if a == nil || handle == nil {
		return
	}
	a.guestEgressApprovalMu.Lock()
	record := a.guestEgressApprovalDelegations[handle.digest]
	delete(a.guestEgressApprovalDelegations, handle.digest)
	a.guestEgressApprovalMu.Unlock()
	if record != nil {
		record.cancel(fmt.Errorf("guest egress approval delegation revoked"))
	}
}

func (a *App) authenticateGuestEgressApproval(r *http.Request, sessionID string) (*guestEgressApprovalDelegation, error) {
	digest, err := parseChildCapabilityToken(r.Header.Get(guestEgressApprovalHeader))
	if err != nil {
		return nil, err
	}
	a.guestEgressApprovalMu.Lock()
	record := a.guestEgressApprovalDelegations[digest]
	if record == nil || record.sessionID != sessionID || record.lifecycle.Err() != nil {
		a.guestEgressApprovalMu.Unlock()
		return nil, fmt.Errorf("guest egress approval delegation is invalid")
	}
	copy := *record
	a.guestEgressApprovalMu.Unlock()
	return &copy, nil
}

func (a *App) bindGuestEgressApprovalDraft(delegation *guestEgressApprovalDelegation, draftSessionID string) error {
	if a == nil || delegation == nil || !draftLandingSessionPattern.MatchString(draftSessionID) {
		return fmt.Errorf("guest egress approval Draft binding is invalid")
	}
	a.guestEgressApprovalMu.Lock()
	defer a.guestEgressApprovalMu.Unlock()
	record := a.guestEgressApprovalDelegations[delegation.digest]
	if record == nil || record.lifecycle.Err() != nil || (record.draftSessionID != "" && record.draftSessionID != draftSessionID) {
		return fmt.Errorf("guest egress approval delegation is not bound to this Draft")
	}
	record.draftSessionID = draftSessionID
	return nil
}

func guestEgressApprovalScope(req guestEgressApprovalRequest) (approvals.Scope, bool) {
	switch req.Kind {
	case "network":
		return approvals.NewNetworkScopeFromTarget(req.Target, 0)
	case "dns":
		return approvals.NewNetworkScopeFromTarget(req.Target, 53)
	default:
		return approvals.Scope{}, false
	}
}

func validateGuestEgressApprovalRequest(req guestEgressApprovalRequest) (approvals.Scope, error) {
	if !draftLandingSessionPattern.MatchString(req.DraftSessionID) || len(req.Target) > 1024 || len(req.Rule) > 1024 || len(req.Message) > 16*1024 ||
		!utf8.ValidString(req.Target) || !utf8.ValidString(req.Rule) || !utf8.ValidString(req.Message) || strings.TrimSpace(req.Target) != req.Target || req.Target == "" {
		return approvals.Scope{}, fmt.Errorf("invalid guest egress approval identity")
	}
	scope, ok := guestEgressApprovalScope(req)
	if !ok {
		return approvals.Scope{}, fmt.Errorf("invalid guest egress approval target")
	}
	return scope, nil
}

func (a *App) requestGuestEgressApproval(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	delegation, err := a.authenticateGuestEgressApproval(r, sessionID)
	if err != nil {
		writeToolError(w, http.StatusUnauthorized, "valid active guest egress approval delegation required")
		return
	}
	var req guestEgressApprovalRequest
	if ok := decodeJSON(w, r, &req, "invalid guest egress approval request"); !ok {
		return
	}
	scope, err := validateGuestEgressApprovalRequest(req)
	if err != nil {
		writeToolError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.bindGuestEgressApprovalDraft(delegation, req.DraftSessionID); err != nil {
		writeToolError(w, http.StatusUnauthorized, err.Error())
		return
	}
	// Session-scoped grants are deliberately Draft-scoped, not parent-session
	// scoped. Parallel Drafts therefore cannot consume one another's grants.
	scopeDigest := sha256.Sum256([]byte(req.DraftSessionID + "\x00" + scope.Key))
	scope.Key = "draft-egress:" + hex.EncodeToString(scopeDigest[:])
	scope.Label = req.DraftSessionID + " · " + scope.Label
	if a.approvals == nil {
		writeToolError(w, http.StatusServiceUnavailable, "approval manager is unavailable")
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(delegation.lifecycle, cancel)
	defer func() {
		stop()
		cancel()
	}()
	message := fmt.Sprintf("A disposable MicroVM Draft requests %s access to %q.", req.Kind, req.Target)
	if detail := strings.TrimSpace(req.Message); detail != "" {
		message += "\n" + detail
	}
	request := approvals.Request{
		SessionID: sessionID,
		CommandID: delegation.commandID,
		Kind:      "network",
		Target:    req.Target,
		Rule:      strings.TrimSpace(req.Rule),
		Message:   message,
		Fields: map[string]any{
			"draft_session_id": req.DraftSessionID,
			"guest_kind":       req.Kind,
			"subagent_request": delegation.requestID,
		},
	}
	resolution, err := a.approvals.RequestApprovalScoped(ctx, request, scope)
	if err != nil {
		writeToolError(w, http.StatusForbidden, "guest egress approval failed")
		return
	}
	writeJSON(w, http.StatusOK, resolution)
}
