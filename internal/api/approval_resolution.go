package api

import (
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
)

type errApprovalInvalidDecision struct{}

func (errApprovalInvalidDecision) Error() string { return "invalid decision" }

func decodeApprovalResolution(raw []byte) (approvals.Resolution, error) {
	var req struct {
		Decision       string `json:"decision"`
		Scope          string `json:"scope"`
		Reason         string `json:"reason"`
		ScopeKind      string `json:"scope_kind"`
		ScopeKey       string `json:"scope_key"`
		ScopeLabel     string `json:"scope_label"`
		ScopeOperation string `json:"scope_operation"`
		ScopePath      string `json:"scope_path"`
		ScopeRule      string `json:"scope_rule"`
		ScopePrefix    bool   `json:"scope_prefix"`
	}
	if err := decodeRawJSON(raw, &req); err != nil {
		return approvals.Resolution{}, err
	}
	approved := strings.EqualFold(req.Decision, "approve") || strings.EqualFold(req.Decision, "allow")
	if !approved && !strings.EqualFold(req.Decision, "deny") && !strings.EqualFold(req.Decision, "reject") {
		return approvals.Resolution{}, errApprovalInvalidDecision{}
	}
	scope, err := approvals.NormalizeResolutionScope(req.Scope)
	if err != nil {
		return approvals.Resolution{}, err
	}
	return approvals.Resolution{
		Approved:       approved,
		Reason:         req.Reason,
		Scope:          scope,
		At:             time.Now().UTC(),
		ScopeKind:      strings.TrimSpace(req.ScopeKind),
		ScopeKey:       strings.TrimSpace(req.ScopeKey),
		ScopeLabel:     strings.TrimSpace(req.ScopeLabel),
		ScopeOperation: strings.TrimSpace(req.ScopeOperation),
		ScopePath:      strings.TrimSpace(req.ScopePath),
		ScopeRule:      strings.TrimSpace(req.ScopeRule),
		ScopePrefix:    req.ScopePrefix,
	}, nil
}

func sameResolutionDecision(a, b approvals.Resolution) bool {
	return a.Approved == b.Approved && a.Reason == b.Reason && a.Scope == b.Scope &&
		a.ScopeKind == b.ScopeKind && a.ScopeKey == b.ScopeKey && a.ScopeLabel == b.ScopeLabel &&
		a.ScopeOperation == b.ScopeOperation && a.ScopePath == b.ScopePath && a.ScopeRule == b.ScopeRule &&
		a.ScopePrefix == b.ScopePrefix
}
