package api

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/detached"
	"github.com/go-chi/chi/v5"
)

type detachedApprovalStore struct {
	mu          sync.Mutex
	pending     map[string]approvals.Request
	resolutions map[string]approvals.Resolution
}

func newDetachedApprovalStore() *detachedApprovalStore {
	return &detachedApprovalStore{
		pending:     make(map[string]approvals.Request),
		resolutions: make(map[string]approvals.Resolution),
	}
}

func (s *detachedApprovalStore) resolve(approvalID, sessionID string, res approvals.Resolution) bool {
	if s == nil {
		return false
	}
	approvalID = strings.TrimSpace(approvalID)
	if approvalID == "" {
		return false
	}
	scope, err := approvals.NormalizeResolutionScope(res.Scope)
	if err != nil {
		return false
	}
	res.Scope = scope
	now := time.Now().UTC()
	if res.At.IsZero() {
		res.At = now
	}
	sessionID = strings.TrimSpace(sessionID)

	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.pending[approvalID]
	if !ok {
		return false
	}
	if sessionID != "" && req.SessionID != sessionID {
		return false
	}
	delete(s.pending, approvalID)
	s.resolutions[approvalID] = res
	s.resolveCoveredBySessionScopeLocked(req, res, now)
	return true
}

func (s *detachedApprovalStore) resolveCoveredBySessionScopeLocked(source approvals.Request, res approvals.Resolution, now time.Time) {
	if res.Scope != approvals.ScopeSession || strings.TrimSpace(source.SessionID) == "" {
		return
	}
	granted, ok := approvals.ScopeFromResolution(res)
	if !ok {
		granted, ok = approvals.ScopeFromRequest(source)
	}
	if !ok {
		return
	}
	for id, req := range s.pending {
		if id == source.ID || req.SessionID != source.SessionID {
			continue
		}
		if !req.ExpiresAt.IsZero() && req.ExpiresAt.Before(now) {
			delete(s.pending, id)
			continue
		}
		if approvals.RequestCoveredByScope(req, granted) {
			delete(s.pending, id)
			s.resolutions[id] = res
		}
	}
}

func isDetachedTokenEndpoint(path string) bool {
	return strings.HasPrefix(path, "/api/v1/detached-sessions/")
}

func (a *App) detachedMetadataForSession(sessionID string) (detached.Metadata, bool) {
	if a == nil || a.cfg == nil || strings.TrimSpace(sessionID) == "" {
		return detached.Metadata{}, false
	}
	for _, root := range a.cfg.Sessions.DetachedSupervisors.Roots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		meta, _, err := detached.ReadMetadataFromRoot(root, sessionID)
		if err == nil && meta.SessionID == sessionID {
			return meta, true
		}
	}
	return detached.Metadata{}, false
}

func (a *App) authorizeDetachedToken(w http.ResponseWriter, r *http.Request, sessionID string) bool {
	meta, ok := a.detachedMetadataForSession(sessionID)
	if !ok || strings.TrimSpace(meta.EventToken) == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unknown detached session or missing event token"})
		return false
	}
	token := strings.TrimSpace(r.Header.Get("X-AgentSH-Session-Event-Token"))
	if token == "" {
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			token = strings.TrimSpace(auth[len("bearer "):])
		}
	}
	if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(meta.EventToken)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid detached session event token"})
		return false
	}
	return true
}

func (a *App) publishDetachedSessionEvent(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimSpace(chi.URLParam(r, "id"))
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "missing session id"})
		return
	}
	if !a.authorizeDetachedToken(w, r, sessionID) {
		return
	}
	var ev sessionEvent
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid event"})
		return
	}
	ev.SessionID = sessionID
	if strings.TrimSpace(ev.Type) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "missing event type"})
		return
	}
	if strings.TrimSpace(ev.Title) == "" {
		ev.Title = ev.Type
	}
	published := a.publishSessionEvent(ev)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "event": published})
}

func (a *App) getDetachedSessionQuestionAnswer(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimSpace(chi.URLParam(r, "id"))
	qid := strings.TrimSpace(chi.URLParam(r, "qid"))
	if sessionID == "" || qid == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "missing session id or questionnaire id"})
		return
	}
	if !a.authorizeDetachedToken(w, r, sessionID) {
		return
	}
	if a.sessionEvents == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	answer, ok := a.sessionEvents.GetAnswer(sessionID, qid)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "answer": answer})
}

func (a *App) listDetachedSessionApprovals(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimSpace(chi.URLParam(r, "id"))
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "missing session id"})
		return
	}
	if !a.authorizeDetachedToken(w, r, sessionID) {
		return
	}
	now := time.Now().UTC()
	a.detachedApprovals.mu.Lock()
	defer a.detachedApprovals.mu.Unlock()
	out := make([]approvals.Request, 0)
	for id, req := range a.detachedApprovals.pending {
		if req.ExpiresAt.Before(now) {
			delete(a.detachedApprovals.pending, id)
			continue
		}
		if req.SessionID == sessionID {
			out = append(out, req)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) registerDetachedApproval(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimSpace(chi.URLParam(r, "id"))
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "missing session id"})
		return
	}
	if !a.authorizeDetachedToken(w, r, sessionID) {
		return
	}
	var req approvals.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid approval"})
		return
	}
	req.SessionID = sessionID
	if strings.TrimSpace(req.ID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "missing approval id"})
		return
	}
	now := time.Now().UTC()
	if req.CreatedAt.IsZero() {
		req.CreatedAt = now
	}
	if req.ExpiresAt.IsZero() {
		req.ExpiresAt = now.Add(5 * time.Minute)
	}
	a.detachedApprovals.mu.Lock()
	if _, resolved := a.detachedApprovals.resolutions[req.ID]; !resolved {
		a.detachedApprovals.pending[req.ID] = req
	}
	a.detachedApprovals.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) getDetachedApprovalResolution(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimSpace(chi.URLParam(r, "id"))
	approvalID := strings.TrimSpace(chi.URLParam(r, "approvalID"))
	if sessionID == "" || approvalID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "missing session id or approval id"})
		return
	}
	if !a.authorizeDetachedToken(w, r, sessionID) {
		return
	}
	a.detachedApprovals.mu.Lock()
	res, ok := a.detachedApprovals.resolutions[approvalID]
	a.detachedApprovals.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "resolved": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "resolved": true, "resolution": res})
}

func (a *App) resolveDetachedApprovalFromSession(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimSpace(chi.URLParam(r, "id"))
	approvalID := strings.TrimSpace(chi.URLParam(r, "approvalID"))
	if sessionID == "" || approvalID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "missing session id or approval id"})
		return
	}
	if !a.authorizeDetachedToken(w, r, sessionID) {
		return
	}
	res, err := decodeApprovalResolutionBody(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if ok := a.detachedApprovals.resolve(approvalID, sessionID, res); !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "approval not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) listPushedDetachedApprovals() []any {
	if a == nil || a.detachedApprovals == nil {
		return nil
	}
	now := time.Now().UTC()
	a.detachedApprovals.mu.Lock()
	defer a.detachedApprovals.mu.Unlock()
	out := make([]any, 0, len(a.detachedApprovals.pending))
	for id, req := range a.detachedApprovals.pending {
		if req.ExpiresAt.Before(now) {
			delete(a.detachedApprovals.pending, id)
			continue
		}
		out = append(out, req)
	}
	return out
}

func (a *App) resolvePushedDetachedApproval(id string, raw []byte) (int, map[string]any, bool) {
	if a == nil || a.detachedApprovals == nil {
		return 0, nil, false
	}
	res, err := decodeApprovalResolution(raw)
	if err != nil {
		return http.StatusBadRequest, map[string]any{"error": err.Error()}, true
	}
	if !a.detachedApprovals.resolve(id, "", res) {
		return 0, nil, false
	}
	return http.StatusOK, map[string]any{"ok": true}, true
}

type errApprovalInvalidDecision struct{}

func (errApprovalInvalidDecision) Error() string { return "invalid decision" }

func decodeApprovalResolutionBody(r *http.Request) (approvals.Resolution, error) {
	raw, err := readRawJSONBody(r)
	if err != nil {
		return approvals.Resolution{}, err
	}
	return decodeApprovalResolution(raw)
}

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
