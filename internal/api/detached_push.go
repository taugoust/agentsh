package api

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/agentsh/agentsh/internal/detached"
	"github.com/go-chi/chi/v5"
)

// Detached session events retain their compatibility callback because they are
// not part of the approval control stream. Approval propagation uses only the
// typed authenticated detached control exchange.
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
