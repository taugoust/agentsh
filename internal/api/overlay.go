package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/agentsh/agentsh/internal/workspace/overlay"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (a *App) diffOverlay(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s, ok := a.sessions.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}
	ow := s.OverlayWorkspace()
	if ow == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "session has no overlay workspace"})
		return
	}
	out, err := ow.Diff(r.Context())
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, overlay.ErrInactive) {
			code = http.StatusBadRequest
		}
		writeJSON(w, code, map[string]any{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(out)
}

func (a *App) acceptOverlay(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s, ok := a.sessions.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}
	ow := s.OverlayWorkspace()
	if ow == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "session has no overlay workspace"})
		return
	}
	if err := ow.Accept(r.Context()); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, overlay.ErrInactive) {
			code = http.StatusBadRequest
		}
		writeJSON(w, code, map[string]any{"error": err.Error()})
		return
	}
	now := time.Now().UTC()
	s.MarkOverlayAccepted(now)
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: now,
		Type:      "overlay_accepted",
		SessionID: s.ID,
		Fields: map[string]any{
			"real":   ow.Real,
			"merged": ow.Merged,
		},
	}
	_ = a.store.AppendEvent(r.Context(), ev)
	a.broker.Publish(ev)
	writeJSON(w, http.StatusOK, s.Snapshot())
}

func (a *App) rejectOverlay(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s, ok := a.sessions.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}
	ow := s.OverlayWorkspace()
	if ow == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "session has no overlay workspace"})
		return
	}
	if err := ow.Reject(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	now := time.Now().UTC()
	s.MarkOverlayRejected(now)
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: now,
		Type:      "overlay_rejected",
		SessionID: s.ID,
		Fields: map[string]any{
			"real":   ow.Real,
			"merged": ow.Merged,
		},
	}
	_ = a.store.AppendEvent(r.Context(), ev)
	a.broker.Publish(ev)
	writeJSON(w, http.StatusOK, s.Snapshot())
}
