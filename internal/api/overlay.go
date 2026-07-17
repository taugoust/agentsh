package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/agentsh/agentsh/internal/workspace/overlay"
	"github.com/agentsh/agentsh/internal/workspace/shadow"
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
	sw := s.ShadowWorkspace()
	if ow == nil && sw == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "session has no reviewable workspace"})
		return
	}
	var out []byte
	var err error
	if sw != nil {
		out, err = sw.Diff(r.Context())
	} else {
		out, err = ow.Diff(r.Context())
	}
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, overlay.ErrInactive) || errors.Is(err, shadow.ErrInactive) {
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
	sw := s.ShadowWorkspace()
	if ow == nil && sw == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "session has no reviewable workspace"})
		return
	}
	if sw != nil {
		if err := sw.Accept(r.Context()); err != nil {
			code := http.StatusInternalServerError
			if errors.Is(err, shadow.ErrInactive) {
				code = http.StatusBadRequest
			}
			writeJSON(w, code, map[string]any{"error": err.Error()})
			return
		}
		now := time.Now().UTC()
		s.MarkShadowAccepted(now)
		ev := types.Event{
			ID:        uuid.NewString(),
			Timestamp: now,
			Type:      "shadow_accepted",
			SessionID: s.ID,
			Fields: map[string]any{
				"real": sw.Real,
				"work": sw.Work,
			},
		}
		_ = a.store.AppendEvent(r.Context(), ev)
		a.broker.Publish(ev)
		writeJSON(w, http.StatusOK, a.sessionSnapshot(s))
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
	writeJSON(w, http.StatusOK, a.sessionSnapshot(s))
}

func (a *App) rejectOverlay(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s, ok := a.sessions.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}
	ow := s.OverlayWorkspace()
	sw := s.ShadowWorkspace()
	if ow == nil && sw == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "session has no reviewable workspace"})
		return
	}
	if sw != nil {
		if err := sw.Reject(r.Context()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		now := time.Now().UTC()
		s.MarkShadowRejected(now)
		ev := types.Event{
			ID:        uuid.NewString(),
			Timestamp: now,
			Type:      "shadow_rejected",
			SessionID: s.ID,
			Fields: map[string]any{
				"real": sw.Real,
				"work": sw.Work,
			},
		}
		_ = a.store.AppendEvent(r.Context(), ev)
		a.broker.Publish(ev)
		writeJSON(w, http.StatusOK, a.sessionSnapshot(s))
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
	writeJSON(w, http.StatusOK, a.sessionSnapshot(s))
}
