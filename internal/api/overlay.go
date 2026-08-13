package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
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
		review, reviewErr := sw.Review(r.Context())
		err = reviewErr
		out = review.Diff
		if err == nil {
			w.Header().Set("X-AgentSH-Review-Generation", strconv.FormatUint(review.Generation, 10))
			w.Header().Set("X-AgentSH-Review-Hash", review.Hash)
			w.Header().Set("ETag", `"`+strconv.FormatUint(review.Generation, 10)+":"+review.Hash+`"`)
			w.Header().Set("Cache-Control", "no-store")
		}
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

type shadowAcceptRequest struct {
	ReviewGeneration uint64 `json:"review_generation"`
	ReviewHash       string `json:"review_hash"`
}

const shadowFinalizationTimeout = 30 * time.Minute

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
		var req shadowAcceptRequest
		if ok := decodeJSON(w, r, &req, "invalid json"); !ok {
			return
		}
		if req.ReviewGeneration == 0 || strings.TrimSpace(req.ReviewHash) == "" {
			writeJSON(w, http.StatusPreconditionRequired, map[string]any{"error": "shadow accept requires review_generation and review_hash from a fresh diff"})
			return
		}
		lease, err := s.TryBeginWorkspaceFinalization()
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
			return
		}
		seal := false
		defer func() { lease.Release(seal) }()
		finalizeCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), shadowFinalizationTimeout)
		defer cancel()
		if err := sw.AcceptReviewed(finalizeCtx, req.ReviewGeneration, req.ReviewHash); err != nil {
			code := http.StatusInternalServerError
			switch {
			case errors.Is(err, shadow.ErrInactive):
				code = http.StatusBadRequest
			case errors.Is(err, shadow.ErrStaleReview):
				code = http.StatusPreconditionFailed
			}
			writeJSON(w, code, map[string]any{"error": err.Error()})
			return
		}
		if a.detachedRuntime != nil {
			if err := a.detachedRuntime.MarkFinalizing(); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "workspace applied but durable finalization state could not be recorded"})
				return
			}
		}
		seal = true
		now := time.Now().UTC()
		s.MarkShadowAccepted(now)
		ev := types.Event{
			ID:        uuid.NewString(),
			Timestamp: now,
			Type:      "shadow_accepted",
			SessionID: s.ID,
			Fields: map[string]any{
				"real":              sw.Real,
				"work":              sw.Work,
				"review_generation": req.ReviewGeneration,
				"review_hash":       req.ReviewHash,
			},
		}
		if err := a.store.AppendEvent(finalizeCtx, ev); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "workspace applied but acceptance audit could not be persisted"})
			return
		}
		a.broker.Publish(ev)
		if a.detachedRuntime != nil {
			if err := a.detachedRuntime.MarkFinalized(); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "workspace applied but durable finalized state could not be recorded"})
				return
			}
		}
		if err := sw.CleanupFinalized(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "workspace accepted but finalized shadow cleanup failed"})
			return
		}
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
		lease, err := s.TryBeginWorkspaceFinalization()
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
			return
		}
		seal := false
		defer func() { lease.Release(seal) }()
		finalizeCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), shadowFinalizationTimeout)
		defer cancel()
		if err := sw.Reject(finalizeCtx); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		if a.detachedRuntime != nil {
			if err := a.detachedRuntime.MarkFinalizing(); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "workspace rejected but durable finalization state could not be recorded"})
				return
			}
		}
		seal = true
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
		if err := a.store.AppendEvent(finalizeCtx, ev); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "workspace rejected but rejection audit could not be persisted"})
			return
		}
		a.broker.Publish(ev)
		if a.detachedRuntime != nil {
			if err := a.detachedRuntime.MarkFinalized(); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "workspace rejected but durable finalized state could not be recorded"})
				return
			}
		}
		if err := sw.CleanupFinalized(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "workspace rejected but finalized shadow cleanup failed"})
			return
		}
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
