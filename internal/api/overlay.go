package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/session"
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
		reserved, lease, reserveErr := a.reserveWorkspaceFinalization(id, false)
		if reserveErr != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"error": reserveErr.Error()})
			return
		}
		defer lease.Release(false)
		sw = reserved.ShadowWorkspace()
		if sw == nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "session has no shadow workspace"})
			return
		}
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

func (a *App) reserveWorkspaceFinalization(id string, resume bool) (*session.Session, *session.WorkspaceFinalizationLease, error) {
	a.sessionTopologyMu.Lock()
	defer a.sessionTopologyMu.Unlock()
	s, ok := a.sessions.Get(id)
	if !ok {
		return nil, nil, fmt.Errorf("session not found")
	}
	var lease *session.WorkspaceFinalizationLease
	var err error
	if resume {
		lease, err = s.TryResumeWorkspaceFinalization()
	} else {
		lease, err = s.TryBeginWorkspaceFinalization()
	}
	if err != nil {
		return nil, nil, err
	}
	return s, lease, nil
}

func (a *App) persistShadowFinalizationAudit(ctx context.Context, s *session.Session, sw *shadow.Workspace, intent shadow.Finalization, recovered bool) error {
	eventType := "shadow_rejected"
	if intent.Action == shadow.FinalizationAccept {
		eventType = "shadow_accepted"
	}
	existing, err := a.store.QueryEvents(ctx, types.EventQuery{SessionID: s.ID, Types: []string{eventType}, Limit: 500, Asc: false})
	if err != nil {
		return err
	}
	for _, event := range existing {
		if event.Fields["finalization_id"] == intent.ID {
			return a.store.FlushSync(ctx)
		}
	}
	now := time.Now().UTC()
	event := types.Event{
		ID: intent.ID + "-audit", Timestamp: now, Type: eventType, SessionID: s.ID,
		Fields: map[string]any{
			"real": sw.Real, "work": sw.Work, "finalization_id": intent.ID,
			"review_generation": intent.ReviewGeneration, "review_hash": intent.ReviewHash,
			"recovered": recovered,
		},
	}
	if err := a.store.AppendEvent(ctx, event); err != nil {
		return err
	}
	if err := a.store.FlushSync(ctx); err != nil {
		return fmt.Errorf("flush finalization audit: %w", err)
	}
	a.broker.Publish(event)
	return nil
}

func (a *App) completeShadowFinalization(ctx context.Context, s *session.Session, sw *shadow.Workspace, intent shadow.Finalization, recovered bool) error {
	now := time.Now().UTC()
	if intent.Action == shadow.FinalizationAccept {
		s.MarkShadowAccepted(now)
	} else {
		s.MarkShadowRejected(now)
	}
	if a.detachedRuntime != nil {
		if err := a.detachedRuntime.MarkFinalizationApplied(intent.ID); err != nil {
			return err
		}
	}
	if err := a.persistShadowFinalizationAudit(ctx, s, sw, intent, recovered); err != nil {
		return err
	}
	if a.detachedRuntime != nil {
		if err := a.detachedRuntime.MarkFinalizationAudited(intent.ID); err != nil {
			return err
		}
	}
	if err := sw.CleanupFinalized(); err != nil {
		return err
	}
	if a.detachedRuntime != nil {
		if err := a.detachedRuntime.MarkFinalizationCleanupComplete(intent.ID); err != nil {
			return err
		}
		if err := a.detachedRuntime.MarkFinalized(intent.ID); err != nil {
			return err
		}
		a.signalDetachedStop()
	}
	return nil
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
		var req shadowAcceptRequest
		if ok := decodeJSON(w, r, &req, "invalid json"); !ok {
			return
		}
		if req.ReviewGeneration == 0 || strings.TrimSpace(req.ReviewHash) == "" {
			writeJSON(w, http.StatusPreconditionRequired, map[string]any{"error": "shadow accept requires review_generation and review_hash from a fresh diff"})
			return
		}
		pending, resume := sw.PendingFinalization()
		if resume && (pending.Action != shadow.FinalizationAccept || pending.ReviewGeneration != req.ReviewGeneration || pending.ReviewHash != req.ReviewHash) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "a different shadow finalization is pending"})
			return
		}
		s, lease, err := a.reserveWorkspaceFinalization(id, resume)
		if err != nil {
			code := http.StatusConflict
			if err.Error() == "session not found" {
				code = http.StatusNotFound
			}
			writeJSON(w, code, map[string]any{"error": err.Error()})
			return
		}
		sw = s.ShadowWorkspace()
		if sw == nil {
			lease.Release(false)
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "session has no shadow workspace"})
			return
		}
		seal := false
		defer func() { lease.Release(seal) }()
		finalizeCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), shadowFinalizationTimeout)
		defer cancel()
		finalizationID := "shadow-finalization-" + uuid.NewString()
		intent := pending
		if !resume {
			intent, err = sw.PrepareAccept(finalizeCtx, finalizationID, req.ReviewGeneration, req.ReviewHash)
		} else {
			finalizationID = pending.ID
		}
		if err != nil {
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
		lease.MarkPending()
		if a.detachedRuntime != nil {
			durable := detached.ShadowFinalizationRecovery{ID: intent.ID, Action: intent.Action, ReviewGeneration: intent.ReviewGeneration, ReviewHash: intent.ReviewHash, CreatedAt: intent.CreatedAt}
			if err := a.detachedRuntime.MarkFinalizing(durable); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "refusing workspace apply because durable finalization state could not be recorded"})
				return
			}
		}
		if err := sw.ApplyFinalization(finalizeCtx, finalizationID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "workspace apply failed after durable finalization began: " + err.Error()})
			return
		}
		if err := a.completeShadowFinalization(finalizeCtx, s, sw, intent, false); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "workspace apply is retained for finalization retry: " + err.Error()})
			return
		}
		seal = true
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
		pending, resume := sw.PendingFinalization()
		if resume && pending.Action != shadow.FinalizationReject {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "a different shadow finalization is pending"})
			return
		}
		s, lease, err := a.reserveWorkspaceFinalization(id, resume)
		if err != nil {
			code := http.StatusConflict
			if err.Error() == "session not found" {
				code = http.StatusNotFound
			}
			writeJSON(w, code, map[string]any{"error": err.Error()})
			return
		}
		sw = s.ShadowWorkspace()
		if sw == nil {
			lease.Release(false)
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "session has no shadow workspace"})
			return
		}
		seal := false
		defer func() { lease.Release(seal) }()
		finalizeCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), shadowFinalizationTimeout)
		defer cancel()
		finalizationID := "shadow-finalization-" + uuid.NewString()
		intent := pending
		if !resume {
			intent, err = sw.PrepareReject(finalizeCtx, finalizationID)
		} else {
			finalizationID = pending.ID
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		lease.MarkPending()
		if a.detachedRuntime != nil {
			durable := detached.ShadowFinalizationRecovery{ID: intent.ID, Action: intent.Action, CreatedAt: intent.CreatedAt}
			if err := a.detachedRuntime.MarkFinalizing(durable); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "workspace rejection intent is retained but durable detached finalization could not be recorded"})
				return
			}
		}
		if err := sw.ApplyFinalization(finalizeCtx, finalizationID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		if err := a.completeShadowFinalization(finalizeCtx, s, sw, intent, false); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "workspace rejection is retained for finalization retry: " + err.Error()})
			return
		}
		seal = true
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
