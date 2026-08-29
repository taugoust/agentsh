package api

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

var (
	draftLandingSessionPattern = regexp.MustCompile(`^session-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	draftLandingCommitPattern  = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	draftLandingDigestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type draftLandingApprovalRequest struct {
	DraftID      string   `json:"draft_id"`
	ResultCommit string   `json:"result_commit"`
	PathCount    int      `json:"path_count"`
	PathsDigest  string   `json:"paths_digest"`
	Paths        []string `json:"paths"`
}

func validateDraftLandingPaths(paths []string, count int, digest string) error {
	if count < 1 || count > 10000 || len(paths) != count {
		return fmt.Errorf("invalid restricted path count")
	}
	hash := sha256.New()
	totalBytes := 0
	for _, candidate := range paths {
		totalBytes += len(candidate)
		if candidate == "" || !utf8.ValidString(candidate) || strings.ContainsRune(candidate, '\x00') ||
			strings.HasPrefix(candidate, "/") || path.Clean(candidate) != candidate || candidate == "." {
			return fmt.Errorf("invalid restricted path")
		}
		_, _ = hash.Write([]byte(candidate))
		_, _ = hash.Write([]byte{0})
	}
	if totalBytes > 1024*1024 || digest != fmt.Sprintf("sha256:%x", hash.Sum(nil)) {
		return fmt.Errorf("restricted path digest mismatch")
	}
	return nil
}

func (a *App) requestDraftLandingApproval(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	sess, ok := a.sessions.Get(sessionID)
	if !ok {
		writeToolError(w, http.StatusNotFound, "session not found")
		return
	}
	claim, err := a.authenticateChildCapabilityProcessGroup(r, sessionID)
	if err != nil {
		writeToolError(w, http.StatusUnauthorized, "valid active child process-group capability required")
		return
	}
	if err := a.validateChildCapabilityClaim(claim); err != nil {
		writeToolError(w, http.StatusUnauthorized, "active child capability is no longer valid")
		return
	}
	var req draftLandingApprovalRequest
	if ok := decodeJSON(w, r, &req, "invalid Draft landing approval request"); !ok {
		return
	}
	if !draftLandingSessionPattern.MatchString(req.DraftID) || !draftLandingCommitPattern.MatchString(req.ResultCommit) ||
		!draftLandingDigestPattern.MatchString(req.PathsDigest) || validateDraftLandingPaths(req.Paths, req.PathCount, req.PathsDigest) != nil {
		writeToolError(w, http.StatusBadRequest, "invalid Draft landing approval identity")
		return
	}
	if a.approvals == nil {
		writeToolError(w, http.StatusServiceUnavailable, "approval manager is unavailable")
		return
	}
	ctx, cleanup := contextForChildCapability(r.Context(), claim)
	defer cleanup()
	quotedPaths := make([]string, 0, len(req.Paths))
	for _, restrictedPath := range req.Paths {
		quotedPaths = append(quotedPaths, fmt.Sprintf("  %q", restrictedPath))
	}
	request := approvals.Request{
		ID:        "approval-" + uuid.NewString(),
		SessionID: sess.ID,
		CommandID: claim.laneID,
		Kind:      "approval",
		Target:    fmt.Sprintf("%s (%d restricted paths)", req.DraftID, req.PathCount),
		Rule:      "approve-restricted-draft-landing",
		Message:   "Pi wants to land a MicroVM Draft that modifies restricted project files:\n" + strings.Join(quotedPaths, "\n"),
		Fields: map[string]any{
			"draft_id":      req.DraftID,
			"result_commit": strings.ToLower(req.ResultCommit),
			"path_count":    req.PathCount,
			"paths_digest":  strings.ToLower(req.PathsDigest),
			"paths":         req.Paths,
			"subagent_id":   claim.laneID,
		},
	}
	resolution, err := a.approvals.RequestApproval(ctx, request)
	if err != nil {
		writeToolError(w, http.StatusForbidden, "restricted Draft landing approval failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"approved": resolution.Approved})
}
