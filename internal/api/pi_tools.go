package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/pmezard/go-difflib/difflib"
)

const (
	defaultToolReadLimitBytes = 1 * 1024 * 1024
	maxToolFileBytes          = 4 * 1024 * 1024
)

type piToolActor map[string]any

type execBashToolRequest struct {
	Command                string            `json:"command"`
	Cwd                    string            `json:"cwd,omitempty"`
	TimeoutMS              *int64            `json:"timeout_ms,omitempty"`
	Env                    map[string]string `json:"env,omitempty"`
	Stdin                  string            `json:"stdin,omitempty"`
	IncludeEvents          string            `json:"include_events,omitempty"`
	PersistOutputOverBytes int64             `json:"persist_output_over_bytes,omitempty"`
	PersistOutputOverLines int64             `json:"persist_output_over_lines,omitempty"`
	Actor                  piToolActor       `json:"actor,omitempty"`
}

type fileToolRequest struct {
	Path       string      `json:"path"`
	Cwd        string      `json:"cwd,omitempty"`
	Content    string      `json:"content,omitempty"`
	Encoding   string      `json:"encoding,omitempty"`
	CreateDirs bool        `json:"create_dirs,omitempty"`
	MaxBytes   int64       `json:"max_bytes,omitempty"`
	Offset     int         `json:"offset,omitempty"`
	Limit      int         `json:"limit,omitempty"`
	OldText    string      `json:"oldText,omitempty"`
	NewText    string      `json:"newText,omitempty"`
	Actor      piToolActor `json:"actor,omitempty"`
}

type toolResponse struct {
	OK     bool   `json:"ok"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

type resolvedToolPath struct {
	Real           string
	Virtual        string
	InWorkspace    bool
	OutputArtifact bool
}

func (a *App) execBashTool(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req execBashToolRequest
	if ok := decodeJSON(w, r, &req, "invalid json"); !ok {
		return
	}
	if strings.TrimSpace(req.Command) == "" {
		writeToolError(w, http.StatusBadRequest, "command is required")
		return
	}
	timeout := ""
	if req.TimeoutMS != nil {
		if *req.TimeoutMS <= 0 {
			writeToolError(w, http.StatusBadRequest, "timeout_ms must be greater than zero")
			return
		}
		maxMilliseconds := int64(math.MaxInt64) / int64(time.Millisecond)
		if *req.TimeoutMS > maxMilliseconds {
			writeToolError(w, http.StatusBadRequest, "timeout_ms is too large")
			return
		}
		timeout = (time.Duration(*req.TimeoutMS) * time.Millisecond).String()
	}
	includeEvents := req.IncludeEvents
	if includeEvents == "" {
		includeEvents = "summary"
	}
	var outputArtifactRequest *types.OutputArtifactRequest
	if req.PersistOutputOverBytes != 0 || req.PersistOutputOverLines != 0 {
		outputArtifactRequest = &types.OutputArtifactRequest{
			PersistOverBytes: req.PersistOutputOverBytes,
			PersistOverLines: req.PersistOutputOverLines,
		}
		if err := validateOutputArtifactRequest(outputArtifactRequest); err != nil {
			writeToolError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	execReq := types.ExecRequest{
		Command: "bash",
		// Do not use a login shell here. On NixOS, /etc/profile rebuilds PATH from
		// HOME/USER and can discard the supervisor's controlled tool PATH (git, rg,
		// etc.), especially now that AgentSH provides a session-local HOME.
		Args:           []string{"-c", req.Command},
		Timeout:        timeout,
		WorkingDir:     req.Cwd,
		Env:            req.Env,
		Stdin:          req.Stdin,
		IncludeEvents:  includeEvents,
		OutputArtifact: outputArtifactRequest,
		Actor:          map[string]any(req.Actor),
	}
	resp, code, err := a.execInSessionCore(r.Context(), id, execReq)
	if err != nil {
		writeToolError(w, code, err.Error())
		return
	}
	// Preserve the established tool transport contract: semantic execution
	// refusals retain their HTTP status and ok:false while typed outcome fields
	// remain additive in the structured body.
	status := code
	if status == 0 {
		status = http.StatusOK
	}
	result := map[string]any{
		"command_id":         resp.CommandID,
		"session_id":         resp.SessionID,
		"exit_code":          resp.Result.ExitCode,
		"stdout":             resp.Result.Stdout,
		"stderr":             resp.Result.Stderr,
		"duration_ms":        resp.Result.DurationMs,
		"stdout_truncated":   resp.Result.StdoutTruncated,
		"stderr_truncated":   resp.Result.StderrTruncated,
		"stdout_total_bytes": resp.Result.StdoutTotalBytes,
		"stderr_total_bytes": resp.Result.StderrTotalBytes,
		"command_timeout":    resp.Result.CommandTimeout,
		"exec_response":      resp,
		"outcome":            resp.Result.Outcome,
		"command_started":    resp.Result.Outcome != nil && resp.Result.Outcome.CommandStarted,
	}
	if resp.Result.Error != nil {
		result["error"] = resp.Result.Error
		result["error_code"] = resp.Result.Error.Code
		result["error_message"] = resp.Result.Error.Message
	}
	if resp.Result.TerminationReason != "" {
		result["termination_reason"] = resp.Result.TerminationReason
	}
	if resp.Result.Error != nil {
		result["error"] = resp.Result.Error
	}
	if artifact := resp.Result.OutputArtifact; artifact != nil {
		result["output_artifact"] = artifact
		result["full_output_path"] = artifact.Path
		result["artifact_bytes"] = artifact.Bytes
		result["artifact_total_bytes"] = artifact.TotalBytes
		result["artifact_complete"] = artifact.Complete
		if artifact.ErrorMessage != "" {
			result["artifact_error"] = artifact.ErrorMessage
		}
	}
	writeJSON(w, status, toolResponse{OK: status >= 200 && status < 300, Result: result})
}

func (a *App) readFileTool(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req fileToolRequest
	if ok := decodeJSON(w, r, &req, "invalid json"); !ok {
		return
	}
	s, rp, code, err := a.resolveToolFileRequest(r.Context(), id, req.Path, req.Cwd, "read", req.Actor, true)
	if err != nil {
		writeToolError(w, code, err.Error())
		return
	}
	maxBytes := req.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultToolReadLimitBytes
	}
	if maxBytes > maxToolFileBytes {
		maxBytes = maxToolFileBytes
	}
	var f *os.File
	var info os.FileInfo
	if rp.OutputArtifact {
		f, info, err = s.OpenOutputArtifact(rp.Real)
	} else {
		f, err = os.Open(rp.Real)
		if err == nil {
			info, err = f.Stat()
		}
	}
	if err != nil {
		status := statusForFileError(err)
		if rp.OutputArtifact && status == http.StatusInternalServerError {
			status = http.StatusForbidden
		}
		writeToolError(w, status, err.Error())
		return
	}
	defer f.Close()
	window, err := readTextLineWindow(f, req.Offset, req.Limit, maxBytes)
	if err != nil {
		writeToolError(w, http.StatusInternalServerError, err.Error())
		return
	}
	result := map[string]any{
		"path":           rp.Virtual,
		"real_path":      rp.Real,
		"size":           info.Size(),
		"truncated":      window.Truncated,
		"byte_truncated": window.ByteTruncated,
		"start_line":     window.StartLine,
		"end_line":       window.EndLine,
		"max_bytes":      maxBytes,
	}
	if window.NextOffset > 0 {
		result["next_offset"] = window.NextOffset
	}
	if utf8.Valid(window.Content) {
		result["encoding"] = "utf-8"
		result["content"] = string(window.Content)
	} else {
		result["encoding"] = "base64"
		result["content"] = base64.StdEncoding.EncodeToString(window.Content)
	}
	writeJSON(w, http.StatusOK, toolResponse{OK: true, Result: result})
}

func (a *App) writeFileTool(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := a.detachedMutationReady(); err != nil {
		writeToolError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	var req fileToolRequest
	if ok := decodeJSON(w, r, &req, "invalid json"); !ok {
		return
	}
	rp, data, code, err := a.prepareWriteFileTool(r.Context(), id, req, "write")
	if err != nil {
		writeToolError(w, code, err.Error())
		return
	}
	completeMutation, err := a.beginDetachedMutation("write_file")
	if err != nil {
		writeToolError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	defer completeMutation()
	if req.CreateDirs {
		if err := os.MkdirAll(filepath.Dir(rp.Real), 0o755); err != nil {
			writeToolError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if err := os.WriteFile(rp.Real, data, 0o644); err != nil {
		writeToolError(w, statusForFileError(err), err.Error())
		return
	}
	a.emitToolEvent(r.Context(), id, "tool_write_file", "write", rp.Virtual, req.Actor, map[string]any{"bytes": len(data)})
	writeJSON(w, http.StatusOK, toolResponse{OK: true, Result: map[string]any{
		"path":          rp.Virtual,
		"real_path":     rp.Real,
		"bytes_written": len(data),
	}})
}

func (a *App) editFileTool(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := a.detachedMutationReady(); err != nil {
		writeToolError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	var req fileToolRequest
	if ok := decodeJSON(w, r, &req, "invalid json"); !ok {
		return
	}
	if req.OldText == "" {
		writeToolError(w, http.StatusBadRequest, "oldText is required")
		return
	}
	s, rp, code, err := a.resolveToolFileRequest(r.Context(), id, req.Path, req.Cwd, "read", req.Actor, false)
	if err != nil {
		writeToolError(w, code, err.Error())
		return
	}
	if code, err := a.enforceToolFilePolicy(r.Context(), s, "write", rp.Real, req.Actor); err != nil {
		writeToolError(w, code, err.Error())
		return
	}
	data, err := os.ReadFile(rp.Real)
	if err != nil {
		writeToolError(w, statusForFileError(err), err.Error())
		return
	}
	if len(data) > maxToolFileBytes {
		writeToolError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("file exceeds edit limit of %d bytes", maxToolFileBytes))
		return
	}
	oldB := []byte(req.OldText)
	count := bytes.Count(data, oldB)
	if count == 0 {
		writeToolError(w, http.StatusConflict, "oldText not found")
		return
	}
	if count > 1 {
		writeToolError(w, http.StatusConflict, "oldText is not unique")
		return
	}
	newData := bytes.Replace(data, oldB, []byte(req.NewText), 1)
	if len(newData) > maxToolFileBytes {
		writeToolError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("edited file exceeds limit of %d bytes", maxToolFileBytes))
		return
	}
	completeMutation, err := a.beginDetachedMutation("edit_file")
	if err != nil {
		writeToolError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	defer completeMutation()
	if err := os.WriteFile(rp.Real, newData, 0o644); err != nil {
		writeToolError(w, statusForFileError(err), err.Error())
		return
	}
	diff := ""
	if utf8.Valid(data) && utf8.Valid(newData) {
		diff = unifiedEditDiff(rp.Virtual, string(data), string(newData))
	}
	a.emitToolEvent(r.Context(), id, "tool_edit_file", "write", rp.Virtual, req.Actor, map[string]any{"bytes_written": len(newData)})
	result := map[string]any{
		"path":          rp.Virtual,
		"real_path":     rp.Real,
		"bytes_written": len(newData),
		"replacements":  1,
	}
	if diff != "" {
		result["diff"] = diff
		result["details"] = map[string]any{"diff": diff}
	}
	writeJSON(w, http.StatusOK, toolResponse{OK: true, Result: result})
}

func unifiedEditDiff(path, oldText, newText string) string {
	if oldText == newText {
		return ""
	}
	diff, err := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A:        difflib.SplitLines(oldText),
		B:        difflib.SplitLines(newText),
		FromFile: "a/" + strings.TrimPrefix(path, "/"),
		ToFile:   "b/" + strings.TrimPrefix(path, "/"),
		Context:  3,
	})
	if err != nil {
		return ""
	}
	return diff
}

func (a *App) prepareWriteFileTool(ctx context.Context, sessionID string, req fileToolRequest, operation string) (resolvedToolPath, []byte, int, error) {
	s, ok := a.sessions.Get(sessionID)
	if !ok {
		return resolvedToolPath{}, nil, http.StatusNotFound, errors.New("session not found")
	}
	rp, err := resolveToolPath(s, req.Path, req.Cwd)
	if err != nil {
		return resolvedToolPath{}, nil, http.StatusBadRequest, err
	}
	if rp.InWorkspace {
		if err := ensureToolPathNoSymlinkEscape(rp.Real, s.WorkspaceMountPath()); err != nil {
			return resolvedToolPath{}, nil, http.StatusBadRequest, err
		}
	}
	policyOperation := operation
	if _, statErr := os.Stat(rp.Real); os.IsNotExist(statErr) {
		policyOperation = "create"
	}
	if code, err := a.enforceToolFilePolicy(ctx, s, policyOperation, rp.Real, req.Actor); err != nil {
		return resolvedToolPath{}, nil, code, err
	}
	data := []byte(req.Content)
	switch strings.ToLower(strings.TrimSpace(req.Encoding)) {
	case "", "utf-8", "utf8":
	case "base64":
		decoded, decErr := base64.StdEncoding.DecodeString(req.Content)
		if decErr != nil {
			return resolvedToolPath{}, nil, http.StatusBadRequest, fmt.Errorf("invalid base64 content: %w", decErr)
		}
		data = decoded
	default:
		return resolvedToolPath{}, nil, http.StatusBadRequest, fmt.Errorf("unsupported encoding %q", req.Encoding)
	}
	if len(data) > maxToolFileBytes {
		return resolvedToolPath{}, nil, http.StatusRequestEntityTooLarge, fmt.Errorf("content exceeds write limit of %d bytes", maxToolFileBytes)
	}
	if !req.CreateDirs {
		if _, err := os.Stat(filepath.Dir(rp.Real)); err != nil {
			return resolvedToolPath{}, nil, statusForFileError(err), err
		}
	}
	return rp, data, http.StatusOK, nil
}

func (a *App) resolveToolFileRequest(ctx context.Context, sessionID, reqPath, reqCwd, operation string, actor piToolActor, allowOutputArtifact bool) (*session.Session, resolvedToolPath, int, error) {
	s, ok := a.sessions.Get(sessionID)
	if !ok {
		return nil, resolvedToolPath{}, http.StatusNotFound, errors.New("session not found")
	}
	// Output artifacts are server-created, bounded files whose exact identity is
	// registered on the session. Permit only that exact read capability before
	// applying the normal shadow/overlay workspace boundary; no RuntimeTmp
	// directory or prefix is made generally readable.
	if allowOutputArtifact && operation == "read" {
		if artifactPath, registered := s.RegisteredOutputArtifactPath(reqPath); registered {
			return s, resolvedToolPath{
				Real:           artifactPath,
				Virtual:        filepath.ToSlash(artifactPath),
				OutputArtifact: true,
			}, http.StatusOK, nil
		}
	}
	rp, err := resolveToolPath(s, reqPath, reqCwd)
	if err != nil {
		return nil, resolvedToolPath{}, http.StatusBadRequest, err
	}
	if rp.InWorkspace {
		if err := ensureToolPathNoSymlinkEscape(rp.Real, s.WorkspaceMountPath()); err != nil {
			return nil, resolvedToolPath{}, http.StatusBadRequest, err
		}
	}
	if code, err := a.enforceToolFilePolicy(ctx, s, operation, rp.Real, actor); err != nil {
		return nil, resolvedToolPath{}, code, err
	}
	return s, rp, http.StatusOK, nil
}

func resolveToolPath(s *session.Session, reqPath, reqCwd string) (resolvedToolPath, error) {
	if strings.TrimSpace(reqPath) == "" {
		return resolvedToolPath{}, errors.New("path is required")
	}
	cwd, _, _ := s.GetCwdEnvHistory()
	if cwd == "" {
		cwd = s.VirtualRoot
	}
	if cwd == "" {
		cwd = "/workspace"
	}
	virtualCwd := cwd
	if reqCwd != "" {
		if strings.HasPrefix(reqCwd, "/") || filepath.IsAbs(reqCwd) {
			virtualCwd = filepath.ToSlash(reqCwd)
		} else {
			virtualCwd = filepath.ToSlash(filepath.Join(cwd, reqCwd))
		}
	}
	var virtual string
	if strings.HasPrefix(reqPath, "/") || filepath.IsAbs(reqPath) {
		virtual = filepath.ToSlash(reqPath)
	} else {
		virtual = filepath.ToSlash(filepath.Join(virtualCwd, reqPath))
	}
	virtual = filepath.ToSlash(filepath.Clean(filepath.FromSlash(virtual)))

	vroot := s.VirtualRoot
	if vroot == "" {
		vroot = "/workspace"
	}
	root := filepath.Clean(s.WorkspaceMountPath())
	if session.IsUnderRoot(virtual, vroot) {
		rel := strings.TrimPrefix(session.TrimRootPrefix(virtual, vroot), "/")
		relPath := filepath.FromSlash(rel)
		if filepath.IsAbs(relPath) {
			return resolvedToolPath{}, errors.New("path contains absolute path component")
		}
		real := filepath.Clean(filepath.Join(root, relPath))
		if !session.IsRealPathUnder(real, root) {
			return resolvedToolPath{}, errors.New("path escapes workspace mount")
		}
		return resolvedToolPath{Real: real, Virtual: virtual, InWorkspace: true}, nil
	}

	// Direct-workspace tool sessions intentionally operate on host paths.  The
	// trusted parent Pi may ask to read/write outside the opened workspace; that
	// must be policy-approved/denied rather than rejected by the REST tool path
	// normalizer.  Shadow/overlay sessions keep the stricter /workspace-only
	// invariant because their mount path is the isolation boundary.
	if s.WorkspaceMode != string(types.WorkspaceModeDirect) || vroot == "/workspace" {
		return resolvedToolPath{}, fmt.Errorf("path must be under %s", vroot)
	}

	var real string
	if strings.HasPrefix(reqPath, "/") || filepath.IsAbs(reqPath) {
		real = filepath.Clean(filepath.FromSlash(reqPath))
	} else {
		base := filepath.Clean(filepath.FromSlash(virtualCwd))
		if session.IsUnderRoot(filepath.ToSlash(base), vroot) {
			rel := strings.TrimPrefix(session.TrimRootPrefix(filepath.ToSlash(base), vroot), "/")
			base = filepath.Clean(filepath.Join(root, filepath.FromSlash(rel)))
		}
		real = filepath.Clean(filepath.Join(base, filepath.FromSlash(reqPath)))
	}
	if !filepath.IsAbs(real) {
		return resolvedToolPath{}, errors.New("path resolves to non-absolute host path")
	}
	return resolvedToolPath{Real: real, Virtual: filepath.ToSlash(real), InWorkspace: session.IsRealPathUnder(real, root)}, nil
}

func ensureToolPathNoSymlinkEscape(realPath, root string) error {
	rootClean := filepath.Clean(root)
	rootResolved, err := filepath.EvalSymlinks(rootClean)
	if err != nil {
		if !os.IsPermission(err) {
			return fmt.Errorf("resolve workspace mount: %w", err)
		}
		rootResolved = rootClean
	}
	checkPath := realPath
	if _, err := os.Lstat(checkPath); err != nil {
		checkPath = filepath.Dir(checkPath)
	}
	for {
		resolved, err := filepath.EvalSymlinks(checkPath)
		if err == nil {
			resolved = filepath.Clean(resolved)
			if !session.IsRealPathUnder(resolved, rootResolved) {
				return errors.New("path symlink escapes workspace mount")
			}
			return nil
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("resolve path: %w", err)
		}
		parent := filepath.Dir(checkPath)
		if parent == checkPath || !session.IsRealPathUnder(parent, rootClean) {
			return nil
		}
		checkPath = parent
	}
}

func (a *App) enforceToolFilePolicy(ctx context.Context, s *session.Session, operation, virtualPath string, actor piToolActor) (int, error) {
	engine := a.policyEngineFor(s)
	if engine == nil {
		return http.StatusOK, nil
	}
	dec := engine.CheckFile(virtualPath, operation)
	fields := map[string]any{"path": virtualPath, "operation": operation}
	if actor != nil {
		fields["actor"] = map[string]any(actor)
	}
	a.emitToolEvent(ctx, s.ID, "tool_file_policy", operation, virtualPath, actor, map[string]any{
		"policy_decision":    string(dec.PolicyDecision),
		"effective_decision": string(dec.EffectiveDecision),
		"rule":               dec.Rule,
	})
	if dec.PolicyDecision == types.DecisionApprove && dec.EffectiveDecision == types.DecisionApprove {
		if a.approvals == nil {
			return http.StatusForbidden, errors.New("operation requires approval but approvals are not enabled")
		}
		scope, ok, scopeOptions := fileApprovalScopeOptions(operation, virtualPath, dec.Rule)
		if !ok {
			return http.StatusForbidden, errors.New("operation requires approval but no valid approval scope exists")
		}
		if cached, ok := a.approvals.CheckScoped(ctx, s.ID, "", scope); ok {
			if cached.Approved {
				return http.StatusOK, nil
			}
			return http.StatusForbidden, errors.New("operation denied by scoped approval")
		}
		for k, v := range approvals.ScopeFields(scope) {
			fields[k] = v
		}
		fields["scope_options"] = scopeOptions
		res, err := a.approvals.RequestApproval(ctx, approvals.Request{
			ID:        "approval-" + uuid.NewString(),
			SessionID: s.ID,
			Kind:      "file",
			Target:    virtualPath,
			Rule:      dec.Rule,
			Message:   dec.Message,
			Fields:    fields,
		})
		if err != nil {
			return http.StatusForbidden, fmt.Errorf("approval failed: %w", err)
		}
		if !res.Approved {
			return http.StatusForbidden, errors.New("operation denied by approval")
		}
		return http.StatusOK, nil
	}
	if dec.EffectiveDecision == types.DecisionDeny {
		return http.StatusForbidden, fmt.Errorf("operation denied by policy rule %q", dec.Rule)
	}
	return http.StatusOK, nil
}

func (a *App) emitToolEvent(ctx context.Context, sessionID, eventType, operation, path string, actor piToolActor, extra map[string]any) {
	if a == nil || a.store == nil || a.broker == nil {
		return
	}
	fields := map[string]any{}
	for k, v := range extra {
		fields[k] = v
	}
	if actor != nil {
		fields["actor"] = map[string]any(actor)
	}
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      eventType,
		SessionID: sessionID,
		Operation: operation,
		Path:      path,
		Fields:    fields,
	}
	_ = a.store.AppendEvent(ctx, ev)
	a.broker.Publish(ev)
}

func writeToolError(w http.ResponseWriter, code int, msg string) {
	if code == 0 {
		code = http.StatusInternalServerError
	}
	writeJSON(w, code, toolResponse{OK: false, Error: msg})
}

func statusForFileError(err error) int {
	switch {
	case os.IsNotExist(err):
		return http.StatusNotFound
	case os.IsPermission(err):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}
