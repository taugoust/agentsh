package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const (
	maxSubagentParallelTasks           = 8
	maxSubagentConcurrency             = 4
	maxDraftSubagentConcurrency        = 2
	maxSubagentTextBytes               = 2 * 1024 * 1024
	subagentDeadlineEpochMSEnvironment = "AGENTSH_SUBAGENT_DEADLINE_EPOCH_MS"
)

type spawnSubagentToolRequest struct {
	RequestID                    string                `json:"request_id,omitempty"`
	Mode                         string                `json:"mode,omitempty"`
	Task                         string                `json:"task,omitempty"`
	Action                       string                `json:"action,omitempty"`
	DraftID                      string                `json:"draft_id,omitempty"`
	SystemPrompt                 string                `json:"systemPrompt,omitempty"`
	Model                        string                `json:"model,omitempty"`
	Tools                        []string              `json:"tools,omitempty"`
	Cwd                          string                `json:"cwd,omitempty"`
	Tasks                        []subagentItemRequest `json:"tasks,omitempty"`
	Chain                        []subagentItemRequest `json:"chain,omitempty"`
	TimeoutMS                    int64                 `json:"timeout_ms,omitempty"`
	ResultArtifactThresholdBytes int64                 `json:"result_artifact_threshold_bytes,omitempty"`
	Stream                       bool                  `json:"stream,omitempty"`
	Actor                        piToolActor           `json:"actor,omitempty"`
}

type subagentItemRequest struct {
	Task         string   `json:"task"`
	Action       string   `json:"action,omitempty"`
	DraftID      string   `json:"draft_id,omitempty"`
	SystemPrompt string   `json:"systemPrompt,omitempty"`
	Model        string   `json:"model,omitempty"`
	Tools        []string `json:"tools,omitempty"`
	Cwd          string   `json:"cwd,omitempty"`
}

type subagentRuntimeConfig struct {
	Name      string
	Isolation string
	Command   string
	Args      []string
	TaskMode  string
	Protocol  string
	MaxDepth  int
	SocketURL string
}

type subagentResult struct {
	SubagentID          string                       `json:"subagent_id"`
	Label               string                       `json:"label"`
	Task                string                       `json:"task"`
	ExitCode            int                          `json:"exit_code"`
	StopReason          string                       `json:"stop_reason"`
	ModelStopReason     string                       `json:"model_stop_reason,omitempty"`
	Terminal            subagentTerminal             `json:"terminal"`
	Final               string                       `json:"final"`
	ProtocolSettled     bool                         `json:"protocol_settled,omitempty"`
	ProtocolDiagnostics []subagentProtocolDiagnostic `json:"protocol_diagnostics,omitempty"`
	Stdout              string                       `json:"stdout,omitempty"`
	StdoutTruncated     bool                         `json:"stdout_truncated,omitempty"`
	StdoutTotalBytes    int64                        `json:"stdout_total_bytes,omitempty"`
	Stderr              string                       `json:"stderr,omitempty"`
	StderrTruncated     bool                         `json:"stderr_truncated,omitempty"`
	StderrTotalBytes    int64                        `json:"stderr_total_bytes,omitempty"`
	DurationMS          int64                        `json:"duration_ms"`
	Model               string                       `json:"model,omitempty"`
	Tools               []string                     `json:"tools,omitempty"`
	Cwd                 string                       `json:"cwd,omitempty"`
	Runtime             string                       `json:"runtime,omitempty"`
	Command             string                       `json:"command,omitempty"`
	Args                []string                     `json:"args,omitempty"`
	Error               string                       `json:"error,omitempty"`
	FullResultPath      string                       `json:"full_result_path,omitempty"`
	FinalTruncated      bool                         `json:"final_truncated,omitempty"`
	FinalTotalBytes     int64                        `json:"final_total_bytes,omitempty"`
	FinalInlineBytes    int64                        `json:"final_inline_bytes,omitempty"`
	ArtifactBytes       int64                        `json:"artifact_bytes,omitempty"`
	ArtifactComplete    *bool                        `json:"artifact_complete,omitempty"`
	ArtifactError       string                       `json:"artifact_error,omitempty"`
	DraftID             string                       `json:"draft_id,omitempty"`
	DraftStatus         string                       `json:"draft_status,omitempty"`
	DraftSummary        string                       `json:"draft_summary,omitempty"`
	DraftSealed         bool                         `json:"draft_sealed,omitempty"`
}

type spawnSubagentResult struct {
	RequestID string           `json:"request_id"`
	Mode      string           `json:"mode"`
	Final     string           `json:"final"`
	Summary   string           `json:"summary"`
	Terminal  subagentTerminal `json:"terminal"`
	Results   []subagentResult `json:"results"`
}

func (a *App) subagentExecutionTimeout(s *session.Session, timeoutMS int64) (time.Duration, error) {
	if timeoutMS < 0 {
		return 0, errors.New("timeout_ms must be non-negative")
	}
	// The server setting is a compatibility fallback for policies that do not
	// define a subagent limit. A positive effective policy value is authoritative.
	configured := config.DefaultSubagentTimeout
	if a != nil && a.cfg != nil {
		configured = a.cfg.Sessions.Subagents.DefaultTimeoutDuration()
	}
	if a != nil {
		if engine := a.policyEngineFor(s); engine != nil {
			if policyTimeout := engine.Limits().SubagentTimeout; policyTimeout > 0 {
				configured = policyTimeout
			}
		}
	}
	if timeoutMS == 0 {
		return configured, nil
	}
	maxMilliseconds := int64(time.Duration(1<<63-1) / time.Millisecond)
	if timeoutMS > maxMilliseconds {
		return 0, errors.New("timeout_ms is too large")
	}
	requested := time.Duration(timeoutMS) * time.Millisecond
	if requested < configured {
		return requested, nil
	}
	return configured, nil
}

func (a *App) spawnSubagentTool(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	if err := a.detachedMutationReady(); err != nil {
		writeToolError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s, ok := a.sessions.Get(sessionID)
	if !ok {
		writeToolError(w, http.StatusNotFound, "session not found")
		return
	}
	var req spawnSubagentToolRequest
	if ok := decodeJSON(w, r, &req, "invalid json"); !ok {
		return
	}
	isolation, err := validateSubagentIsolation(req.Mode)
	if err != nil {
		writeToolError(w, http.StatusBadRequest, err.Error())
		return
	}
	runtime, err := subagentRuntimeForIsolation(a, isolation)
	if err != nil {
		writeToolError(w, http.StatusConflict, err.Error())
		return
	}
	mode, specs, err := validateSpawnSubagentRequest(req)
	if err != nil {
		writeToolError(w, http.StatusBadRequest, err.Error())
		return
	}
	if mode == "disposition" && isolation != "draft" {
		writeToolError(w, http.StatusBadRequest, "Draft disposition requires mode=draft")
		return
	}
	depth := subagentDepthFromActor(req.Actor)
	if isolation == "draft" && depth != 0 {
		writeToolError(w, http.StatusForbidden, "Draft subagents may be started only by the top-level supervised Pi")
		return
	}
	if depth >= runtime.MaxDepth {
		writeToolError(w, http.StatusForbidden, fmt.Sprintf("subagent recursion depth %d exceeds max %d", depth+1, runtime.MaxDepth))
		return
	}
	timeout, err := a.subagentExecutionTimeout(s, req.TimeoutMS)
	if err != nil {
		writeToolError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ResultArtifactThresholdBytes < 0 || req.ResultArtifactThresholdBytes > maxSubagentTextBytes {
		writeToolError(w, http.StatusBadRequest, fmt.Sprintf("result_artifact_threshold_bytes must be between 0 and %d", maxSubagentTextBytes))
		return
	}
	activity, err := s.BeginWorkspaceActivity()
	if err != nil {
		writeToolDomainError(w, http.StatusConflict, toolErrorConflict, err.Error(), "", err)
		return
	}
	defer activity.Release()
	requestID := strings.TrimSpace(req.RequestID)
	if requestID == "" {
		requestID = "subagent-request-" + uuid.NewString()
	}
	if !validSubagentRequestID(requestID) {
		writeToolError(w, http.StatusBadRequest, "invalid subagent request_id")
		return
	}
	var flusher http.Flusher
	if req.Stream {
		var ok bool
		flusher, ok = w.(http.Flusher)
		if !ok {
			writeToolError(w, http.StatusInternalServerError, "streaming unsupported by response writer")
			return
		}
	}
	ctx, explicitCancel, cleanupContext := a.newSubagentRequestContext(r.Context(), timeout)
	if err := a.registerSubagentCancellation(sessionID, requestID, explicitCancel); err != nil {
		cleanupContext()
		writeToolError(w, http.StatusConflict, err.Error())
		return
	}
	defer func() {
		a.unregisterSubagentCancellation(sessionID, requestID)
		cleanupContext()
	}()
	if err := a.beginDetachedSubagentOperation(requestID, detachedOperationSpawnSubagent, ""); err != nil {
		writeToolError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	a.emitToolEvent(r.Context(), sessionID, "tool_spawn_subagent_start", "spawn_subagent", "", req.Actor, map[string]any{
		"request_id": requestID,
		"mode":       mode,
		"isolation":  isolation,
		"tasks":      len(specs),
		"runtime":    runtime.Name,
		"timeout_ms": timeout.Milliseconds(),
	})
	started := time.Now()
	var stream *subagentStreamer
	if req.Stream {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		stream = newSubagentStreamer(w, flusher)
	}

	var result spawnSubagentResult
	result.RequestID = requestID
	var code int
	var runErr error
	terminalPersistenceAttempted := false
	if stream != nil {
		defer func() {
			if recover() != nil {
				runErr = errors.New("subagent request failed unexpectedly")
				if result.Mode == "" {
					result.Mode = mode
				}
				if result.Final == "" {
					result.Final = runErr.Error()
				}
				result.Terminal = failedSubagentTerminal(subagentFailureUnknown, 1, "", subagentTerminationNatural, true, runErr.Error())
			}
			if result.Terminal.State == "" {
				result.Terminal = aggregateSubagentTerminal(result.Results, runErr)
			}
			result.RequestID = requestID
			result.Summary = result.Final
			if !terminalPersistenceAttempted {
				terminalPersistenceAttempted = true
				if persistErr := a.persistSubagentTerminalEvent(sessionID, "tool_spawn_subagent_end", requestID, "", result.Terminal, map[string]any{
					"mode": mode, "tasks": len(specs), "runtime": runtime.Name,
					"duration_ms": time.Since(started).Milliseconds(), "error": sanitizeSubagentDiagnostic(errString(runErr)),
				}); persistErr != nil {
					runErr = errors.Join(runErr, persistErr)
				}
			}
			protocolOK := runErr == nil || len(result.Results) > 0
			_ = stream.Done(map[string]any{"ok": protocolOK, "result": result, "error": errString(runErr)})
		}()
	}
	if stream != nil {
		if emitErr := stream.Emit("subagent_start", map[string]any{"request_id": requestID, "mode": mode, "tasks": len(specs), "runtime": runtime.Name, "timeout_ms": timeout.Milliseconds()}); emitErr != nil {
			runErr = errors.New("subagent stream is not writable")
			code = http.StatusInternalServerError
			result = spawnSubagentResult{RequestID: requestID, Mode: mode, Final: runErr.Error(), Terminal: failedSubagentTerminal(subagentFailureTransport, 1, "", subagentTerminationNatural, true, runErr.Error())}
		} else {
			result, code, runErr = a.runSubagentModeSafely(ctx, s, runtime, requestID, mode, specs, req.Actor, req.ResultArtifactThresholdBytes, stream)
		}
	} else {
		result, code, runErr = a.runSubagentModeSafely(ctx, s, runtime, requestID, mode, specs, req.Actor, req.ResultArtifactThresholdBytes, nil)
	}
	result.RequestID = requestID
	if result.Terminal.State == "" {
		result.Terminal = aggregateSubagentTerminal(result.Results, runErr)
	}
	result.Summary = result.Final
	status := code
	if status == 0 {
		status = http.StatusOK
	}
	terminalPersistenceAttempted = true
	terminalPersistErr := a.persistSubagentTerminalEvent(sessionID, "tool_spawn_subagent_end", requestID, "", result.Terminal, map[string]any{
		"mode":        mode,
		"tasks":       len(specs),
		"runtime":     runtime.Name,
		"duration_ms": time.Since(started).Milliseconds(),
		"error":       sanitizeSubagentDiagnostic(errString(runErr)),
	})
	if terminalPersistErr != nil {
		runErr = errors.Join(runErr, terminalPersistErr)
		if status == http.StatusOK {
			status = http.StatusInternalServerError
		}
	}
	protocolOK := runErr == nil || (len(result.Results) > 0 && terminalPersistErr == nil)
	if stream != nil {
		return
	}
	if runErr != nil && len(result.Results) == 0 {
		writeToolError(w, status, runErr.Error())
		return
	}
	writeJSON(w, status, toolResponse{OK: protocolOK, Result: result, Error: errString(runErr)})
}

func validateSubagentIsolation(value string) (string, error) {
	switch isolation := strings.ToLower(strings.TrimSpace(value)); isolation {
	case "", "shared":
		return "shared", nil
	case "draft":
		return "draft", nil
	default:
		return "", fmt.Errorf("unsupported subagent mode %q; use shared or draft", value)
	}
}

func subagentRuntimeForIsolation(a *App, isolation string) (subagentRuntimeConfig, error) {
	if isolation != "draft" {
		return subagentRuntimeFromEnv(a)
	}
	command := strings.TrimSpace(os.Getenv("AGENTSH_DRAFT_SUBAGENT_COMMAND"))
	if command == "" {
		return subagentRuntimeConfig{}, errors.New("AgentSH Draft subagent runtime is not configured")
	}
	if !filepath.IsAbs(command) || filepath.Clean(command) != command {
		return subagentRuntimeConfig{}, errors.New("AGENTSH_DRAFT_SUBAGENT_COMMAND must be a clean absolute path")
	}
	if st, err := os.Stat(command); err != nil {
		return subagentRuntimeConfig{}, fmt.Errorf("AGENTSH_DRAFT_SUBAGENT_COMMAND is not usable: %w", err)
	} else if !st.Mode().IsRegular() {
		return subagentRuntimeConfig{}, errors.New("AGENTSH_DRAFT_SUBAGENT_COMMAND is not a regular file")
	}
	args, err := splitCommandArgs(os.Getenv("AGENTSH_DRAFT_SUBAGENT_ARGS"))
	if err != nil {
		return subagentRuntimeConfig{}, fmt.Errorf("parse AGENTSH_DRAFT_SUBAGENT_ARGS: %w", err)
	}
	socketURL := strings.TrimSpace(os.Getenv("AGENTSH_SESSION_SUPERVISOR"))
	if socketURL == "" && a != nil && a.cfg != nil && a.cfg.Server.UnixSocket.Path != "" {
		socketURL = "unix://" + a.cfg.Server.UnixSocket.Path
	}
	return subagentRuntimeConfig{
		Name: "pi-auto-draft", Isolation: "draft", Command: command, Args: args,
		TaskMode: "json-stdin", Protocol: "text", MaxDepth: 1, SocketURL: socketURL,
	}, nil
}

func subagentRuntimeFromEnv(a *App) (subagentRuntimeConfig, error) {
	command := strings.TrimSpace(os.Getenv("AGENTSH_SUBAGENT_COMMAND"))
	if command == "" {
		return subagentRuntimeConfig{}, errors.New("AgentSH subagent runtime is not configured; set AGENTSH_SUBAGENT_COMMAND")
	}
	if st, err := os.Stat(command); err != nil {
		return subagentRuntimeConfig{}, fmt.Errorf("AGENTSH_SUBAGENT_COMMAND is not usable: %w", err)
	} else if st.IsDir() {
		return subagentRuntimeConfig{}, errors.New("AGENTSH_SUBAGENT_COMMAND points to a directory")
	}
	args, err := splitCommandArgs(os.Getenv("AGENTSH_SUBAGENT_ARGS"))
	if err != nil {
		return subagentRuntimeConfig{}, fmt.Errorf("parse AGENTSH_SUBAGENT_ARGS: %w", err)
	}
	taskMode := strings.ToLower(strings.TrimSpace(os.Getenv("AGENTSH_SUBAGENT_TASK_MODE")))
	if taskMode == "" {
		taskMode = "arg"
	}
	switch taskMode {
	case "arg", "stdin", "env", "json-stdin":
	default:
		return subagentRuntimeConfig{}, fmt.Errorf("unsupported AGENTSH_SUBAGENT_TASK_MODE %q", taskMode)
	}
	protocol := strings.ToLower(strings.TrimSpace(os.Getenv("AGENTSH_SUBAGENT_PROTOCOL")))
	if protocol == "" {
		protocol = "text"
	}
	switch protocol {
	case "text", "pi-json":
	default:
		return subagentRuntimeConfig{}, fmt.Errorf("unsupported AGENTSH_SUBAGENT_PROTOCOL %q", protocol)
	}
	maxDepth := 1
	if raw := strings.TrimSpace(os.Getenv("AGENTSH_SUBAGENT_MAX_DEPTH")); raw != "" {
		parsed, parseErr := strconv.Atoi(raw)
		if parseErr != nil || parsed < 0 {
			return subagentRuntimeConfig{}, fmt.Errorf("invalid AGENTSH_SUBAGENT_MAX_DEPTH %q", raw)
		}
		maxDepth = parsed
	}
	socketURL := strings.TrimSpace(os.Getenv("AGENTSH_SESSION_SUPERVISOR"))
	if socketURL == "" && a != nil && a.cfg != nil && a.cfg.Server.UnixSocket.Path != "" {
		socketURL = "unix://" + a.cfg.Server.UnixSocket.Path
	}
	name := strings.TrimSpace(os.Getenv("AGENTSH_SUBAGENT_RUNTIME"))
	if name == "" {
		name = filepath.Base(command)
	}
	return subagentRuntimeConfig{Name: name, Isolation: "shared", Command: command, Args: args, TaskMode: taskMode, Protocol: protocol, MaxDepth: maxDepth, SocketURL: socketURL}, nil
}

func subagentDepthFromActor(actor piToolActor) int {
	if actor == nil {
		return 0
	}
	value, ok := actor["subagent_depth"]
	if !ok {
		return 0
	}
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		parsed, _ := strconv.Atoi(v)
		return parsed
	default:
		return 0
	}
}

func validateSpawnSubagentRequest(req spawnSubagentToolRequest) (string, []subagentItemRequest, error) {
	hasSingle := strings.TrimSpace(req.Task) != ""
	hasTasks := len(req.Tasks) > 0
	hasChain := len(req.Chain) > 0
	hasDisposition := strings.TrimSpace(req.Action) != "" || strings.TrimSpace(req.DraftID) != ""
	count := 0
	if hasSingle {
		count++
	}
	if hasTasks {
		count++
	}
	if hasChain {
		count++
	}
	if hasDisposition {
		count++
	}
	if count != 1 {
		return "", nil, errors.New("provide exactly one mode: task, non-empty tasks, non-empty chain, or Draft disposition")
	}
	if hasDisposition {
		action := strings.TrimSpace(req.Action)
		switch action {
		case "review", "apply", "discard":
		default:
			return "", nil, errors.New("Draft disposition action must be review, apply, or discard")
		}
		draftID := strings.TrimSpace(req.DraftID)
		if !strings.HasPrefix(draftID, "session-") {
			return "", nil, errors.New("Draft disposition requires an exact draft_id")
		}
		if _, err := uuid.Parse(strings.TrimPrefix(draftID, "session-")); err != nil {
			return "", nil, errors.New("Draft disposition requires an exact draft_id")
		}
		item := subagentItemRequest{Task: fmt.Sprintf("%s Draft %s", action, draftID), Action: action, DraftID: draftID}
		return "disposition", []subagentItemRequest{item}, nil
	}
	if hasSingle {
		item := subagentItemRequest{Task: req.Task, SystemPrompt: req.SystemPrompt, Model: req.Model, Tools: req.Tools, Cwd: req.Cwd}
		return "single", []subagentItemRequest{item}, validateSubagentItem(item)
	}
	items := req.Tasks
	mode := "parallel"
	if hasChain {
		items = req.Chain
		mode = "chain"
	}
	items = inheritSubagentRequestCwd(items, req.Cwd)
	if mode == "parallel" && len(items) > maxSubagentParallelTasks {
		return "", nil, fmt.Errorf("too many parallel tasks (%d), max is %d", len(items), maxSubagentParallelTasks)
	}
	for _, item := range items {
		if err := validateSubagentItem(item); err != nil {
			return "", nil, err
		}
	}
	return mode, items, nil
}

func inheritSubagentRequestCwd(items []subagentItemRequest, requestCwd string) []subagentItemRequest {
	inherited := make([]subagentItemRequest, len(items))
	copy(inherited, items)
	for i := range inherited {
		itemCwd := strings.TrimSpace(inherited[i].Cwd)
		if itemCwd == "" {
			inherited[i].Cwd = requestCwd
			continue
		}
		if requestCwd != "" && !strings.HasPrefix(itemCwd, "/") && !filepath.IsAbs(itemCwd) {
			inherited[i].Cwd = filepath.ToSlash(filepath.Clean(filepath.Join(filepath.FromSlash(requestCwd), filepath.FromSlash(itemCwd))))
		}
	}
	return inherited
}

func validateSubagentItem(item subagentItemRequest) error {
	if strings.TrimSpace(item.Task) == "" {
		return errors.New("subagent task is required")
	}
	if len(item.Task) > 64*1024 {
		return errors.New("subagent task is too large")
	}
	if len(item.SystemPrompt) > 64*1024 {
		return errors.New("subagent systemPrompt is too large")
	}
	return nil
}

func (a *App) runSubagentModeSafely(ctx context.Context, s *session.Session, runtime subagentRuntimeConfig, requestID, mode string, specs []subagentItemRequest, actor piToolActor, artifactThresholdBytes int64, stream *subagentStreamer) (result spawnSubagentResult, code int, err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("subagent runtime failed unexpectedly")
			code = http.StatusInternalServerError
			result = spawnSubagentResult{
				RequestID: requestID,
				Mode:      mode,
				Final:     err.Error(),
				Terminal:  failedSubagentTerminal(subagentFailureUnknown, 1, "", subagentTerminationNatural, true, err.Error()),
			}
		}
	}()
	return a.runSubagentMode(ctx, s, runtime, requestID, mode, specs, actor, artifactThresholdBytes, stream)
}

func (a *App) runSubagentMode(ctx context.Context, s *session.Session, runtime subagentRuntimeConfig, requestID, mode string, specs []subagentItemRequest, actor piToolActor, artifactThresholdBytes int64, stream *subagentStreamer) (spawnSubagentResult, int, error) {
	switch mode {
	case "single", "disposition":
		res := a.runSingleSubagent(ctx, s, runtime, requestID, specs[0], "subagent", 0, mode, len(specs), actor, artifactThresholdBytes, stream)
		if stream != nil {
			_ = stream.Emit("subagent_result", map[string]any{"label": res.Label, "result": res})
		}
		out := spawnSubagentResult{RequestID: requestID, Mode: mode, Final: res.Final, Terminal: res.Terminal, Results: []subagentResult{res}}
		if subagentResultFailed(res) {
			return out, http.StatusOK, errors.New(resultErrorSummary(res))
		}
		return out, http.StatusOK, nil
	case "chain":
		results := make([]subagentResult, 0, len(specs))
		previous := ""
		for i, spec := range specs {
			spec.Task = strings.ReplaceAll(spec.Task, "{previous}", previous)
			res := a.runSingleSubagent(ctx, s, runtime, requestID, spec, fmt.Sprintf("step %d", i+1), i+1, mode, len(specs), actor, artifactThresholdBytes, stream)
			if stream != nil {
				_ = stream.Emit("subagent_result", map[string]any{"label": res.Label, "step": i + 1, "result": res})
			}
			results = append(results, res)
			if subagentResultFailed(res) {
				return spawnSubagentResult{RequestID: requestID, Mode: mode, Final: resultErrorSummary(res), Terminal: res.Terminal, Results: results}, http.StatusOK, errors.New(resultErrorSummary(res))
			}
			previous = res.Final
		}
		final := ""
		if len(results) > 0 {
			final = results[len(results)-1].Final
		}
		return spawnSubagentResult{RequestID: requestID, Mode: mode, Final: final, Terminal: aggregateSubagentTerminal(results, nil), Results: results}, http.StatusOK, nil
	case "parallel":
		results := make([]subagentResult, len(specs))
		concurrency := maxSubagentConcurrency
		if runtime.Isolation == "draft" {
			concurrency = maxDraftSubagentConcurrency
		}
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup
		for i, spec := range specs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				label := fmt.Sprintf("task %d", i+1)
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
					results[i] = a.runSingleSubagent(ctx, s, runtime, requestID, spec, label, 0, mode, len(specs), actor, artifactThresholdBytes, stream)
				case <-ctx.Done():
					results[i] = subagentResult{Label: label, Task: spec.Task, Model: spec.Model, Tools: spec.Tools, Runtime: runtime.Name, Command: runtime.Command}
					setSubagentTerminal(&results[i], cancelledSubagentTerminal(ctx, subagentCancellationExitCode(ctx), "", subagentTerminationNatural, false))
				}
				if stream != nil {
					_ = stream.Emit("subagent_result", map[string]any{"label": results[i].Label, "index": i, "result": results[i]})
				}
			}()
		}
		wg.Wait()
		parts := make([]string, 0, len(results))
		var failed []string
		for _, res := range results {
			if subagentResultFailed(res) {
				failed = append(failed, resultErrorSummary(res))
			}
			preview := res.Final
			if preview == "" {
				preview = resultErrorSummary(res)
			}
			parts = append(parts, fmt.Sprintf("[%s] %s", res.Label, truncateString(preview, 500)))
		}
		final := strings.Join(parts, "\n\n")
		out := spawnSubagentResult{RequestID: requestID, Mode: mode, Final: final, Terminal: aggregateSubagentTerminal(results, nil), Results: results}
		if len(failed) > 0 {
			return out, http.StatusOK, fmt.Errorf("%d/%d subagents failed: %s", len(failed), len(results), strings.Join(failed, "; "))
		}
		return out, http.StatusOK, nil
	default:
		err := fmt.Errorf("unsupported subagent mode %q", mode)
		return spawnSubagentResult{RequestID: requestID, Mode: mode, Final: err.Error(), Terminal: failedSubagentTerminal(subagentFailureConfiguration, 1, "", subagentTerminationNatural, false, err.Error())}, http.StatusBadRequest, err
	}
}

func (a *App) runSingleSubagent(ctx context.Context, s *session.Session, runtime subagentRuntimeConfig, requestID string, spec subagentItemRequest, label string, step int, invocationMode string, taskCount int, actor piToolActor, artifactThresholdBytes int64, stream *subagentStreamer) (res subagentResult) {
	started := time.Now()
	subagentID := "subagent-" + uuid.NewString()
	res = subagentResult{SubagentID: subagentID, Label: label, Task: spec.Task, Model: spec.Model, Tools: spec.Tools, Runtime: runtime.Name, Command: runtime.Command}
	if err := a.beginDetachedSubagentOperation(subagentID, detachedOperationSpawnSubagentChild, requestID); err != nil {
		res.Error = err.Error()
		setSubagentTerminal(&res, failedSubagentTerminal(subagentFailureProcess, 1, "", subagentTerminationNatural, false, err.Error()))
		res.DurationMS = time.Since(started).Milliseconds()
		return res
	}
	defer func() {
		if res.DurationMS == 0 {
			res.DurationMS = time.Since(started).Milliseconds()
		}
		if res.Terminal.State == "" {
			message := "subagent ended without terminal evidence"
			res.Error = message
			setSubagentTerminal(&res, failedSubagentTerminal(subagentFailureUnknown, 1, "", subagentTerminationNatural, false, message))
		}
		if persistErr := a.persistSubagentTerminalEvent(s.ID, "subagent_terminal", subagentID, requestID, res.Terminal, map[string]any{
			"label": res.Label, "duration_ms": res.DurationMS, "protocol_settled": res.ProtocolSettled,
		}); persistErr != nil {
			if res.Error == "" {
				res.Error = persistErr.Error()
			} else {
				res.Error = errors.Join(errors.New(res.Error), persistErr).Error()
			}
			res.Error = sanitizeSubagentDiagnostic(res.Error)
			terminal := failedSubagentTerminal(subagentFailureTransport, res.ExitCode, res.Terminal.Signal, res.Terminal.Termination, false, res.Error)
			terminal.SideEffectsMayHaveOccurred = res.Terminal.SideEffectsMayHaveOccurred
			setSubagentTerminal(&res, terminal)
		}
	}()
	cwd, virtualCwd, err := a.resolveSubagentCwd(ctx, s, spec.Cwd, actor)
	res.Cwd = virtualCwd
	if err != nil {
		res.Error = err.Error()
		setSubagentTerminal(&res, failedSubagentTerminal(subagentFailureConfiguration, 1, "", subagentTerminationNatural, false, err.Error()))
		res.DurationMS = time.Since(started).Milliseconds()
		return res
	}
	if stream != nil {
		_ = stream.Emit("subagent_child_start", map[string]any{"label": label, "subagent_id": subagentID, "task": spec.Task, "cwd": virtualCwd, "model": spec.Model, "tools": spec.Tools})
	}

	childAgentDir, childSessionDir, err := prepareSubagentPiDirs(s, subagentID)
	if err != nil {
		res.Error = err.Error()
		setSubagentTerminal(&res, failedSubagentTerminal(subagentFailureConfiguration, 1, "", subagentTerminationNatural, false, err.Error()))
		res.DurationMS = time.Since(started).Milliseconds()
		return res
	}

	var promptFile string
	var promptDir string
	if strings.TrimSpace(spec.SystemPrompt) != "" && runtime.Protocol == "pi-json" {
		promptFile, promptDir, err = writeSubagentSystemPrompt(s, subagentID, spec.SystemPrompt)
		if err != nil {
			res.Error = err.Error()
			setSubagentTerminal(&res, failedSubagentTerminal(subagentFailureConfiguration, 1, "", subagentTerminationNatural, false, err.Error()))
			res.DurationMS = time.Since(started).Milliseconds()
			return res
		}
		defer os.RemoveAll(promptDir)
	}

	capability, err := a.mintChildCapability(s.ID, subagentID)
	if err != nil {
		res.Error = err.Error()
		setSubagentTerminal(&res, failedSubagentTerminal(subagentFailureProcess, 1, "", subagentTerminationNatural, false, err.Error()))
		res.DurationMS = time.Since(started).Milliseconds()
		return res
	}
	defer a.revokeChildCapability(capability, errChildCapabilityRevoked)

	args := append([]string{}, runtime.Args...)
	stdin := ""
	env := sanitizedSubagentEnv(os.Environ())
	childDepth := subagentDepthFromActor(actor) + 1
	childEnv := map[string]string{
		"AGENTSH_SESSION_ID":          s.ID,
		"AGENTSH_SUBAGENT_ID":         subagentID,
		"AGENTSH_SUBAGENT_REQUEST_ID": requestID,
		"AGENTSH_SUBAGENT_MODE":       invocationMode,
		"AGENTSH_SUBAGENT_STEP":       strconv.Itoa(step),
		"AGENTSH_SUBAGENT_TASK_COUNT": strconv.Itoa(taskCount),
		"AGENTSH_SUBAGENT_ISOLATION":  runtime.Isolation,
		"AGENTSH_SUBAGENT_DEPTH":      strconv.Itoa(childDepth),
		"AGENTSH_SUBAGENT_CWD":        virtualCwd,
		"AGENTSH_SUBAGENT_MODEL":      spec.Model,
		"AGENTSH_SUBAGENT_TOOLS":      strings.Join(spec.Tools, ","),
		childCapabilityEnv:            capability.token,
		"PI_CODING_AGENT_DIR":         childAgentDir,
		"PI_CODING_AGENT_SESSION_DIR": childSessionDir,
	}
	if runtime.Isolation == "draft" {
		// The detached supervisor scrubs helper coordinates from its ambient
		// environment after startup. A fixed operator-owned Draft worker still
		// needs the exact protected paths so its nested pi-auto lifecycle can use
		// the already-authenticated helper without sudo. Never expose these paths
		// to ordinary shared/model-selected child runtimes.
		binding := a.nethelperBinding.snapshot()
		if binding.SocketPath != "" && binding.CredentialFile != "" {
			childEnv["AGENTSH_NETHELPER_SOCKET"] = binding.SocketPath
			childEnv["AGENTSH_NETHELPER_CREDENTIAL_FILE"] = binding.CredentialFile
			if binding.BootstrapResultPath != "" {
				childEnv["AGENTSH_NETHELPER_BOOTSTRAP_RESULT"] = binding.BootstrapResultPath
			}
		}
	}
	if deadline, ok := ctx.Deadline(); ok {
		childEnv[subagentDeadlineEpochMSEnvironment] = strconv.FormatInt(deadline.UnixMilli(), 10)
	}
	env = withEnvOverrides(env, childEnv)
	if home := s.ProcessHomePath(); home != "" {
		overrides := map[string]string{"HOME": home}
		if s.RuntimeHomeModeValue() == "isolated" {
			overrides["XDG_CACHE_HOME"] = filepath.Join(home, ".cache")
			overrides["XDG_DATA_HOME"] = filepath.Join(home, ".local", "share")
			overrides["XDG_STATE_HOME"] = filepath.Join(home, ".local", "state")
			overrides["XDG_CONFIG_HOME"] = filepath.Join(home, ".config")
		}
		env = withEnvOverrides(env, overrides)
	}
	if s.RuntimeTmp != "" {
		env = withEnvOverrides(env, map[string]string{"TMPDIR": s.RuntimeTmp, "TEMP": s.RuntimeTmp, "TMP": s.RuntimeTmp})
	}
	if runtime.SocketURL != "" {
		env = withEnvOverrides(env, map[string]string{"AGENTSH_SESSION_SUPERVISOR": runtime.SocketURL})
	}
	switch runtime.TaskMode {
	case "arg":
		args = appendSubagentTaskArgs(args, spec, runtime.Protocol, promptFile)
	case "stdin":
		stdin = spec.Task
	case "env":
		env = withEnvOverrides(env, map[string]string{"AGENTSH_SUBAGENT_TASK": spec.Task})
	case "json-stdin":
		payload, _ := json.Marshal(map[string]any{"task": spec.Task, "action": spec.Action, "draft_id": spec.DraftID, "systemPrompt": spec.SystemPrompt, "model": spec.Model, "tools": spec.Tools, "cwd": virtualCwd, "actor": map[string]any(actor)})
		stdin = string(payload)
	}
	res.Args = args
	cmd := exec.Command(runtime.Command, args...)
	cmd.Dir = cwd
	cmd.Env = env
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr cappedBuffer
	stdout.limit = maxSubagentTextBytes
	stderr.limit = maxSubagentTextBytes
	var protocolReducer *piProtocolReducer
	var protocolWriter io.Writer
	if runtime.Protocol == "pi-json" {
		protocolReducer = newPiProtocolReducer()
		protocolWriter = protocolReducer
	}
	cmd.Stdout = subagentOutputWriter(&stdout, protocolWriter, stream, subagentID, label, "stdout")
	cmd.Stderr = subagentOutputWriter(&stderr, nil, stream, subagentID, label, "stderr")
	process := runOwnedSubagentProcessWithStart(ctx, cmd, subagentTerminationGracePeriod, func(pid, processGroupID int) error {
		// Durable process evidence must exist before the capability becomes
		// usable. A child that reaches the supervisor early waits on capability
		// activation and can never race an unjournaled command into execution.
		if err := a.markDetachedSubagentProcess(subagentID, pid, processGroupID); err != nil {
			return err
		}
		return a.activateChildCapability(capability, pid, processGroupID)
	})
	stderrText := stderr.String()
	if stream == nil {
		res.Stdout = stdout.String()
		res.Stderr = stderrText
	}
	res.StdoutTruncated = stdout.truncated
	res.StdoutTotalBytes = stdout.total
	res.StderrTruncated = stderr.truncated
	res.StderrTotalBytes = stderr.total
	res.DurationMS = time.Since(started).Milliseconds()
	var protocolOutcome subagentProtocolOutcome
	if protocolReducer != nil {
		protocolOutcome = protocolReducer.outcome()
	} else {
		protocolOutcome = parseSubagentProtocolOutcome(runtime.Protocol, stdout.String())
	}
	res.Final = protocolOutcome.Final
	if runtime.Isolation == "draft" && process.RunError == nil {
		if err := applyDraftWorkerOutput(&res, protocolOutcome.Final); err != nil {
			res.Error = err.Error()
			terminal := failedSubagentTerminal(subagentFailureProtocol, 1, process.Signal, process.Termination, false, res.Error)
			terminal.SideEffectsMayHaveOccurred = process.Started
			setSubagentTerminal(&res, terminal)
			return res
		}
	}
	res.ModelStopReason = protocolOutcome.StopReason
	res.ProtocolSettled = protocolOutcome.Settled
	res.ProtocolDiagnostics = protocolOutcome.Diagnostics

	if ctx.Err() != nil {
		setSubagentTerminal(&res, cancelledSubagentTerminal(ctx, subagentCancellationExitCode(ctx), process.Signal, process.Termination, process.Started))
		return res
	}
	if process.RunError != nil {
		res.Error = process.RunError.Error()
		kind := subagentFailureProcess
		retryable := !process.Started
		var execErr *exec.Error
		if errors.As(process.RunError, &execErr) {
			kind = subagentFailureConfiguration
			retryable = false
		} else if likelySubagentAuthFailure(res.Error, stderrText) {
			kind = subagentFailureAuth
			retryable = false
		} else if protocolOutcome.Failed() {
			kind = protocolOutcome.FailureKind
			retryable = !process.Started && (kind == subagentFailureProtocol || kind == subagentFailureCompaction)
			if protocolOutcome.ErrorMessage != "" {
				res.Error = protocolOutcome.ErrorMessage
			}
		}
		terminal := failedSubagentTerminal(kind, exitCode(process.RunError), process.Signal, process.Termination, retryable, res.Error)
		terminal.SideEffectsMayHaveOccurred = process.Started
		setSubagentTerminal(&res, terminal)
		if res.Final == "" {
			res.Final = resultErrorSummary(res)
		}
		return res
	}
	if protocolOutcome.Failed() {
		res.Error = protocolOutcome.ErrorMessage
		retryable := !process.Started && (protocolOutcome.FailureKind == subagentFailureProtocol || protocolOutcome.FailureKind == subagentFailureCompaction)
		terminal := failedSubagentTerminal(protocolOutcome.FailureKind, 1, process.Signal, process.Termination, retryable, res.Error)
		terminal.SideEffectsMayHaveOccurred = process.Started
		setSubagentTerminal(&res, terminal)
		return res
	}
	if !protocolOutcome.Completed {
		res.Error = "subagent output protocol did not reach completion"
		terminal := failedSubagentTerminal(subagentFailureProtocol, 1, process.Signal, process.Termination, !process.Started, res.Error)
		terminal.SideEffectsMayHaveOccurred = process.Started
		setSubagentTerminal(&res, terminal)
		return res
	}
	setSubagentTerminal(&res, completedSubagentTerminal(0, process.Termination))
	a.persistSubagentFinalArtifact(s, &res, runtime.Protocol, artifactThresholdBytes)
	return res
}

type draftWorkerOutput struct {
	SchemaVersion int    `json:"schema_version"`
	DraftID       string `json:"draft_id"`
	Status        string `json:"status"`
	Final         string `json:"final"`
	Summary       string `json:"summary"`
	Step          int    `json:"step"`
	TaskCount     int    `json:"task_count"`
	Sealed        bool   `json:"sealed"`
}

func applyDraftWorkerOutput(result *subagentResult, raw string) error {
	var output draftWorkerOutput
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&output); err != nil {
		return fmt.Errorf("decode Draft worker result: %w", err)
	}
	if output.SchemaVersion != 1 || !strings.HasPrefix(output.DraftID, "session-") || output.TaskCount < 1 || output.Step < 0 || output.Step > output.TaskCount {
		return errors.New("Draft worker returned invalid lifecycle identity")
	}
	if _, err := uuid.Parse(strings.TrimPrefix(output.DraftID, "session-")); err != nil {
		return errors.New("Draft worker returned invalid session identity")
	}
	if output.Status != "completed" {
		return fmt.Errorf("Draft worker returned status %q", output.Status)
	}
	result.DraftID = output.DraftID
	result.DraftStatus = output.Status
	result.DraftSummary = output.Summary
	result.DraftSealed = output.Sealed
	result.Final = strings.TrimSpace(output.Final)
	if result.Final == "" {
		result.Final = "Draft subagent completed without a textual response."
	}
	if output.Sealed {
		result.Final += "\n\nDraft: " + output.DraftID
		if summary := strings.TrimSpace(output.Summary); summary != "" {
			result.Final += "\n\n" + summary
		}
	}
	return nil
}

func appendSubagentTaskArgs(args []string, spec subagentItemRequest, protocol string, promptFile string) []string {
	if protocol == "pi-json" {
		if strings.TrimSpace(spec.Model) != "" {
			args = append(args, "--model", spec.Model)
		}
		if len(spec.Tools) > 0 {
			args = append(args, "--tools", strings.Join(spec.Tools, ","))
		}
		if promptFile != "" {
			args = append(args, "--append-system-prompt", promptFile)
		}
	}
	return append(args, spec.Task)
}

func (a *App) resolveSubagentCwd(ctx context.Context, s *session.Session, reqCwd string, actor piToolActor) (real string, virtual string, err error) {
	rp, err := resolveToolPath(s, ".", reqCwd)
	if err != nil {
		return "", "", err
	}
	resolved, err := filepath.EvalSymlinks(rp.Real)
	if err != nil {
		return "", "", fmt.Errorf("resolve subagent cwd: %w", err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", "", err
	}
	root := filepath.Clean(s.WorkspaceMountPath())
	resolvedRoot, rootErr := filepath.EvalSymlinks(root)
	if rootErr != nil {
		return "", "", fmt.Errorf("resolve session workspace: %w", rootErr)
	}
	if session.IsRealPathUnder(resolved, resolvedRoot) {
		info, statErr := os.Stat(resolved)
		if statErr != nil {
			return "", "", statErr
		}
		if !info.IsDir() {
			return "", "", errors.New("subagent cwd is not a directory")
		}
		return resolved, rp.Virtual, nil
	}
	if s.WorkspaceMode != string(types.WorkspaceModeDirect) {
		return "", "", errors.New("subagent cwd is outside the isolated session workspace")
	}
	if _, policyErr := a.enforceToolFilePolicy(ctx, s, "read", resolved, actor); policyErr != nil {
		return "", "", fmt.Errorf("subagent cwd is not authorized by the session file policy: %w", policyErr)
	}
	info, statErr := os.Stat(resolved)
	if statErr != nil {
		return "", "", statErr
	}
	if !info.IsDir() {
		return "", "", errors.New("subagent cwd is not a directory")
	}
	return resolved, filepath.ToSlash(resolved), nil
}

func sanitizedSubagentEnv(in []string) []string {
	blocked := map[string]bool{
		childCapabilityEnv:          true,
		"AGENTSH_API_KEY":           true,
		"AGENTSH_APPROVER_KEY":      true,
		"AGENTSH_APPROVER_API_KEY":  true,
		"AGENTSH_APPROVER_KEY_FILE": true,
		"AGENTSH_ADMIN_TOKEN":       true,
		"AGENTSH_TOKEN":             true,
	}
	out := make([]string, 0, len(in))
	for _, item := range in {
		key := item
		if idx := strings.IndexByte(item, '='); idx >= 0 {
			key = item[:idx]
		}
		if blocked[key] {
			continue
		}
		out = append(out, item)
	}
	return out
}

func withEnvOverrides(in []string, overrides map[string]string) []string {
	if len(overrides) == 0 {
		return in
	}
	out := make([]string, 0, len(in)+len(overrides))
	for _, item := range in {
		key := item
		if idx := strings.IndexByte(item, '='); idx >= 0 {
			key = item[:idx]
		}
		if _, ok := overrides[key]; ok {
			continue
		}
		out = append(out, item)
	}
	for key, value := range overrides {
		out = append(out, key+"="+value)
	}
	return out
}

func subagentBaseAgentDir(s *session.Session) string {
	_, sessEnv, _ := s.GetCwdEnvHistory()
	if raw := strings.TrimSpace(sessEnv["PI_CODING_AGENT_DIR"]); raw != "" {
		return raw
	}
	if raw := strings.TrimSpace(os.Getenv("PI_CODING_AGENT_DIR")); raw != "" {
		return raw
	}
	if s.RuntimeHome != "" {
		return filepath.Join(s.RuntimeHome, "pi-agent")
	}
	return filepath.Join(os.TempDir(), "agentsh-pi-agent")
}

func prepareSubagentPiDirs(s *session.Session, subagentID string) (agentDir string, sessionDir string, err error) {
	base := filepath.Clean(subagentBaseAgentDir(s))
	if !filepath.IsAbs(base) {
		return "", "", errors.New("subagent Pi agent directory must be absolute")
	}
	info, statErr := os.Stat(base)
	if statErr != nil {
		return "", "", fmt.Errorf("inspect subagent Pi agent directory: %w", statErr)
	}
	if !info.IsDir() {
		return "", "", errors.New("subagent Pi agent directory is not a directory")
	}

	// Share the lifecycle-local config/auth root with trusted child Pi processes.
	// In particular, all Pi instances must address auth.json through the same
	// pathname so proper-lockfile serializes rotating OAuth refreshes. Session
	// state remains child-specific and --no-session prevents history persistence.
	childStateDir := filepath.Join(base, "subagents", subagentID)
	childSessionDir := filepath.Join(childStateDir, "sessions")
	if err := os.MkdirAll(childSessionDir, 0o700); err != nil {
		return "", "", fmt.Errorf("create subagent Pi state: %w", err)
	}
	_ = os.Chmod(childStateDir, 0o700)
	_ = os.Chmod(childSessionDir, 0o700)
	return base, childSessionDir, nil
}

func writeSubagentSystemPrompt(s *session.Session, subagentID, prompt string) (filePath string, dir string, err error) {
	root := s.RuntimeTmp
	if root == "" {
		root = os.TempDir()
	}
	dir, err = os.MkdirTemp(root, "agentsh-subagent-prompt-"+subagentID+"-")
	if err != nil {
		return "", "", fmt.Errorf("create subagent prompt dir: %w", err)
	}
	filePath = filepath.Join(dir, "system-prompt.md")
	if err := os.WriteFile(filePath, []byte(prompt), 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", "", fmt.Errorf("write subagent system prompt: %w", err)
	}
	return filePath, dir, nil
}

var errSubagentStreamTerminal = errors.New("subagent stream is already terminal")

type subagentStreamer struct {
	mu       sync.Mutex
	w        http.ResponseWriter
	flusher  http.Flusher
	terminal bool
	err      error
}

func newSubagentStreamer(w http.ResponseWriter, flusher http.Flusher) *subagentStreamer {
	return &subagentStreamer{w: w, flusher: flusher}
}

func (s *subagentStreamer) Emit(event string, fields map[string]any) error {
	return s.emit(event, fields, false)
}

func (s *subagentStreamer) Done(fields map[string]any) error {
	return s.emit("done", fields, true)
}

func (s *subagentStreamer) emit(event string, fields map[string]any, terminal bool) error {
	if s == nil {
		return nil
	}
	payload := make(map[string]any, len(fields)+1)
	payload["event"] = event
	for k, v := range fields {
		payload[k] = v
	}
	line, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if s.terminal {
		return errSubagentStreamTerminal
	}
	if terminal {
		s.terminal = true
	}
	if _, err := s.w.Write(append(line, '\n')); err != nil {
		s.err = err
		return err
	}
	s.flusher.Flush()
	return nil
}

func (s *subagentStreamer) Err() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

type subagentChunkWriter struct {
	stream     *subagentStreamer
	subagentID string
	label      string
	name       string
}

func subagentOutputWriter(buf *cappedBuffer, protocol io.Writer, stream *subagentStreamer, subagentID, label, name string) io.Writer {
	writers := []io.Writer{buf}
	if protocol != nil {
		writers = append(writers, protocol)
	}
	if stream != nil {
		writers = append(writers, subagentChunkWriter{stream: stream, subagentID: subagentID, label: label, name: name})
	}
	if len(writers) == 1 {
		return writers[0]
	}
	return io.MultiWriter(writers...)
}

func (w subagentChunkWriter) Write(p []byte) (int, error) {
	if len(p) > 0 {
		_ = w.stream.Emit(w.name, map[string]any{"subagent_id": w.subagentID, "label": w.label, "data": string(p)})
	}
	return len(p), nil
}

// cappedBuffer is a raw diagnostic ring. Protocol correctness must not depend
// on it: it retains the most recent bytes while the event-aware reducer keeps
// authoritative terminal state independently.
type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	total     int64
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	written := len(p)
	b.total += int64(written)
	if b.limit <= 0 || written == 0 {
		if written > 0 {
			b.truncated = true
		}
		return written, nil
	}
	if written >= b.limit {
		b.buf.Reset()
		_, _ = b.buf.Write(p[written-b.limit:])
		b.truncated = b.total > int64(b.limit)
		return written, nil
	}
	if overflow := b.buf.Len() + written - b.limit; overflow > 0 {
		b.buf.Next(overflow)
		b.truncated = true
	}
	_, _ = b.buf.Write(p)
	if b.total > int64(b.limit) {
		b.truncated = true
	}
	return written, nil
}
func (b *cappedBuffer) String() string {
	return b.buf.String()
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 1
}

func resultErrorSummary(res subagentResult) string {
	msg := res.Error
	if msg == "" {
		msg = res.Stderr
	}
	if msg == "" {
		msg = res.Final
	}
	if msg == "" {
		msg = fmt.Sprintf("subagent exited with code %d", res.ExitCode)
	}
	return fmt.Sprintf("%s %s: %s", res.Label, res.StopReason, truncateString(sanitizeSubagentDiagnostic(msg), 1000))
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + "…"
}

func splitCommandArgs(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var args []string
	var cur strings.Builder
	var quote rune
	escaped := false
	for _, r := range s {
		if escaped {
			cur.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == ' ' || r == '\t' || r == '\n' {
			if cur.Len() > 0 {
				args = append(args, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteRune(r)
	}
	if escaped {
		cur.WriteRune('\\')
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote")
	}
	if cur.Len() > 0 {
		args = append(args, cur.String())
	}
	return args, nil
}

var _ io.Writer = (*cappedBuffer)(nil)
