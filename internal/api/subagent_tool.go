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

	"github.com/agentsh/agentsh/internal/session"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const (
	maxSubagentParallelTasks = 8
	maxSubagentConcurrency   = 4
	maxSubagentTextBytes     = 2 * 1024 * 1024
	defaultSubagentTimeout   = 30 * time.Minute
)

type spawnSubagentToolRequest struct {
	Task         string                `json:"task,omitempty"`
	SystemPrompt string                `json:"systemPrompt,omitempty"`
	Model        string                `json:"model,omitempty"`
	Tools        []string              `json:"tools,omitempty"`
	Cwd          string                `json:"cwd,omitempty"`
	Tasks        []subagentItemRequest `json:"tasks,omitempty"`
	Chain        []subagentItemRequest `json:"chain,omitempty"`
	TimeoutMS    int64                 `json:"timeout_ms,omitempty"`
	Stream       bool                  `json:"stream,omitempty"`
	Actor        piToolActor           `json:"actor,omitempty"`
}

type subagentItemRequest struct {
	Task         string   `json:"task"`
	SystemPrompt string   `json:"systemPrompt,omitempty"`
	Model        string   `json:"model,omitempty"`
	Tools        []string `json:"tools,omitempty"`
	Cwd          string   `json:"cwd,omitempty"`
}

type subagentRuntimeConfig struct {
	Name      string
	Command   string
	Args      []string
	TaskMode  string
	Protocol  string
	MaxDepth  int
	SocketURL string
}

type subagentResult struct {
	Label      string           `json:"label"`
	Task       string           `json:"task"`
	ExitCode   int              `json:"exit_code"`
	StopReason string           `json:"stop_reason"`
	Terminal   subagentTerminal `json:"terminal"`
	Final      string           `json:"final"`
	Stdout     string           `json:"stdout,omitempty"`
	Stderr     string           `json:"stderr,omitempty"`
	DurationMS int64            `json:"duration_ms"`
	Model      string           `json:"model,omitempty"`
	Tools      []string         `json:"tools,omitempty"`
	Cwd        string           `json:"cwd,omitempty"`
	Runtime    string           `json:"runtime,omitempty"`
	Command    string           `json:"command,omitempty"`
	Args       []string         `json:"args,omitempty"`
	Error      string           `json:"error,omitempty"`
}

type spawnSubagentResult struct {
	Mode     string           `json:"mode"`
	Final    string           `json:"final"`
	Summary  string           `json:"summary"`
	Terminal subagentTerminal `json:"terminal"`
	Results  []subagentResult `json:"results"`
}

func (a *App) spawnSubagentTool(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	s, ok := a.sessions.Get(sessionID)
	if !ok {
		writeToolError(w, http.StatusNotFound, "session not found")
		return
	}
	var req spawnSubagentToolRequest
	if ok := decodeJSON(w, r, &req, "invalid json"); !ok {
		return
	}
	runtime, err := subagentRuntimeFromEnv(a)
	if err != nil {
		writeToolError(w, http.StatusConflict, err.Error())
		return
	}
	mode, specs, err := validateSpawnSubagentRequest(req)
	if err != nil {
		writeToolError(w, http.StatusBadRequest, err.Error())
		return
	}
	if depth := subagentDepthFromActor(req.Actor); depth >= runtime.MaxDepth {
		writeToolError(w, http.StatusForbidden, fmt.Sprintf("subagent recursion depth %d exceeds max %d", depth+1, runtime.MaxDepth))
		return
	}
	if req.TimeoutMS < 0 {
		writeToolError(w, http.StatusBadRequest, "timeout_ms must be non-negative")
		return
	}
	timeout := defaultSubagentTimeout
	if req.TimeoutMS > 0 {
		timeout = time.Duration(req.TimeoutMS) * time.Millisecond
	}
	ctx, cancel := context.WithTimeoutCause(r.Context(), timeout, errSubagentRequestTimeout)
	defer cancel()

	a.emitToolEvent(r.Context(), sessionID, "tool_spawn_subagent_start", "spawn_subagent", "", req.Actor, map[string]any{
		"mode":    mode,
		"tasks":   len(specs),
		"runtime": runtime.Name,
	})
	started := time.Now()
	var stream *subagentStreamer
	if req.Stream {
		flusher, ok := w.(http.Flusher)
		if !ok {
			writeToolError(w, http.StatusInternalServerError, "streaming unsupported by response writer")
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		stream = newSubagentStreamer(w, flusher)
	}

	var result spawnSubagentResult
	var code int
	var runErr error
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
			result.Summary = result.Final
			protocolOK := runErr == nil || len(result.Results) > 0
			_ = stream.Done(map[string]any{"ok": protocolOK, "result": result, "error": errString(runErr)})
		}()
	}
	if stream != nil {
		if emitErr := stream.Emit("subagent_start", map[string]any{"mode": mode, "tasks": len(specs), "runtime": runtime.Name}); emitErr != nil {
			runErr = errors.New("subagent stream is not writable")
			code = http.StatusInternalServerError
			result = spawnSubagentResult{Mode: mode, Final: runErr.Error(), Terminal: failedSubagentTerminal(subagentFailureTransport, 1, "", subagentTerminationNatural, true, runErr.Error())}
		} else {
			result, code, runErr = a.runSubagentModeSafely(ctx, s, runtime, mode, specs, req.Actor, stream)
		}
	} else {
		result, code, runErr = a.runSubagentModeSafely(ctx, s, runtime, mode, specs, req.Actor, nil)
	}
	if result.Terminal.State == "" {
		result.Terminal = aggregateSubagentTerminal(result.Results, runErr)
	}
	result.Summary = result.Final
	status := code
	if status == 0 {
		status = http.StatusOK
	}
	a.emitToolEvent(r.Context(), sessionID, "tool_spawn_subagent_end", "spawn_subagent", "", req.Actor, map[string]any{
		"mode":           mode,
		"tasks":          len(specs),
		"runtime":        runtime.Name,
		"duration_ms":    time.Since(started).Milliseconds(),
		"terminal_state": result.Terminal.State,
		"failure_kind":   result.Terminal.FailureKind,
		"error":          errString(runErr),
	})
	protocolOK := runErr == nil || len(result.Results) > 0
	if stream != nil {
		return
	}
	if runErr != nil && len(result.Results) == 0 {
		writeToolError(w, status, runErr.Error())
		return
	}
	writeJSON(w, status, toolResponse{OK: protocolOK, Result: result, Error: errString(runErr)})
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
	return subagentRuntimeConfig{Name: name, Command: command, Args: args, TaskMode: taskMode, Protocol: protocol, MaxDepth: maxDepth, SocketURL: socketURL}, nil
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
	if count != 1 {
		return "", nil, errors.New("provide exactly one mode: task, non-empty tasks, or non-empty chain")
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

func (a *App) runSubagentModeSafely(ctx context.Context, s *session.Session, runtime subagentRuntimeConfig, mode string, specs []subagentItemRequest, actor piToolActor, stream *subagentStreamer) (result spawnSubagentResult, code int, err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("subagent runtime failed unexpectedly")
			code = http.StatusInternalServerError
			result = spawnSubagentResult{
				Mode:     mode,
				Final:    err.Error(),
				Terminal: failedSubagentTerminal(subagentFailureUnknown, 1, "", subagentTerminationNatural, true, err.Error()),
			}
		}
	}()
	return a.runSubagentMode(ctx, s, runtime, mode, specs, actor, stream)
}

func (a *App) runSubagentMode(ctx context.Context, s *session.Session, runtime subagentRuntimeConfig, mode string, specs []subagentItemRequest, actor piToolActor, stream *subagentStreamer) (spawnSubagentResult, int, error) {
	switch mode {
	case "single":
		res := a.runSingleSubagent(ctx, s, runtime, specs[0], "subagent", 0, actor, stream)
		if stream != nil {
			_ = stream.Emit("subagent_result", map[string]any{"label": res.Label, "result": res})
		}
		out := spawnSubagentResult{Mode: mode, Final: res.Final, Terminal: res.Terminal, Results: []subagentResult{res}}
		if subagentResultFailed(res) {
			return out, http.StatusOK, errors.New(resultErrorSummary(res))
		}
		return out, http.StatusOK, nil
	case "chain":
		results := make([]subagentResult, 0, len(specs))
		previous := ""
		for i, spec := range specs {
			spec.Task = strings.ReplaceAll(spec.Task, "{previous}", previous)
			res := a.runSingleSubagent(ctx, s, runtime, spec, fmt.Sprintf("step %d", i+1), i+1, actor, stream)
			if stream != nil {
				_ = stream.Emit("subagent_result", map[string]any{"label": res.Label, "step": i + 1, "result": res})
			}
			results = append(results, res)
			if subagentResultFailed(res) {
				return spawnSubagentResult{Mode: mode, Final: resultErrorSummary(res), Terminal: res.Terminal, Results: results}, http.StatusOK, errors.New(resultErrorSummary(res))
			}
			previous = res.Final
		}
		final := ""
		if len(results) > 0 {
			final = results[len(results)-1].Final
		}
		return spawnSubagentResult{Mode: mode, Final: final, Terminal: aggregateSubagentTerminal(results, nil), Results: results}, http.StatusOK, nil
	case "parallel":
		results := make([]subagentResult, len(specs))
		sem := make(chan struct{}, maxSubagentConcurrency)
		var wg sync.WaitGroup
		for i, spec := range specs {
			i, spec := i, spec
			wg.Add(1)
			go func() {
				defer wg.Done()
				label := fmt.Sprintf("task %d", i+1)
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
					results[i] = a.runSingleSubagent(ctx, s, runtime, spec, label, 0, actor, stream)
				case <-ctx.Done():
					results[i] = subagentResult{Label: label, Task: spec.Task, Model: spec.Model, Tools: spec.Tools, Runtime: runtime.Name, Command: runtime.Command}
					setSubagentTerminal(&results[i], cancelledSubagentTerminal(ctx, subagentCancellationExitCode(ctx), "", subagentTerminationNatural))
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
		out := spawnSubagentResult{Mode: mode, Final: final, Terminal: aggregateSubagentTerminal(results, nil), Results: results}
		if len(failed) > 0 {
			return out, http.StatusOK, fmt.Errorf("%d/%d subagents failed: %s", len(failed), len(results), strings.Join(failed, "; "))
		}
		return out, http.StatusOK, nil
	default:
		err := fmt.Errorf("unsupported subagent mode %q", mode)
		return spawnSubagentResult{Mode: mode, Final: err.Error(), Terminal: failedSubagentTerminal(subagentFailureConfiguration, 1, "", subagentTerminationNatural, false, err.Error())}, http.StatusBadRequest, err
	}
}

func (a *App) runSingleSubagent(ctx context.Context, s *session.Session, runtime subagentRuntimeConfig, spec subagentItemRequest, label string, step int, actor piToolActor, stream *subagentStreamer) subagentResult {
	started := time.Now()
	subagentID := "subagent-" + uuid.NewString()
	cwd, virtualCwd, err := resolveSubagentCwd(s, spec.Cwd)
	res := subagentResult{Label: label, Task: spec.Task, Model: spec.Model, Tools: spec.Tools, Cwd: virtualCwd, Runtime: runtime.Name, Command: runtime.Command}
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

	args := append([]string{}, runtime.Args...)
	stdin := ""
	env := sanitizedSubagentEnv(os.Environ())
	childDepth := subagentDepthFromActor(actor) + 1
	env = withEnvOverrides(env, map[string]string{
		"AGENTSH_SESSION_ID":          s.ID,
		"AGENTSH_SUBAGENT_ID":         subagentID,
		"AGENTSH_SUBAGENT_DEPTH":      strconv.Itoa(childDepth),
		"AGENTSH_SUBAGENT_CWD":        virtualCwd,
		"AGENTSH_SUBAGENT_MODEL":      spec.Model,
		"AGENTSH_SUBAGENT_TOOLS":      strings.Join(spec.Tools, ","),
		"PI_CODING_AGENT_DIR":         childAgentDir,
		"PI_CODING_AGENT_SESSION_DIR": childSessionDir,
	})
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
		payload, _ := json.Marshal(map[string]any{"task": spec.Task, "systemPrompt": spec.SystemPrompt, "model": spec.Model, "tools": spec.Tools, "cwd": virtualCwd, "actor": map[string]any(actor)})
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
	cmd.Stdout = subagentOutputWriter(&stdout, stream, subagentID, label, "stdout")
	cmd.Stderr = subagentOutputWriter(&stderr, stream, subagentID, label, "stderr")
	process := runOwnedSubagentProcess(ctx, cmd, subagentTerminationGracePeriod)
	res.Stdout = stdout.String()
	res.Stderr = stderr.String()
	res.DurationMS = time.Since(started).Milliseconds()
	protocolOutcome := parseSubagentProtocolOutcome(runtime.Protocol, res.Stdout)
	res.Final = protocolOutcome.Final

	if ctx.Err() != nil {
		setSubagentTerminal(&res, cancelledSubagentTerminal(ctx, subagentCancellationExitCode(ctx), process.Signal, process.Termination))
		return res
	}
	if process.RunError != nil {
		res.Error = process.RunError.Error()
		kind := subagentFailureProcess
		retryable := true
		var execErr *exec.Error
		if errors.As(process.RunError, &execErr) {
			kind = subagentFailureConfiguration
			retryable = false
		} else if likelySubagentAuthFailure(res.Error, res.Stderr) {
			kind = subagentFailureAuth
			retryable = false
		} else if protocolOutcome.Failed() {
			kind = protocolOutcome.FailureKind
			retryable = kind == subagentFailureProtocol || kind == subagentFailureCompaction
			if protocolOutcome.ErrorMessage != "" {
				res.Error = protocolOutcome.ErrorMessage
			}
		}
		setSubagentTerminal(&res, failedSubagentTerminal(kind, exitCode(process.RunError), process.Signal, process.Termination, retryable, res.Error))
		if res.Final == "" {
			res.Final = resultErrorSummary(res)
		}
		return res
	}
	if protocolOutcome.Failed() {
		res.Error = protocolOutcome.ErrorMessage
		retryable := protocolOutcome.FailureKind == subagentFailureProtocol || protocolOutcome.FailureKind == subagentFailureCompaction
		setSubagentTerminal(&res, failedSubagentTerminal(protocolOutcome.FailureKind, 1, process.Signal, process.Termination, retryable, res.Error))
		return res
	}
	if !protocolOutcome.Completed {
		res.Error = "subagent output protocol did not reach completion"
		setSubagentTerminal(&res, failedSubagentTerminal(subagentFailureProtocol, 1, process.Signal, process.Termination, true, res.Error))
		return res
	}
	setSubagentTerminal(&res, completedSubagentTerminal(0, process.Termination))
	return res
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

func resolveSubagentCwd(s *session.Session, reqCwd string) (real string, virtual string, err error) {
	if strings.TrimSpace(reqCwd) != "" && filepath.IsAbs(reqCwd) {
		root := filepath.Clean(s.WorkspaceMountPath())
		candidate := filepath.Clean(reqCwd)
		if session.IsRealPathUnder(candidate, root) {
			rel, relErr := filepath.Rel(root, candidate)
			if relErr != nil {
				return "", "", relErr
			}
			vroot := s.EffectiveVirtualRoot()
			virtual = filepath.ToSlash(filepath.Join(filepath.FromSlash(vroot), rel))
			return validateSubagentCwdPath(s, candidate, virtual)
		}
	}
	rp, err := resolveToolPath(s, ".", reqCwd)
	if err != nil {
		return "", "", err
	}
	if !rp.InWorkspace {
		return "", "", errors.New("subagent cwd must be inside the session workspace")
	}
	return validateSubagentCwdPath(s, rp.Real, rp.Virtual)
}

func validateSubagentCwdPath(s *session.Session, realPath, virtualPath string) (string, string, error) {
	info, statErr := os.Stat(realPath)
	if statErr != nil {
		return "", "", statErr
	}
	if !info.IsDir() {
		return "", "", errors.New("subagent cwd is not a directory")
	}
	if err := ensureToolPathNoSymlinkEscape(realPath, s.WorkspaceMountPath()); err != nil {
		return "", "", err
	}
	return realPath, virtualPath, nil
}

func sanitizedSubagentEnv(in []string) []string {
	blocked := map[string]bool{
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

func subagentOutputWriter(buf *cappedBuffer, stream *subagentStreamer, subagentID, label, name string) io.Writer {
	if stream == nil {
		return buf
	}
	return io.MultiWriter(buf, subagentChunkWriter{stream: stream, subagentID: subagentID, label: label, name: name})
}

func (w subagentChunkWriter) Write(p []byte) (int, error) {
	if len(p) > 0 {
		_ = w.stream.Emit(w.name, map[string]any{"subagent_id": w.subagentID, "label": w.label, "data": string(p)})
	}
	return len(p), nil
}

type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 {
		return len(p), nil
	}
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		if len(p) <= remaining {
			_, _ = b.buf.Write(p)
		} else {
			_, _ = b.buf.Write(p[:remaining])
			b.truncated = true
		}
	} else {
		b.truncated = true
	}
	return len(p), nil
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
