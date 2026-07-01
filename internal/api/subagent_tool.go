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
	Label      string   `json:"label"`
	Task       string   `json:"task"`
	ExitCode   int      `json:"exit_code"`
	StopReason string   `json:"stop_reason"`
	Final      string   `json:"final"`
	Stdout     string   `json:"stdout,omitempty"`
	Stderr     string   `json:"stderr,omitempty"`
	DurationMS int64    `json:"duration_ms"`
	Model      string   `json:"model,omitempty"`
	Tools      []string `json:"tools,omitempty"`
	Cwd        string   `json:"cwd,omitempty"`
	Runtime    string   `json:"runtime,omitempty"`
	Command    string   `json:"command,omitempty"`
	Args       []string `json:"args,omitempty"`
	Error      string   `json:"error,omitempty"`
}

type spawnSubagentResult struct {
	Mode    string           `json:"mode"`
	Final   string           `json:"final"`
	Summary string           `json:"summary"`
	Results []subagentResult `json:"results"`
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
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	a.emitToolEvent(r.Context(), sessionID, "tool_spawn_subagent_start", "spawn_subagent", "", req.Actor, map[string]any{
		"mode": mode,
		"tasks": len(specs),
		"runtime": runtime.Name,
	})
	started := time.Now()
	result, code, err := a.runSubagentMode(ctx, s, runtime, mode, specs, req.Actor)
	result.Summary = result.Final
	status := code
	if status == 0 {
		status = http.StatusOK
	}
	a.emitToolEvent(r.Context(), sessionID, "tool_spawn_subagent_end", "spawn_subagent", "", req.Actor, map[string]any{
		"mode": mode,
		"tasks": len(specs),
		"runtime": runtime.Name,
		"duration_ms": time.Since(started).Milliseconds(),
		"error": errString(err),
	})
	if err != nil && len(result.Results) == 0 {
		writeToolError(w, status, err.Error())
		return
	}
	writeJSON(w, status, toolResponse{OK: err == nil, Result: result, Error: errString(err)})
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

func (a *App) runSubagentMode(ctx context.Context, s *session.Session, runtime subagentRuntimeConfig, mode string, specs []subagentItemRequest, actor piToolActor) (spawnSubagentResult, int, error) {
	switch mode {
	case "single":
		res := a.runSingleSubagent(ctx, s, runtime, specs[0], "subagent", 0, actor)
		out := spawnSubagentResult{Mode: mode, Final: res.Final, Results: []subagentResult{res}}
		if res.ExitCode != 0 || res.StopReason == "error" || res.StopReason == "timeout" {
			return out, http.StatusOK, errors.New(resultErrorSummary(res))
		}
		return out, http.StatusOK, nil
	case "chain":
		results := make([]subagentResult, 0, len(specs))
		previous := ""
		for i, spec := range specs {
			spec.Task = strings.ReplaceAll(spec.Task, "{previous}", previous)
			res := a.runSingleSubagent(ctx, s, runtime, spec, fmt.Sprintf("step %d", i+1), i+1, actor)
			results = append(results, res)
			if res.ExitCode != 0 || res.StopReason == "error" || res.StopReason == "timeout" {
				return spawnSubagentResult{Mode: mode, Final: resultErrorSummary(res), Results: results}, http.StatusOK, errors.New(resultErrorSummary(res))
			}
			previous = res.Final
		}
		final := ""
		if len(results) > 0 {
			final = results[len(results)-1].Final
		}
		return spawnSubagentResult{Mode: mode, Final: final, Results: results}, http.StatusOK, nil
	case "parallel":
		results := make([]subagentResult, len(specs))
		sem := make(chan struct{}, maxSubagentConcurrency)
		var wg sync.WaitGroup
		for i, spec := range specs {
			i, spec := i, spec
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				results[i] = a.runSingleSubagent(ctx, s, runtime, spec, fmt.Sprintf("task %d", i+1), 0, actor)
			}()
		}
		wg.Wait()
		parts := make([]string, 0, len(results))
		var failed []string
		for _, res := range results {
			if res.ExitCode != 0 || res.StopReason == "error" || res.StopReason == "timeout" {
				failed = append(failed, resultErrorSummary(res))
			}
			preview := res.Final
			if preview == "" {
				preview = resultErrorSummary(res)
			}
			parts = append(parts, fmt.Sprintf("[%s] %s", res.Label, truncateString(preview, 500)))
		}
		final := strings.Join(parts, "\n\n")
		out := spawnSubagentResult{Mode: mode, Final: final, Results: results}
		if len(failed) > 0 {
			return out, http.StatusOK, fmt.Errorf("%d/%d subagents failed: %s", len(failed), len(results), strings.Join(failed, "; "))
		}
		return out, http.StatusOK, nil
	default:
		return spawnSubagentResult{}, http.StatusBadRequest, fmt.Errorf("unsupported subagent mode %q", mode)
	}
}

func (a *App) runSingleSubagent(ctx context.Context, s *session.Session, runtime subagentRuntimeConfig, spec subagentItemRequest, label string, step int, actor piToolActor) subagentResult {
	started := time.Now()
	subagentID := "subagent-" + uuid.NewString()
	cwd, virtualCwd, err := resolveSubagentCwd(s, spec.Cwd)
	res := subagentResult{Label: label, Task: spec.Task, Model: spec.Model, Tools: spec.Tools, Cwd: virtualCwd, Runtime: runtime.Name, Command: runtime.Command}
	if err != nil {
		res.ExitCode = 1
		res.StopReason = "error"
		res.Error = err.Error()
		res.DurationMS = time.Since(started).Milliseconds()
		return res
	}
	args := append([]string{}, runtime.Args...)
	stdin := ""
	env := sanitizedSubagentEnv(os.Environ())
	childDepth := subagentDepthFromActor(actor) + 1
	env = append(env,
		"AGENTSH_SESSION_ID="+s.ID,
		"AGENTSH_SUBAGENT_ID="+subagentID,
		"AGENTSH_SUBAGENT_DEPTH="+strconv.Itoa(childDepth),
		"AGENTSH_SUBAGENT_CWD="+virtualCwd,
		"AGENTSH_SUBAGENT_MODEL="+spec.Model,
		"AGENTSH_SUBAGENT_TOOLS="+strings.Join(spec.Tools, ","),
		"AGENTSH_SUBAGENT_SYSTEM_PROMPT="+spec.SystemPrompt,
	)
	if runtime.SocketURL != "" {
		env = append(env, "AGENTSH_SESSION_SUPERVISOR="+runtime.SocketURL)
	}
	switch runtime.TaskMode {
	case "arg":
		args = appendSubagentTaskArgs(args, spec)
	case "stdin":
		stdin = spec.Task
	case "env":
		env = append(env, "AGENTSH_SUBAGENT_TASK="+spec.Task)
	case "json-stdin":
		payload, _ := json.Marshal(map[string]any{"task": spec.Task, "systemPrompt": spec.SystemPrompt, "model": spec.Model, "tools": spec.Tools, "cwd": virtualCwd, "actor": map[string]any(actor)})
		stdin = string(payload)
	}
	res.Args = args
	cmd := exec.CommandContext(ctx, runtime.Command, args...)
	cmd.Dir = cwd
	cmd.Env = env
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr cappedBuffer
	stdout.limit = maxSubagentTextBytes
	stderr.limit = maxSubagentTextBytes
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	res.Stdout = stdout.String()
	res.Stderr = stderr.String()
	res.DurationMS = time.Since(started).Milliseconds()
	res.Final = parseSubagentFinal(runtime.Protocol, res.Stdout)
	if ctx.Err() != nil {
		res.ExitCode = 124
		res.StopReason = "timeout"
		res.Error = ctx.Err().Error()
		return res
	}
	if runErr != nil {
		res.ExitCode = exitCode(runErr)
		res.StopReason = "error"
		res.Error = runErr.Error()
		if res.Final == "" {
			res.Final = resultErrorSummary(res)
		}
		return res
	}
	res.ExitCode = 0
	res.StopReason = "completed"
	return res
}

func appendSubagentTaskArgs(args []string, spec subagentItemRequest) []string {
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
		"AGENTSH_API_KEY": true,
		"AGENTSH_APPROVER_KEY": true,
		"AGENTSH_APPROVER_API_KEY": true,
		"AGENTSH_APPROVER_KEY_FILE": true,
		"AGENTSH_ADMIN_TOKEN": true,
		"AGENTSH_TOKEN": true,
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

func parseSubagentFinal(protocol, stdout string) string {
	switch protocol {
	case "pi-json":
		if text := parsePiJSONFinal(stdout); text != "" {
			return text
		}
	}
	return strings.TrimSpace(stdout)
}

func parsePiJSONFinal(stdout string) string {
	var final string
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if typ, _ := ev["type"].(string); typ != "message_end" && typ != "message_update" && typ != "message_start" {
			continue
		}
		msg, _ := ev["message"].(map[string]any)
		if msg == nil {
			continue
		}
		if role, _ := msg["role"].(string); role != "assistant" {
			continue
		}
		if text := messageContentText(msg["content"]); text != "" {
			final = text
		}
	}
	return strings.TrimSpace(final)
}

func messageContentText(content any) string {
	switch v := content.(type) {
	case string:
		return v
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if obj, ok := item.(map[string]any); ok {
				if typ, _ := obj["type"].(string); typ == "text" || typ == "text_delta" || typ == "markdown" {
					if text, _ := obj["text"].(string); text != "" {
						parts = append(parts, text)
					}
				}
			}
		}
		return strings.Join(parts, "")
	default:
		return ""
	}
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
	return fmt.Sprintf("%s %s: %s", res.Label, res.StopReason, truncateString(strings.TrimSpace(msg), 1000))
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
