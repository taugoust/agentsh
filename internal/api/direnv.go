package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/go-chi/chi/v5"
)

var direnvNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type refreshDirenvRequest struct {
	Cwd   string `json:"cwd,omitempty"`
	Actor struct {
		Kind  string `json:"kind,omitempty"`
		Label string `json:"label,omitempty"`
	} `json:"actor,omitempty"`
}

type refreshDirenvResult struct {
	State         string `json:"state"`
	SetCount      int    `json:"set_count"`
	UnsetCount    int    `json:"unset_count"`
	RejectedCount int    `json:"rejected_count"`
	Generation    uint64 `json:"generation"`
	DurationMS    int64  `json:"duration_ms"`
}

type direnvChange struct {
	name  string
	value *string
}

func (a *App) refreshDirenvTool(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req refreshDirenvRequest
	if ok := decodeJSON(w, r, &req, "invalid json"); !ok {
		return
	}
	if len(req.Cwd) > 4096 || len(req.Actor.Kind) > 64 || len(req.Actor.Label) > 256 {
		writeToolError(w, http.StatusBadRequest, "request field exceeds limit")
		return
	}
	s, ok := a.sessions.Get(id)
	if !ok {
		writeToolError(w, http.StatusNotFound, "session not found")
		return
	}
	engine := a.policyEngineFor(s)
	cfg := engine.DirenvImportPolicy()
	if !cfg.Enabled {
		_, generation := s.DirenvEnvironment()
		writeJSON(w, http.StatusForbidden, toolResponse{
			OK: false, Result: refreshDirenvResult{State: "policy_denied", Generation: generation},
			Error: "direnv refresh is disabled by policy",
		})
		return
	}
	if _, err := resolveWorkingDir(s, req.Cwd); err != nil {
		writeToolError(w, http.StatusBadRequest, "invalid direnv working directory")
		return
	}

	start := time.Now()
	result := refreshDirenvResult{State: "unavailable"}
	var old map[string]string
	var generation uint64
	callbackRan := false
	execReq := types.ExecRequest{
		Command: "direnv", Args: []string{"export", "json"}, WorkingDir: req.Cwd,
		Timeout: cfg.EvaluationTimeout.String(), IncludeEvents: "summary",
		Actor: map[string]any{"kind": "extension", "label": "Pi direnv refresh"},
	}
	resp, code, err := a.execInSessionCoreWithOptions(r.Context(), id, execReq, internalExecOptions{
		sensitive: true, stdoutCaptureBytes: int64(cfg.MaxStdoutBytes), stderrCaptureBytes: int64(cfg.MaxStderrBytes),
		queueTimeout: cfg.QueueTimeout, evaluationTimeout: cfg.EvaluationTimeout,
		onAdmitted: func() {
			old, generation = s.DirenvEnvironment()
			result.Generation = generation
		},
		onSensitiveResult: func(run internalSensitiveExecResult) {
			callbackRan = true
			result = evaluateDirenvResult(cfg, s, old, generation, run)
		},
	})
	result.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "queue timeout") {
			result.State = "timed_out"
		}
	} else if code == http.StatusForbidden {
		result.State = "policy_denied"
		if resp != nil && resp.Result.Error != nil && resp.Result.Error.Code == "E_APPROVAL_DENIED" {
			result.State = "policy_denied"
		}
	} else if !callbackRan {
		result.State = "unavailable"
	}
	// Actor metadata is server-owned; do not echo request-controlled labels into
	// the audit stream for this sensitive operation.
	actor := piToolActor{"kind": "extension", "label": "Pi direnv refresh"}
	a.emitToolEvent(r.Context(), id, "tool_refresh_direnv", "refresh", "", actor, map[string]any{
		"state": result.State, "set_count": result.SetCount, "unset_count": result.UnsetCount,
		"rejected_count": result.RejectedCount, "generation": result.Generation, "duration_ms": result.DurationMS,
	})
	writeJSON(w, http.StatusOK, toolResponse{OK: result.State == "loaded" || result.State == "unchanged" || result.State == "no_envrc", Result: result})
}

func evaluateDirenvResult(cfg policy.ResolvedDirenvImportPolicy, s *session.Session, old map[string]string, generation uint64, run internalSensitiveExecResult) refreshDirenvResult {
	out := refreshDirenvResult{Generation: generation}
	if run.StdoutTruncated || run.StderrTruncated || run.StdoutTotal > int64(cfg.MaxStdoutBytes) || run.StderrTotal > int64(cfg.MaxStderrBytes) {
		out.State = "invalid_output"
		return out
	}
	if run.ExecErr != nil {
		if errors.Is(run.ExecErr, context.DeadlineExceeded) || run.ExitCode == 124 {
			out.State = "timed_out"
		} else {
			out.State = "unavailable"
		}
		return out
	}
	if run.ExitCode != 0 {
		lower := strings.ToLower(string(run.Stderr))
		switch {
		case strings.Contains(lower, "not allowed"), strings.Contains(lower, "blocked"):
			out.State = "not_allowed"
		case run.ExitCode == 124:
			out.State = "timed_out"
		case run.ExitCode == 126:
			out.State = "policy_denied"
		default:
			out.State = "unavailable"
		}
		return out
	}
	changes, err := parseDirenvJSON(run.Stdout, cfg)
	if err != nil {
		out.State = "invalid_output"
		return out
	}
	next := cloneStringMap(old)
	serviceEnv := s.ServiceEnvVars()
	for _, change := range changes {
		if !policy.DirenvImportAllowed(cfg, change.name) || containsKeyFold(serviceEnv, change.name) {
			out.RejectedCount++
			continue
		}
		deleteFold(next, change.name)
		if change.value == nil {
			out.UnsetCount++
			continue
		}
		next[change.name] = *change.value
		out.SetCount++
	}
	if len(next) > cfg.MaxKeys || environmentBytes(next) > cfg.MaxBytes {
		out.State = "invalid_output"
		return out
	}
	newGeneration, changed := s.ReplaceDirenvEnvironment(next)
	out.Generation = newGeneration
	if changed {
		out.State = "loaded"
	} else if len(changes) == 0 && len(old) == 0 {
		out.State = "no_envrc"
	} else {
		out.State = "unchanged"
	}
	return out
}

func parseDirenvJSON(data []byte, cfg policy.ResolvedDirenvImportPolicy) ([]direnvChange, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, fmt.Errorf("direnv output must be an object")
	}
	seen := map[string]struct{}{}
	changes := make([]direnvChange, 0)
	total := 0
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, ok := tok.(string)
		if !ok || !direnvNameRE.MatchString(name) {
			return nil, fmt.Errorf("invalid environment name")
		}
		fold := strings.ToUpper(name)
		if _, duplicate := seen[fold]; duplicate {
			return nil, fmt.Errorf("duplicate environment name")
		}
		seen[fold] = struct{}{}
		if len(seen) > cfg.MaxKeys {
			return nil, fmt.Errorf("too many environment keys")
		}
		var raw any
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		change := direnvChange{name: name}
		total += len(name) + 1
		switch value := raw.(type) {
		case nil:
		case string:
			if len(value) > cfg.MaxValueBytes {
				return nil, fmt.Errorf("environment value too large")
			}
			total += len(value)
			change.value = &value
		default:
			return nil, fmt.Errorf("environment value must be string or null")
		}
		if total > cfg.MaxBytes {
			return nil, fmt.Errorf("environment output too large")
		}
		changes = append(changes, change)
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if tok, err := dec.Token(); err != io.EOF || tok != nil {
		return nil, fmt.Errorf("trailing direnv output")
	}
	return changes, nil
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func containsKeyFold(values map[string]string, name string) bool {
	for key := range values {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

func deleteFold(values map[string]string, name string) {
	for key := range values {
		if strings.EqualFold(key, name) {
			delete(values, key)
		}
	}
}

func environmentBytes(values map[string]string) int {
	total := 0
	for k, v := range values {
		total += len(k) + len(v) + 1
	}
	return total
}
