package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (a *App) execInSessionStream(w http.ResponseWriter, r *http.Request) {
	if a.ptraceFailed.Load() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "ptrace tracer exited unexpectedly; refusing to execute commands without enforcement"})
		return
	}
	id := chi.URLParam(r, "id")
	s, ok := a.sessions.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}

	var req types.ExecRequest
	if ok := decodeJSON(w, r, &req, "invalid json"); !ok {
		return
	}
	if req.Command == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "command is required"})
		return
	}
	parsedTimeout, err := parseCommandTimeout(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	cmdID := "cmd-" + uuid.NewString()
	start := time.Now().UTC()
	unlock, admissionErr := s.LockExecContext(r.Context())
	if admissionErr != nil {
		writeJSON(w, http.StatusRequestTimeout, map[string]any{"error": "execution admission cancelled", "command_started": false})
		return
	}
	defer unlock()

	engine := a.policyEngineFor(s)
	limits := engine.Limits()
	timeoutResolution := a.resolveParsedCommandTimeout(parsedTimeout, limits.CommandTimeout)
	s.SetCurrentCommandID(cmdID)

	// Propagate W3C trace context for distributed tracing correlation
	if tp := r.Header.Get("Traceparent"); tp != "" {
		if traceID, spanID, traceFlags, ok := parseTraceparent(tp); ok {
			s.SetCurrentTraceContext(traceID, spanID, traceFlags)
		}
	}

	pre := engine.CheckCommandWithExecve(req.Command, req.Args, a.execveEnforcementActive(), a.shellCOpaqueMode())
	redirected, originalCmd, originalArgs := applyCommandRedirect(&req.Command, &req.Args, pre)
	approvalErr := a.applyCommandApproval(r.Context(), id, cmdID, originalCmd, originalArgs, req.Actor, &pre)
	preEv := types.Event{
		ID:        uuid.NewString(),
		Timestamp: start,
		Type:      "command_policy",
		SessionID: id,
		CommandID: cmdID,
		Operation: "command_precheck",
		Policy: &types.PolicyInfo{
			Decision:          pre.PolicyDecision,
			EffectiveDecision: pre.EffectiveDecision,
			Rule:              pre.Rule,
			Message:           pre.Message,
			Approval:          pre.Approval,
			Redirect:          pre.Redirect,
		},
		Fields: map[string]any{
			"command": originalCmd,
			"args":    originalArgs,
		},
	}
	s.InjectTraceContext(preEv.Fields)
	_ = a.store.AppendEvent(r.Context(), preEv)
	a.broker.Publish(preEv)

	if redirected && pre.Redirect != nil {
		redirEv := types.Event{
			ID:        uuid.NewString(),
			Timestamp: start,
			Type:      "command_redirected",
			SessionID: id,
			CommandID: cmdID,
			Policy: &types.PolicyInfo{
				Decision:          types.DecisionRedirect,
				EffectiveDecision: types.DecisionAllow,
				Rule:              pre.Rule,
				Message:           pre.Message,
				Redirect:          pre.Redirect,
			},
			Fields: map[string]any{
				"from_command": originalCmd,
				"from_args":    originalArgs,
				"to_command":   req.Command,
				"to_args":      req.Args,
			},
		}
		s.InjectTraceContext(redirEv.Fields)
		_ = a.store.AppendEvent(r.Context(), redirEv)
		a.broker.Publish(redirEv)
	}

	if pre.EffectiveDecision == types.DecisionDeny {
		a.emitCommandDBBypassAttempt(r.Context(), s, id, cmdID, pre)
		code := "E_POLICY_DENIED"
		if pre.PolicyDecision == types.DecisionApprove {
			code = "E_APPROVAL_DENIED"
			if approvalErr != nil && strings.Contains(strings.ToLower(approvalErr.Error()), "timeout") {
				code = "E_APPROVAL_TIMEOUT"
			}
		}
		resp := types.ExecResponse{
			CommandID: cmdID,
			SessionID: id,
			Timestamp: start,
			Request:   req,
			Result: types.ExecResult{

				ExitCode:       126,
				CommandTimeout: timeoutResolution.Metadata,
				DurationMs:     int64(time.Since(start).Milliseconds()),
				Outcome:        &types.ExecOutcome{CommandStarted: false, DispatchState: "not_dispatched", FailureKind: types.ExecFailureDenied, Code: code, Message: "command denied by policy"},

				Error: &types.ExecError{
					Code:       code,
					Message:    "command denied by policy",
					PolicyRule: pre.Rule,
				},
			},
			Events: types.ExecEvents{
				FileOperations:    []types.Event{},
				NetworkOperations: []types.Event{},
				BlockedOperations: []types.Event{preEv},
			},
		}
		writeJSON(w, http.StatusForbidden, resp)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "streaming not supported", "command_timeout": timeoutResolution.Metadata})
		return
	}

	commandStarted := false
	onStarted := func() {
		commandStarted = true
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		startEv := types.Event{ID: uuid.NewString(), Timestamp: time.Now().UTC(), Type: "command_started", SessionID: id, CommandID: cmdID, CommandTimeout: &timeoutResolution.Metadata,
			Fields: map[string]any{"command": req.Command, "args": req.Args}}
		s.InjectTraceContext(startEv.Fields)
		_ = a.store.AppendEvent(r.Context(), startEv)
		a.broker.Publish(startEv)
		_ = writeSSE(w, flusher, "start", map[string]any{"command_id": cmdID, "command_started": true, "command_timeout": timeoutResolution.Metadata})

	}

	emit := func(event string, payload map[string]any) error {
		return writeSSE(w, flusher, event, payload)
	}

	var (
		wrappedReq               types.ExecRequest
		extraCfg                 *extraProcConfig
		envPolicy                policy.ResolvedEnvPolicy
		envPolicyResolved        bool
		exitCode                 int
		stdoutB, stderrB         []byte
		stdoutTotal, stderrTotal int64
		stdoutTrunc, stderrTrunc bool
		resources                types.ExecResources
		execErr                  error
		attemptCount             int
		attemptDiagnostics       []types.ExecAttemptDiagnostic
	)
	for {
		attemptCount++
		// Setup is per-attempt; policy and approval above are not replayed.
		wrapperResult := a.setupSeccompWrapperWithPolicy(req, id, s, engine)
		if wrapperResult.setupErr != nil {
			a.recordNetworkEnforcementFailure(id, cmdID, wrapperResult.setupErr)
			if attemptCount == 1 {
				message := fmt.Sprintf("pre-exec boundary unavailable: %v", wrapperResult.setupErr)
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": message, "command_timeout": timeoutResolution.Metadata, "outcome": &types.ExecOutcome{CommandStarted: false, DispatchState: "pre_exec_refused", FailureKind: types.ExecFailurePreExec, Code: "E_PRE_EXEC_BOUNDARY", Message: message, AttemptCount: 1}})
				return
			}
			exitCode = 127
			execErr = markPreExecEnforcementError("E_PRE_EXEC_BOUNDARY", fmt.Errorf("fresh retry boundary unavailable: %w", wrapperResult.setupErr))
			attemptDiagnostics = append(attemptDiagnostics, types.ExecAttemptDiagnostic{Attempt: attemptCount, ProtocolStage: "command_boundary_setup"})
			break
		}
		wrappedReq = wrapperResult.wrappedReq
		extraCfg = wrapperResult.extraCfg
		if !envPolicyResolved {
			cmdDecision := engine.CheckCommandWithExecve(wrappedReq.Command, wrappedReq.Args, a.execveEnforcementActive(), a.shellCOpaqueMode())
			envPolicy = cmdDecision.EnvPolicy
			envPolicyResolved = true
		}
		exitCode, stdoutB, stderrB, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, resources, execErr = runCommandWithResourcesStreamingEmitResolvedTimeout(r.Context(), s, cmdID, wrappedReq, a.cfg, envPolicy, timeoutResolution.Duration, emit, a.cgroupHook(id, cmdID, limits), extraCfg, a.ptraceTracer, id, onStarted)
		failure := commandJailFailureFrom(execErr)
		if failure == nil {
			break
		}
		diagnostic := failure.diagnostic(attemptCount)
		attemptDiagnostics = append(attemptDiagnostics, diagnostic)
		retrying := shouldRetryCommandJailAttempt(r.Context(), attemptCount, execErr)
		a.emitCommandJailAttempt(id, cmdID, diagnostic, retrying)
		if !retrying {
			break
		}
	}
	if !commandStarted {
		outcome := normalizeExecOutcome(false, exitCode, execErr)
		applyCommandAttemptDiagnostics(outcome, attemptCount, attemptDiagnostics)
		writeJSON(w, execFailureHTTPStatus(outcome), map[string]any{"command_id": cmdID, "command_timeout": timeoutResolution.Metadata, "outcome": outcome, "error": outcome.Message})
		return
	}
	terminalCtx, cancelTerminalPersistence := terminalPersistenceContext(r.Context())
	defer cancelTerminalPersistence()

	if commandBoundaryRequired(extraCfg) && shouldRecordNetworkEnforcementFailure(execErr) {
		a.recordNetworkEnforcementFailure(id, cmdID, execErr)
	}
	_ = a.store.SaveOutput(terminalCtx, id, cmdID, stdoutB, stderrB, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc)

	// Check if process was killed by seccomp (SIGSYS) and emit event
	emitSeccompBlockedIfSIGSYS(terminalCtx, a.store, a.broker, id, cmdID, execErr)

	terminationReason, resultError := executionTermination(execErr)
	end := time.Now().UTC()
	endEv := types.Event{
		ID:                uuid.NewString(),
		Timestamp:         end,
		Type:              "command_finished",
		SessionID:         id,
		CommandID:         cmdID,
		CommandTimeout:    &timeoutResolution.Metadata,
		TerminationReason: terminationReason,
		Fields: map[string]any{
			"exit_code":      exitCode,
			"duration_ms":    int64(end.Sub(start).Milliseconds()),
			"cpu_user_ms":    resources.CPUUserMs,
			"cpu_system_ms":  resources.CPUSystemMs,
			"memory_peak_kb": resources.MemoryPeakKB,
		},
	}
	if execErr != nil {
		endEv.Fields["error"] = execErr.Error()
	}
	if terminationReason != "" {
		endEv.Fields["termination_reason"] = terminationReason
	}
	s.InjectTraceContext(endEv.Fields)
	_ = a.store.AppendEvent(terminalCtx, endEv)
	a.broker.Publish(endEv)

	// Final event for the client includes effective timeout and typed terminal state.
	terminalOutcome := normalizeExecOutcome(true, exitCode, execErr)
	applyCommandAttemptDiagnostics(terminalOutcome, attemptCount, attemptDiagnostics)
	done := map[string]any{

		"command_id":       cmdID,
		"exit_code":        exitCode,
		"duration_ms":      int64(end.Sub(start).Milliseconds()),
		"stdout_truncated": stdoutTrunc,
		"stderr_truncated": stderrTrunc,

		"outcome":         terminalOutcome,
		"command_timeout": timeoutResolution.Metadata,
	}
	if terminationReason != "" {
		done["termination_reason"] = terminationReason
	}
	if resultError != nil {
		done["error"] = resultError
	}
	_ = writeSSE(w, flusher, "done", done)

}

type emitFunc func(event string, payload map[string]any) error

func runCommandWithResourcesStreamingEmit(ctx context.Context, s *session.Session, cmdID string, req types.ExecRequest, cfg *config.Config, envPol policy.ResolvedEnvPolicy, policyLimit time.Duration, emit emitFunc, hook postStartHook, extra *extraProcConfig, tracer any, sessionID string, onStarted func()) (exitCode int, stdout []byte, stderr []byte, stdoutTotal int64, stderrTotal int64, stdoutTrunc bool, stderrTrunc bool, resources types.ExecResources, err error) {
	resolution, resolveErr := resolveCommandTimeout(req, policyLimit)
	if resolveErr != nil {
		closePreStartProcessFiles(extra)
		return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, resolveErr
	}
	return runCommandWithResourcesStreamingEmitResolvedTimeout(ctx, s, cmdID, req, cfg, envPol, resolution.Duration, emit, hook, extra, tracer, sessionID, onStarted)
}

func runCommandWithResourcesStreamingEmitResolvedTimeout(ctx context.Context, s *session.Session, cmdID string, req types.ExecRequest, cfg *config.Config, envPol policy.ResolvedEnvPolicy, timeout time.Duration, emit emitFunc, hook postStartHook, extra *extraProcConfig, tracer any, sessionID string, onStarted func()) (exitCode int, stdout []byte, stderr []byte, stdoutTotal int64, stderrTotal int64, stdoutTrunc bool, stderrTrunc bool, resources types.ExecResources, err error) {

	ctx, cancel := withExtendableCommandTimeout(ctx, timeout)
	defer cancel()
	defer func() {
		if !commandTimedOut(ctx) || errors.Is(err, errCommandTimeout) {
			return
		}
		const message = "command timed out\n"
		exitCode = 124
		stderr = append(stderr, message...)
		stderrTotal += int64(len(message))
		stdoutTrunc = true
		stderrTrunc = true
		err = errCommandTimeout
	}()

	extraOwnershipTransferred := false
	defer func() {
		if !extraOwnershipTransferred {
			closePreStartProcessFiles(extra)
		}
	}()

	notifyStarted := sync.OnceFunc(func() {
		if onStarted != nil {
			onStarted()
		}
	})
	if handled, code, out, errOut := s.Builtin(req); handled {
		notifyStarted()
		if len(out) > 0 {
			_ = emit("stdout", map[string]any{"command_id": cmdID, "stream": "stdout", "data": string(out)})
		}
		if len(errOut) > 0 {
			_ = emit("stderr", map[string]any{"command_id": cmdID, "stream": "stderr", "data": string(errOut)})
		}
		return code, out, errOut, int64(len(out)), int64(len(errOut)), false, false, types.ExecResources{}, nil
	}

	s.RecordHistory(strings.TrimSpace(req.Command + " " + strings.Join(req.Args, " ")))

	workdir, err := resolveWorkingDir(s, req.WorkingDir)
	if err != nil {
		msg := []byte(err.Error() + "\n")
		return 2, []byte{}, msg, 0, int64(len(msg)), false, false, types.ExecResources{}, &commandPreStartError{code: "E_INVALID_WORKING_DIRECTORY", err: err}
	}
	if barrierErr := validatePreExecBarrierPath(hook, tracer, extra); barrierErr != nil {
		closePreStartProcessFiles(extra)
		return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, barrierErr
	}

	var cmd *exec.Cmd
	if tracer != nil {
		cmd = exec.Command(req.Command, req.Args...)
	} else {
		cmd = exec.CommandContext(ctx, req.Command, req.Args...)
	}
	if ns := s.NetNSName(); ns != "" {
		allArgs := append([]string{"netns", "exec", ns, req.Command}, req.Args...)
		if tracer != nil {
			cmd = exec.Command("ip", allArgs...)
		} else {
			cmd = exec.CommandContext(ctx, "ip", allArgs...)
		}
	} else if strings.TrimSpace(req.Argv0) != "" && len(cmd.Args) > 0 {
		cmd.Args[0] = req.Argv0
	}
	cmd.Dir = workdir

	var commandBoundary *types.LinuxCommandJailRequirements
	if extra != nil {
		commandBoundary = extra.commandBoundary
	}
	// Match the non-streaming path: ordinary hooks use a ptrace exec stop,
	// while a strict jail runs only its trusted wrapper before ACK/READY/GO.
	if tracer != nil {
		cmd.SysProcAttr = getSysProcAttr()
	} else if hook != nil && !commandBoundaryRequired(extra) {
		cmd.SysProcAttr = getSysProcAttrStopped()
	} else {
		cmd.SysProcAttr = getSysProcAttr()
	}
	if boundaryErr := configureCommandBoundaryProcess(cmd.SysProcAttr, commandBoundary); boundaryErr != nil {
		return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, markPreExecEnforcementError("E_PRE_EXEC_BOUNDARY", boundaryErr)
	}

	env, envErr := buildCommandEnvironment(cfg, envPol, os.Environ(), s, req.Env, extra)
	if envErr != nil {
		closePreStartProcessFiles(extra)
		return 2, nil, nil, 0, 0, false, false, types.ExecResources{}, &commandPreStartError{code: "E_INVALID_ENVIRONMENT", err: envErr}
	}
	cmd.Env = env

	// Add extra files (socket fds for seccomp notify/signal)
	if extra != nil && len(extra.extraFiles) > 0 {
		cmd.ExtraFiles = append(cmd.ExtraFiles, extra.extraFiles...)
	}

	if req.Stdin != "" {
		cmd.Stdin = strings.NewReader(req.Stdin)
	}

	var writeMu sync.Mutex
	stdoutW := newCaptureWriter(defaultMaxOutputBytes, func(chunk []byte) error {
		if emit == nil || len(chunk) == 0 {
			return nil
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		return emit("stdout", map[string]any{"command_id": cmdID, "stream": "stdout", "data": string(chunk)})
	})
	stderrW := newCaptureWriter(defaultMaxOutputBytes, func(chunk []byte) error {
		if emit == nil || len(chunk) == 0 {
			return nil
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		return emit("stderr", map[string]any{"command_id": cmdID, "stream": "stderr", "data": string(chunk)})
	})
	cmd.Stdout = stdoutW
	cmd.Stderr = stderrW

	// For ptrace mode, use explicit pipes for drain synchronization
	var stdoutPipeR, stderrPipeR, stdoutPipeW, stderrPipeW *os.File
	var pipeWG sync.WaitGroup
	if tracer != nil {
		var pipeErr error
		stdoutPipeR, stdoutPipeW, pipeErr = os.Pipe()
		if pipeErr != nil {
			extra.closeWrapperLogPipe()
			return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, fmt.Errorf("stdout pipe: %w", pipeErr)
		}
		stderrPipeR, stderrPipeW, pipeErr = os.Pipe()
		if pipeErr != nil {
			extra.closeWrapperLogPipe()
			stdoutPipeR.Close()
			stdoutPipeW.Close()
			return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, fmt.Errorf("stderr pipe: %w", pipeErr)
		}
		cmd.Stdout = stdoutPipeW
		cmd.Stderr = stderrPipeW
	}

	if tracer != nil && ctx.Err() != nil {
		extra.closeWrapperLogPipe()
		if stdoutPipeR != nil {
			stdoutPipeR.Close()
		}
		if stderrPipeR != nil {
			stderrPipeR.Close()
		}
		if stdoutPipeW != nil {
			stdoutPipeW.Close()
		}
		if stderrPipeW != nil {
			stderrPipeW.Close()
		}
		if commandTimedOut(ctx) {
			return 124, nil, nil, 0, 0, false, false, types.ExecResources{}, errCommandTimeout
		}
		return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, ctx.Err()
	}

	barrier := newPreExecBarrier(hook)
	defer func() {
		if cleanupErr := barrier.Cleanup(); cleanupErr != nil && !errors.Is(err, cleanupErr) {
			err = errors.Join(err, fmt.Errorf("post-start cleanup: %w", cleanupErr))
		}
	}()

	if err := cmd.Start(); err != nil {
		extra.closeWrapperLogPipe()
		if stdoutPipeR != nil {
			stdoutPipeR.Close()
		}
		if stderrPipeR != nil {
			stderrPipeR.Close()
		}
		if stdoutPipeW != nil {
			stdoutPipeW.Close()
		}
		if stderrPipeW != nil {
			stderrPipeW.Close()
		}
		return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, &commandStartError{err: fmt.Errorf("start: %w", err)}
	}

	// For ptrace mode: close write ends and start draining
	if tracer != nil && stdoutPipeW != nil {
		stdoutPipeW.Close()
		stderrPipeW.Close()
		pipeWG.Add(2)
		go func() {
			defer pipeWG.Done()
			if _, err := io.Copy(stdoutW, stdoutPipeR); err != nil {
				slog.Debug("ptrace stdout drain error", "error", err)
			}
			stdoutPipeR.Close()
		}()
		go func() {
			defer pipeWG.Done()
			if _, err := io.Copy(stderrW, stderrPipeR); err != nil {
				slog.Debug("ptrace stderr drain error", "error", err)
			}
			stderrPipeR.Close()
		}()
	}

	pgid := 0
	var handlerLifecycle *wrapperHandlerLifecycle
	defer func() { handlerLifecycle.cancelHandlers() }()
	if cmd.Process != nil {
		s.SetCurrentProcessPID(cmd.Process.Pid)
		// Register PID→command_id for ESF event attribution.
		if extra != nil && extra.cmdResolver != nil {
			extra.cmdResolver.RegisterCommand(int32(cmd.Process.Pid), cmdID)
		}
		// Register PID→session for ESF event attribution and notify sysext.
		// Register the server PID first so the sysext can track all children
		// via FORK events (the server is the parent of all command processes).
		if extra != nil && extra.sessionTracker != nil {
			extra.sessionTracker.RegisterProcess(s.ID, int32(os.Getpid()), 0)
			extra.sessionTracker.RegisterProcess(s.ID, int32(cmd.Process.Pid), int32(os.Getpid()))
			notifySessionRegistered()
		}
		pgid = getProcessGroupID(cmd.Process.Pid)
		if tracer == nil {
			stopCancellationWatch := watchProcessGroupCancellation(ctx, cmd.Process.Pid, pgid)
			defer stopCancellationWatch()
		}

		hasWrapperHandlers := extra != nil && (extra.notifyParentSock != nil || (extra.signalParentSock != nil && extra.signalEngine != nil))
		wrapperHandlersStarted := false
		var commandBoundaryReady chan error
		if tracer == nil && commandBoundaryRequired(extra) {
			commandBoundaryReady = make(chan error, 1)
			handlerLifecycle = startWrapperHandlers(ctx, extra, cmd.Process.Pid, pgid, commandBoundaryReady)
			extraOwnershipTransferred = true
			wrapperHandlersStarted = true
		}
		if tracer != nil && hasWrapperHandlers {
			// HYBRID MODE: ptrace for execve interception + seccomp wrapper for sockets/files/Landlock.
			// The wrapper must complete seccomp setup BEFORE ptrace attaches to prevent deadlock.
			// Protocol: wrapper does seccomp init → READY byte → server attaches ptrace → GO byte → wrapper exec's.
			ptraceDone := make(chan struct{})
			go func() {
				select {
				case <-ctx.Done():
					_ = killProcessGroup(pgid)
					_ = killProcess(cmd.Process.Pid)
				case <-ptraceDone:
				}
			}()

			// 1. Start wrapper handlers — notify handler receives FD, sends ACK,
			// starts ServeNotifyWithExecve, then reads READY byte from wrapper.
			handlerCtx, handlerCancel := context.WithCancel(ctx)
			var ptraceReady chan error
			if extra.ptraceSync {
				ptraceReady = make(chan error, 1)
			}
			handlerLifecycle = startWrapperHandlers(handlerCtx, extra, cmd.Process.Pid, pgid, ptraceReady)
			extraOwnershipTransferred = true

			// 2. Wait for wrapper to signal READY (only when ptrace sync is enabled).
			if extra.ptraceSync {
				var readyErr error
				select {
				case readyErr = <-ptraceReady:
				case <-ctx.Done():
					readyErr = ctx.Err()
				}
				if readyErr != nil {
					close(ptraceDone)
					handlerCancel()
					_ = killProcess(cmd.Process.Pid)
					_ = killProcessGroup(pgid)
					pipeWG.Wait()
					cmd.Process.Release()
					return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, fmt.Errorf("hybrid wrapper ready: %w", readyErr)
				}
			}

			// 3. Attach ptrace NOW — wrapper is idle, waiting for GO byte.
			waitExit, resume, attachErr := ptraceExecAttach(tracer, cmd.Process.Pid, sessionID, cmdID, hook != nil)
			if attachErr != nil {
				close(ptraceDone)
				handlerCancel()
				_ = killProcess(cmd.Process.Pid)
				_ = killProcessGroup(pgid)
				pipeWG.Wait()
				cmd.Process.Release()
				return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, fmt.Errorf("hybrid ptrace attach: %w", attachErr)
			}

			// 4-6. Enforce once, then resume and send GO. Release steps are
			// never attempted after a cgroup/helper setup failure.
			releaseSteps := []preExecReleaseStep{{name: "ptrace resume", run: resume}}
			if extra.ptraceSync {
				releaseSteps = append(releaseSteps, preExecReleaseStep{
					name: "hybrid GO byte write",
					run: func() error {
						return writePreExecControlByte(extra.notifyParentSock, 'G')
					},
				})
			}
			if releaseErr := barrier.Release(cmd.Process.Pid, releaseSteps...); releaseErr != nil {
				close(ptraceDone)
				handlerCancel()
				_ = killProcess(cmd.Process.Pid)
				_ = killProcessGroup(pgid)
				_ = waitExit()
				pipeWG.Wait()
				cmd.Process.Release()
				return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, releaseErr
			}

			notifyStarted()
			// 7. Wait for exit via ptrace exit channel
			waitStart := time.Now()
			slog.Debug("exec_stream waiting for command (hybrid)", "command", req.Command, "pid", cmd.Process.Pid)
			result := waitExit()
			close(ptraceDone)
			handlerCancel()
			if result.err != nil {
				_ = killProcess(cmd.Process.Pid)
				_ = killProcessGroup(pgid)
			}
			waitDuration := time.Since(waitStart)
			slog.Debug("exec_stream command finished (hybrid)", "command", req.Command, "pid", cmd.Process.Pid, "exit_code", result.exitCode, "wait_duration_ms", waitDuration.Milliseconds())
			pipeWG.Wait()
			stdout, stderr = stdoutW.Bytes(), stderrW.Bytes()
			stdoutTotal, stderrTotal = stdoutW.total, stderrW.total
			stdoutTrunc, stderrTrunc = stdoutW.truncated, stderrW.truncated
			resources = result.resources
			cmd.Process.Release()

			if ctx.Err() != nil {
				_ = killProcessGroup(pgid)
			}
			if commandTimedOut(ctx) {
				return 124, stdout, append(stderr, []byte("command timed out\n")...), stdoutTotal, stderrTotal + int64(len("command timed out\n")), true, true, resources, errCommandTimeout
			}
			if ctx.Err() != nil {
				return 127, stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, resources, ctx.Err()
			}
			return result.exitCode, stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, resources, result.err
		} else if tracer != nil {
			// FULL PTRACE MODE: ptrace handles everything (no seccomp wrapper).
			// Context cancellation watcher: start BEFORE attach
			ptraceDone := make(chan struct{})
			go func() {
				select {
				case <-ctx.Done():
					_ = killProcessGroup(pgid)
					_ = killProcess(cmd.Process.Pid)
				case <-ptraceDone:
				}
			}()

			waitExit, resume, attachErr := ptraceExecAttach(tracer, cmd.Process.Pid, sessionID, cmdID, hook != nil)
			if attachErr != nil {
				close(ptraceDone)
				_ = killProcess(cmd.Process.Pid)
				_ = killProcessGroup(pgid)
				pipeWG.Wait()
				cmd.Process.Release()
				return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, fmt.Errorf("ptrace attach: %w", attachErr)
			}
			if releaseErr := barrier.Release(cmd.Process.Pid, preExecReleaseStep{name: "ptrace resume", run: resume}); releaseErr != nil {
				close(ptraceDone)
				_ = killProcess(cmd.Process.Pid)
				_ = killProcessGroup(pgid)
				_ = waitExit()
				pipeWG.Wait()
				cmd.Process.Release()
				return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, releaseErr
			}

			notifyStarted()
			// Tracer-managed wait: block on exit channel instead of cmd.Wait()
			waitStart := time.Now()
			slog.Debug("exec_stream waiting for command (ptrace)", "command", req.Command, "pid", cmd.Process.Pid)
			result := waitExit()
			close(ptraceDone)
			if result.err != nil {
				_ = killProcess(cmd.Process.Pid)
				_ = killProcessGroup(pgid)
			}
			waitDuration := time.Since(waitStart)
			slog.Debug("exec_stream command finished (ptrace)", "command", req.Command, "pid", cmd.Process.Pid, "exit_code", result.exitCode, "wait_duration_ms", waitDuration.Milliseconds())
			pipeWG.Wait() // drain pipes before reading capture writers
			stdout, stderr = stdoutW.Bytes(), stderrW.Bytes()
			stdoutTotal, stderrTotal = stdoutW.total, stderrW.total
			stdoutTrunc, stderrTrunc = stdoutW.truncated, stderrW.truncated
			resources = result.resources
			cmd.Process.Release()

			if ctx.Err() != nil {
				_ = killProcessGroup(pgid)
			}
			if commandTimedOut(ctx) {
				return 124, stdout, append(stderr, []byte("command timed out\n")...), stdoutTotal, stderrTotal + int64(len("command timed out\n")), true, true, resources, errCommandTimeout
			}
			if ctx.Err() != nil {
				return 127, stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, resources, ctx.Err()
			}
			return result.exitCode, stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, resources, result.err
		} else if hook != nil {
			releaseSteps := make([]preExecReleaseStep, 0, 3)
			if !commandBoundaryRequired(extra) {
				releaseSteps = append(releaseSteps, preExecReleaseStep{name: "resume traced process", run: func() error {
					return resumeTracedProcess(cmd.Process.Pid)
				}})
			}
			releaseSteps = append(releaseSteps, commandBoundaryReleaseSteps(ctx, extra, commandBoundaryReady)...)
			if releaseErr := barrier.Release(cmd.Process.Pid, releaseSteps...); releaseErr != nil {
				releaseErr = finalizeCommandBoundaryFailure(cmd, pgid, barrier, handlerLifecycle, releaseErr)
				return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, releaseErr
			}
		}

		notifyStarted()
		if !wrapperHandlersStarted {
			handlerLifecycle = startWrapperHandlers(ctx, extra, cmd.Process.Pid, pgid, nil)
			extraOwnershipTransferred = true
		}
	}

	if extra == nil {
		notifyStarted()
	}
	waitStart := time.Now()
	waitErr := cmd.Wait()
	waitDuration := time.Since(waitStart)
	slog.Debug("exec_stream command finished", "command", req.Command, "pid", cmd.Process.Pid, "wait_error", waitErr, "ctx_err", ctx.Err(), "wait_duration_ms", waitDuration.Milliseconds())
	stdout, stderr = stdoutW.Bytes(), stderrW.Bytes()
	stdoutTotal, stderrTotal = stdoutW.total, stderrW.total
	stdoutTrunc, stderrTrunc = stdoutW.truncated, stderrW.truncated

	resources = resourcesFromProcessState(cmd.ProcessState)

	if ctx.Err() != nil {
		_ = killProcessGroup(pgid)
	}

	if commandTimedOut(ctx) {
		return 124, stdout, append(stderr, []byte("command timed out\n")...), stdoutTotal, stderrTotal + int64(len("command timed out\n")), true, true, resources, errCommandTimeout
	}
	if ctx.Err() != nil {
		return 127, stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, resources, ctx.Err()
	}
	if waitErr == nil {
		return 0, stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, resources, err
	}
	if ee := (*exec.ExitError)(nil); errors.As(waitErr, &ee) {
		return ee.ExitCode(), stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, resources, err
	}
	return 127, stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, resources, waitErr
}

func writeSSE(w io.Writer, flusher http.Flusher, event string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if event != "" {
		if _, err := fmt.Fprintf(w, "event: %s\n", event); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", strings.TrimSpace(string(b))); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}
