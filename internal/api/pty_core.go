package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/pty"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

type ptyStartParams struct {
	Command    string
	Args       []string
	Argv0      string
	WorkingDir string
	Env        map[string]string
	Rows       uint16
	Cols       uint16
}

type ptyRun struct {
	sessionID string
	unlock    func()

	cmdID   string
	started time.Time

	req ptyStartParams
	ps  *pty.Session
}

func (a *App) startPTY(ctx context.Context, sessionID string, req ptyStartParams) (*ptyRun, int, error) {
	if a == nil {
		return nil, http.StatusServiceUnavailable, errors.New("server not initialized")
	}
	if a.ptraceFailed.Load() {
		return nil, http.StatusServiceUnavailable, errors.New("ptrace tracer exited unexpectedly; refusing to execute commands without enforcement")
	}
	sess, ok := a.sessions.Get(sessionID)
	if !ok {
		return nil, http.StatusNotFound, errors.New("session not found")
	}
	if strings.TrimSpace(req.Command) == "" {
		return nil, http.StatusBadRequest, errors.New("command is required")
	}

	cmdID := "cmd-" + uuid.NewString()
	start := time.Now().UTC()
	unlock, admissionErr := sess.LockExecContext(ctx)
	if admissionErr != nil {
		return nil, http.StatusRequestTimeout, fmt.Errorf("PTY execution admission cancelled before dispatch: %w", admissionErr)
	}
	sess.SetCurrentCommandID(cmdID)

	pre := a.policyEngineFor(sess).CheckCommandWithExecve(req.Command, req.Args, a.execveEnforcementActive(), a.shellCOpaqueMode())
	redirected, originalCmd, originalArgs := applyCommandRedirect(&req.Command, &req.Args, pre)
	approvalErr := a.applyCommandApproval(ctx, sessionID, cmdID, originalCmd, originalArgs, nil, &pre)

	preEv := types.Event{
		ID:        uuid.NewString(),
		Timestamp: start,
		Type:      "command_policy",
		SessionID: sessionID,
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
	_ = a.store.AppendEvent(ctx, preEv)
	a.broker.Publish(preEv)

	if redirected && pre.Redirect != nil {
		redirEv := types.Event{
			ID:        uuid.NewString(),
			Timestamp: start,
			Type:      "command_redirected",
			SessionID: sessionID,
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
		_ = a.store.AppendEvent(ctx, redirEv)
		a.broker.Publish(redirEv)
	}

	if pre.EffectiveDecision == types.DecisionDeny {
		a.emitCommandDBBypassAttempt(ctx, sess, sessionID, cmdID, pre)
		defer unlock()
		msg := "command denied by policy"
		if pre.PolicyDecision == types.DecisionApprove {
			msg = "command denied (approval required)"
			if approvalErr != nil && strings.Contains(strings.ToLower(approvalErr.Error()), "timeout") {
				msg = "command denied (approval timed out)"
			}
		}
		return nil, http.StatusForbidden, fmt.Errorf("%s", msg)
	}

	// Record history like non-PTY exec (only for allowed commands).
	sess.RecordHistory(strings.TrimSpace(originalCmd + " " + strings.Join(originalArgs, " ")))

	workdir, err := resolveWorkingDir(sess, strings.TrimSpace(req.WorkingDir))
	if err != nil {
		defer unlock()
		return nil, http.StatusBadRequest, err
	}
	wrapperResult := a.setupSeccompWrapper(types.ExecRequest{
		Command:    req.Command,
		Args:       req.Args,
		Argv0:      req.Argv0,
		WorkingDir: req.WorkingDir,
		Env:        req.Env,
	}, sessionID, sess)
	if wrapperResult.setupErr != nil {
		a.recordNetworkEnforcementFailure(sessionID, cmdID, wrapperResult.setupErr)
		defer unlock()
		return nil, http.StatusServiceUnavailable, fmt.Errorf("pre-exec boundary unavailable: %w", wrapperResult.setupErr)
	}
	wrappedReq := wrapperResult.wrappedReq
	extraCfg := wrapperResult.extraCfg
	env, envErr := buildCommandEnvironment(a.cfg, policy.ResolvedEnvPolicy{}, os.Environ(), sess, wrappedReq.Env, extraCfg)
	if envErr != nil {
		defer unlock()
		closePreStartProcessFiles(extraCfg)
		return nil, http.StatusInternalServerError, fmt.Errorf("build PTY environment: %w", envErr)
	}

	rows := req.Rows
	cols := req.Cols
	if rows == 0 {
		rows = 24
	}
	if cols == 0 {
		cols = 80
	}

	limits := a.policyEngineFor(sess).Limits()
	hook := a.cgroupHook(sessionID, cmdID, limits)
	if barrierErr := validatePreExecBarrierPath(hook, nil, extraCfg); barrierErr != nil {
		a.recordNetworkEnforcementFailure(sessionID, cmdID, barrierErr)
		defer unlock()
		closePreStartProcessFiles(extraCfg)
		return nil, http.StatusServiceUnavailable, barrierErr
	}
	barrier := newPreExecBarrier(hook)
	extraOwnershipTransferred := false
	var preExec func(int, func() error) (func() error, error)
	if hook != nil {
		preExec = func(pid int, resume func() error) (func() error, error) {
			var ready chan error
			if commandBoundaryRequired(extraCfg) {
				ready = make(chan error, 1)
			}
			startWrapperHandlers(ctx, extraCfg, pid, getProcessGroupID(pid), ready)
			extraOwnershipTransferred = true
			releaseSteps := []preExecReleaseStep{{name: "resume stopped PTY process", run: resume}}
			releaseSteps = append(releaseSteps, commandBoundaryReleaseSteps(ctx, extraCfg, ready)...)
			return barrier.CleanupFunc(), barrier.Release(pid, releaseSteps...)
		}
	}

	var commandBoundary *types.LinuxCommandJailRequirements
	if extraCfg != nil {
		commandBoundary = extraCfg.commandBoundary
	}
	ps, err := pty.New().Start(ctx, pty.StartRequest{
		Command:         wrappedReq.Command,
		Args:            wrappedReq.Args,
		Argv0:           strings.TrimSpace(wrappedReq.Argv0),
		Dir:             workdir,
		Env:             env,
		ExtraFiles:      extraProcessFiles(extraCfg),
		CommandBoundary: commandBoundary,
		PreExec:         preExec,
		InitialSize: pty.Winsize{
			Rows: rows,
			Cols: cols,
		},
	})
	if err != nil {
		if commandBoundaryRequired(extraCfg) {
			a.recordNetworkEnforcementFailure(sessionID, cmdID, err)
		}
		defer unlock()
		if !extraOwnershipTransferred {
			closePreStartProcessFiles(extraCfg)
		}
		return nil, http.StatusInternalServerError, err
	}
	sess.SetCurrentProcessPID(ps.PID())
	if !extraOwnershipTransferred {
		startWrapperHandlers(ctx, extraCfg, ps.PID(), getProcessGroupID(ps.PID()), nil)
	}

	startEv := types.Event{
		ID:        uuid.NewString(),
		Timestamp: start,
		Type:      "command_started",
		SessionID: sessionID,
		CommandID: cmdID,
		Fields: map[string]any{
			"command": req.Command,
			"args":    req.Args,
		},
	}
	_ = a.store.AppendEvent(ctx, startEv)
	a.broker.Publish(startEv)

	return &ptyRun{
		sessionID: sessionID,
		unlock:    unlock,
		cmdID:     cmdID,
		started:   start,
		req:       req,
		ps:        ps,
	}, http.StatusOK, nil
}

func (a *App) finishPTY(ctx context.Context, run *ptyRun, exitCode int, started time.Time, err error, out []byte, outTotal int64, outTrunc bool) {
	if a == nil || run == nil {
		return
	}
	end := time.Now().UTC()
	outcome := normalizeExecOutcome(true, exitCode, err)
	endEv := types.Event{
		ID:        uuid.NewString(),
		Timestamp: end,
		Type:      "command_finished",
		SessionID: run.sessionID,
		CommandID: run.cmdID,
		Fields: map[string]any{
			"exit_code":       exitCode,
			"duration_ms":     int64(end.Sub(started).Milliseconds()),
			"command_started": outcome.CommandStarted,
			"dispatch_state":  outcome.DispatchState,
			"failure_kind":    outcome.FailureKind,
			"outcome_code":    outcome.Code,
		},
	}
	if err != nil {
		endEv.Fields["error"] = err.Error()
	}
	_ = a.store.AppendEvent(ctx, endEv)
	a.broker.Publish(endEv)

	// Best-effort store of PTY output as stdout.
	_ = a.store.SaveOutput(ctx, run.sessionID, run.cmdID, out, []byte{}, outTotal, 0, outTrunc, false)
}
