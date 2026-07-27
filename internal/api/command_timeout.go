package api

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/commandtimeout"
	"github.com/agentsh/agentsh/pkg/types"
)

var errCommandTimeout = errors.New("command timed out")

const terminalPersistenceTimeout = 5 * time.Second

type commandTerminalState uint8

const (
	commandTerminalPending commandTerminalState = iota
	commandTerminalCompleted
	commandTerminalTimedOut
	commandTerminalParentCancelled
)

type commandTimeoutControllerKey struct{}

// commandTimeoutExtender serializes process completion, timer expiry, caller
// cancellation, and approval extensions under one mutex. The first positive
// extension fixes the cumulative extension cap; later extensions may not move
// the deadline past that cap.
type commandTimeoutExtender struct {
	mu sync.Mutex

	cancel          context.CancelCauseFunc
	parent          context.Context
	parentDeadline  time.Time
	parentStop      func() bool
	timer           *time.Timer
	initialDeadline time.Time
	deadline        time.Time
	maximumDeadline time.Time
	terminal        commandTerminalState
	stopped         bool
}

func withExtendableCommandTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	baseCtx, extender := newCommandTimeoutExtender(parent, timeout)
	ctx := approvals.WithCommandTimeoutExtension(baseCtx, extender.extend)
	return ctx, extender.cancelContext
}

func newCommandTimeoutExtender(parent context.Context, timeout time.Duration) (context.Context, *commandTimeoutExtender) {
	if parent == nil {
		parent = context.Background()
	}
	// Preserve request values without inheriting cancellation directly. Parent
	// cancellation is arbitrated explicitly against process completion and the
	// command deadline below, so a cancellation that arrives during post-exit
	// cleanup cannot rewrite a completed process result.
	baseCtx, cancelCause := context.WithCancelCause(context.WithoutCancel(parent))
	extender := &commandTimeoutExtender{cancel: cancelCause, parent: parent}
	if deadline, ok := parent.Deadline(); ok {
		extender.parentDeadline = deadline
	}
	if timeout > 0 {
		extender.initialDeadline = time.Now().Add(timeout)
		extender.deadline = extender.initialDeadline
	}

	// Hold the mutex until callbacks are installed. Even an unusually short
	// timeout or an already-cancelled parent therefore sees complete state.
	extender.mu.Lock()
	if timeout > 0 {
		extender.timer = time.AfterFunc(timeout, extender.expire)
	}
	extender.parentStop = context.AfterFunc(parent, extender.cancelFromParent)
	extender.mu.Unlock()
	return context.WithValue(baseCtx, commandTimeoutControllerKey{}, extender), extender
}

func (e *commandTimeoutExtender) expire() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.expireLocked(time.Now())
}

func (e *commandTimeoutExtender) cancelFromParent() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return
	}
	now := time.Now()
	cause := context.Cause(e.parent)
	if cause == nil {
		cause = e.parent.Err()
	}
	if e.timeoutWinsOverParentLocked(now, cause) {
		e.finishLocked(commandTerminalTimedOut, errCommandTimeout)
		return
	}
	e.finishLocked(commandTerminalParentCancelled, cause)
}

func (e *commandTimeoutExtender) timeoutWinsOverParentLocked(now time.Time, parentCause error) bool {
	if e.deadline.IsZero() || now.Before(e.deadline) {
		return false
	}
	// A manual cancellation has no trustworthy timestamp. If it is already
	// observable when arbitration acquires the mutex, preserve it. Deadline
	// causes can be ordered exactly using their published deadlines.
	if !errors.Is(parentCause, context.DeadlineExceeded) || e.parentDeadline.IsZero() {
		return false
	}
	return !e.deadline.After(e.parentDeadline)
}

// expireLocked returns true when this call wins expiry. A stale callback from
// the pre-extension timer only reschedules against the current deadline.
func (e *commandTimeoutExtender) expireLocked(now time.Time) bool {
	if e.stopped || e.deadline.IsZero() {
		return false
	}
	if now.Before(e.deadline) {
		e.timer.Reset(time.Until(e.deadline))
		return false
	}
	if e.parent != nil && e.parent.Err() != nil {
		cause := context.Cause(e.parent)
		if cause == nil {
			cause = e.parent.Err()
		}
		if !e.timeoutWinsOverParentLocked(now, cause) {
			e.finishLocked(commandTerminalParentCancelled, cause)
			return false
		}
	}
	e.finishLocked(commandTerminalTimedOut, errCommandTimeout)
	return true
}

func (e *commandTimeoutExtender) extend(extra time.Duration) {
	if extra <= 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.extendLocked(extra, time.Now())
}

// extendLocked returns whether the extension was accepted. The first accepted
// extension sets the one-command cap to initial deadline plus its allowance.
func (e *commandTimeoutExtender) extendLocked(extra time.Duration, now time.Time) bool {
	if extra <= 0 || e.stopped || e.deadline.IsZero() {
		return false
	}
	if e.parent != nil && e.parent.Err() != nil {
		cause := context.Cause(e.parent)
		if cause == nil {
			cause = e.parent.Err()
		}
		if e.timeoutWinsOverParentLocked(now, cause) {
			e.finishLocked(commandTerminalTimedOut, errCommandTimeout)
		} else {
			e.finishLocked(commandTerminalParentCancelled, cause)
		}
		return false
	}
	if !now.Before(e.deadline) {
		e.finishLocked(commandTerminalTimedOut, errCommandTimeout)
		return false
	}

	if e.maximumDeadline.IsZero() {
		e.maximumDeadline = e.initialDeadline.Add(extra)
	}
	deadline := e.deadline.Add(extra)
	if deadline.After(e.maximumDeadline) {
		deadline = e.maximumDeadline
	}
	e.deadline = deadline
	// time.AfterFunc timers have no channel to drain. Reset is safe here even
	// if an old callback has started: that callback must acquire this mutex and
	// will re-check the updated deadline before it can expire the context.
	e.timer.Reset(time.Until(e.deadline))
	return true
}

// complete atomically establishes the process-completion winner. It compares
// the observed completion time with the effective deadline even if the timer
// callback itself was delayed by scheduling.
func (e *commandTimeoutExtender) complete(now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return e.terminal == commandTerminalCompleted
	}
	if now.IsZero() {
		now = time.Now()
	}
	if e.parent != nil && e.parent.Err() != nil {
		cause := context.Cause(e.parent)
		if cause == nil {
			cause = e.parent.Err()
		}
		if e.timeoutWinsOverParentLocked(now, cause) {
			e.finishLocked(commandTerminalTimedOut, errCommandTimeout)
		} else {
			e.finishLocked(commandTerminalParentCancelled, cause)
		}
		return false
	}
	if !e.deadline.IsZero() && !now.Before(e.deadline) {
		e.finishLocked(commandTerminalTimedOut, errCommandTimeout)
		return false
	}
	e.finishLocked(commandTerminalCompleted, nil)
	return true
}

func (e *commandTimeoutExtender) cancelContext() {
	e.mu.Lock()
	if !e.stopped {
		e.finishLocked(commandTerminalCompleted, nil)
	}
	e.mu.Unlock()
	// Release any context waiters only after runner-owned cancellation watchers
	// and cleanup defers have stopped. A prior timeout/parent cause wins.
	e.cancel(context.Canceled)
}

func (e *commandTimeoutExtender) finishLocked(state commandTerminalState, cause error) {
	if e.stopped {
		return
	}
	e.stopped = true
	e.terminal = state
	if e.timer != nil {
		// A false result means the callback has fired or is running. It still
		// has to acquire mu and will observe stopped before doing any work.
		e.timer.Stop()
	}
	if e.parentStop != nil {
		e.parentStop()
	}
	if state != commandTerminalCompleted {
		if cause == nil {
			cause = context.Canceled
		}
		e.cancel(cause)
	}
}

func commandTimeoutController(ctx context.Context) *commandTimeoutExtender {
	if ctx == nil {
		return nil
	}
	controller, _ := ctx.Value(commandTimeoutControllerKey{}).(*commandTimeoutExtender)
	return controller
}

func completeCommandExecution(ctx context.Context, at time.Time) bool {
	controller := commandTimeoutController(ctx)
	if controller == nil {
		return true
	}
	return controller.complete(at)
}

func commandContextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return ctx.Err()
}

func commandTimedOut(ctx context.Context) bool {
	if controller := commandTimeoutController(ctx); controller != nil {
		controller.mu.Lock()
		timedOut := controller.terminal == commandTerminalTimedOut
		controller.mu.Unlock()
		if timedOut {
			return true
		}
	}
	return errors.Is(context.Cause(ctx), errCommandTimeout)
}

func parseCommandTimeout(req types.ExecRequest) (commandtimeout.ParsedRequest, error) {
	if req.Timeout == "" {
		return commandtimeout.ParseRequest(nil)
	}
	return commandtimeout.ParseRequest(&req.Timeout)
}

func resolveParsedCommandTimeout(requested commandtimeout.ParsedRequest, policyLimit time.Duration) commandtimeout.Resolution {
	return commandtimeout.ResolveParsed(requested, policyLimit)
}

func resolveCommandTimeout(req types.ExecRequest, policyLimit time.Duration) (commandtimeout.Resolution, error) {
	requested, err := parseCommandTimeout(req)
	if err != nil {
		return commandtimeout.Resolution{}, err
	}
	return resolveParsedCommandTimeout(requested, policyLimit), nil
}

func (a *App) resolveParsedCommandTimeout(requested commandtimeout.ParsedRequest, policyLimit time.Duration) commandtimeout.Resolution {
	resolution := resolveParsedCommandTimeout(requested, policyLimit)
	resolution.Metadata.ApprovalExtensionMS = approvalExtensionMilliseconds(a.approvals)
	return resolution
}

func (a *App) resolveCommandTimeout(req types.ExecRequest, policyLimit time.Duration) (commandtimeout.Resolution, error) {
	requested, err := parseCommandTimeout(req)
	if err != nil {
		return commandtimeout.Resolution{}, err
	}
	return a.resolveParsedCommandTimeout(requested, policyLimit), nil
}

func approvalExtensionMilliseconds(manager *approvals.Manager) int64 {
	if manager == nil {
		return 0
	}
	allowance := manager.CommandTimeoutExtensionAllowance()
	if allowance <= 0 {
		return 0
	}
	return commandtimeout.CeilMilliseconds(allowance)
}

func executionTermination(execErr error) (string, *types.ExecError) {
	if errors.Is(execErr, errCommandTimeout) {
		return types.TerminationReasonCommandTimeout, &types.ExecError{
			Code:    "E_COMMAND_TIMEOUT",
			Message: errCommandTimeout.Error(),
		}
	}
	if errors.Is(execErr, context.DeadlineExceeded) {
		return types.TerminationReasonCallerDeadline, executionFailure(execErr)
	}
	if errors.Is(execErr, context.Canceled) {
		return types.TerminationReasonCallerCancelled, executionFailure(execErr)
	}
	return "", executionFailure(execErr)
}

func executionFailure(execErr error) *types.ExecError {
	if execErr == nil {
		return nil
	}
	return &types.ExecError{Code: "E_COMMAND_FAILED", Message: execErr.Error()}
}

func terminalPersistenceContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(parent), terminalPersistenceTimeout)
}
