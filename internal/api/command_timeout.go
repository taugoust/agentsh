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

// commandTimeoutExtender serializes timer expiry and approval extensions under
// one mutex. The first positive extension fixes the cumulative extension cap;
// later extensions may not move the deadline past that cap.
type commandTimeoutExtender struct {
	mu sync.Mutex

	cancel          context.CancelCauseFunc
	timer           *time.Timer
	initialDeadline time.Time
	deadline        time.Time
	maximumDeadline time.Time
	stopped         bool
}

func withExtendableCommandTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		ctx, cancel := context.WithCancel(parent)
		return approvals.WithCommandTimeoutExtension(ctx, func(time.Duration) {}), cancel
	}

	baseCtx, extender := newCommandTimeoutExtender(parent, timeout)
	ctx := approvals.WithCommandTimeoutExtension(baseCtx, extender.extend)
	return ctx, extender.cancelContext
}

func newCommandTimeoutExtender(parent context.Context, timeout time.Duration) (context.Context, *commandTimeoutExtender) {
	baseCtx, cancelCause := context.WithCancelCause(parent)
	initialDeadline := time.Now().Add(timeout)
	extender := &commandTimeoutExtender{
		cancel:          cancelCause,
		initialDeadline: initialDeadline,
		deadline:        initialDeadline,
	}

	// Hold the mutex until timer assignment is complete. Even an unusually
	// short timeout therefore cannot run its callback against a nil timer.
	extender.mu.Lock()
	extender.timer = time.AfterFunc(timeout, extender.expire)
	extender.mu.Unlock()
	return baseCtx, extender
}

func (e *commandTimeoutExtender) expire() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.expireLocked(time.Now())
}

// expireLocked returns true when this call wins expiry. A stale callback from
// the pre-extension timer only reschedules against the current deadline.
func (e *commandTimeoutExtender) expireLocked(now time.Time) bool {
	if e.stopped {
		return false
	}
	if now.Before(e.deadline) {
		e.timer.Reset(time.Until(e.deadline))
		return false
	}

	e.stopLocked()
	// Cancel while still holding the mutex so an extension that loses the
	// deadline race observes errCommandTimeout before it returns.
	e.cancel(errCommandTimeout)
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
	if extra <= 0 || e.stopped {
		return false
	}
	if !now.Before(e.deadline) {
		e.stopLocked()
		e.cancel(errCommandTimeout)
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

func (e *commandTimeoutExtender) cancelContext() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopLocked()
	e.cancel(context.Canceled)
}

func (e *commandTimeoutExtender) stopLocked() {
	if e.stopped {
		return
	}
	e.stopped = true
	if e.timer != nil {
		// A false result means the callback has fired or is running. It still
		// has to acquire mu and will observe stopped before doing any work.
		e.timer.Stop()
	}
}

func commandTimedOut(ctx context.Context) bool {
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
