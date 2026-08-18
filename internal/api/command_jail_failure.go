package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

const (
	commandJailStageReadyWait = "command_jail_ready_wait"
	commandJailStageGOWrite   = "command_jail_go_write"
)

// commandJailFailure carries machine-checkable protocol and cleanup evidence.
// Retry decisions must use these fields rather than parsing Error strings or
// compatibility exit code 127.
type commandJailFailure struct {
	mu sync.Mutex

	stage       string
	readyBytes  int
	readErr     error
	goAttempted bool

	wrapperExitCode *int
	wrapperSignal   string
	wrapperLogTail  string
	processReaped   bool
	handlersJoined  bool
	cleanupComplete bool
	cleanupErr      error
}

func newCommandJailReadyFailure(n int, err error) *commandJailFailure {
	return &commandJailFailure{
		stage:      commandJailStageReadyWait,
		readyBytes: n,
		readErr:    err,
	}
}

func newCommandJailGOFailure(err error) *commandJailFailure {
	return &commandJailFailure{
		stage:       commandJailStageGOWrite,
		readErr:     err,
		goAttempted: true,
	}
}

func (e *commandJailFailure) Error() string {
	if e == nil {
		return "command-jail protocol failure"
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	var message string
	switch e.stage {
	case commandJailStageReadyWait:
		message = fmt.Sprintf("command-jail READY failed before GO: read %d byte(s)", e.readyBytes)
	case commandJailStageGOWrite:
		message = "command-jail GO write failed after dispatch became ambiguous"
	default:
		message = "command-jail protocol failure"
	}
	if e.readErr != nil {
		message += ": " + e.readErr.Error()
	}
	if e.wrapperExitCode != nil {
		message += fmt.Sprintf("; wrapper exit=%d", *e.wrapperExitCode)
	} else if e.wrapperSignal != "" {
		message += "; wrapper signal=" + e.wrapperSignal
	}
	if e.wrapperLogTail != "" {
		message += "; wrapper diagnostic=" + e.wrapperLogTail
	}
	if e.cleanupErr != nil {
		message += "; cleanup failed=" + e.cleanupErr.Error()
	}
	return message
}

func (e *commandJailFailure) Unwrap() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.readErr
}

func (e *commandJailFailure) code() string {
	if e == nil {
		return "E_PRE_EXEC_RELEASE"
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stage == commandJailStageReadyWait {
		return "E_COMMAND_JAIL_READY"
	}
	if e.stage == commandJailStageGOWrite {
		return "E_COMMAND_JAIL_GO"
	}
	return "E_PRE_EXEC_RELEASE"
}

func (e *commandJailFailure) finalize(exitCode *int, signal, logTail string, processReaped, handlersJoined bool, cleanupErr error) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.wrapperExitCode = exitCode
	e.wrapperSignal = signal
	e.wrapperLogTail = strings.TrimSpace(logTail)
	e.processReaped = processReaped
	e.handlersJoined = handlersJoined
	e.cleanupErr = cleanupErr
	e.cleanupComplete = processReaped && handlersJoined && cleanupErr == nil
}

func (e *commandJailFailure) observedReadyEOF() bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stage == commandJailStageReadyWait && e.readyBytes == 0 && errors.Is(e.readErr, io.EOF) && !e.goAttempted
}

func (e *commandJailFailure) provenCleanPreGO() bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stage == commandJailStageReadyWait && !e.goAttempted && e.processReaped && e.handlersJoined && e.cleanupComplete
}

// boundaryCleanupComplete reports only whether the failed attempt left any
// process, handler, helper, eBPF, or cgroup resource behind. A GO write remains
// dispatch-ambiguous and is never retryable, but complete teardown means the
// session-scoped preflight is still valid for a later, independently admitted
// command.
func (e *commandJailFailure) boundaryCleanupComplete() bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.processReaped && e.handlersJoined && e.cleanupComplete
}

func (e *commandJailFailure) retryableReadyEOF(ctx context.Context) bool {
	if e == nil || (ctx != nil && ctx.Err() != nil) {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stage == commandJailStageReadyWait &&
		e.readyBytes == 0 && errors.Is(e.readErr, io.EOF) && !e.goAttempted &&
		e.processReaped && e.handlersJoined && e.cleanupComplete
}

func (e *commandJailFailure) diagnostic(attempt int) types.ExecAttemptDiagnostic {
	d := types.ExecAttemptDiagnostic{Attempt: attempt}
	if e == nil {
		return d
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	d.ProtocolStage = e.stage
	d.ReadyBytes = e.readyBytes
	if e.readErr != nil {
		d.ReadError = e.readErr.Error()
	}
	d.GOAttempted = e.goAttempted
	d.WrapperExitCode = e.wrapperExitCode
	d.WrapperSignal = e.wrapperSignal
	d.WrapperLogTail = e.wrapperLogTail
	d.ProcessReaped = e.processReaped
	d.HandlersJoined = e.handlersJoined
	d.CleanupComplete = e.cleanupComplete
	if e.cleanupErr != nil {
		d.CleanupError = e.cleanupErr.Error()
	}
	return d
}

func commandJailFailureFrom(err error) *commandJailFailure {
	var failure *commandJailFailure
	if errors.As(err, &failure) {
		return failure
	}
	return nil
}

func shouldRetryCommandJailAttempt(ctx context.Context, attempt int, err error) bool {
	if attempt != 1 {
		return false
	}
	failure := commandJailFailureFrom(err)
	return failure != nil && failure.retryableReadyEOF(ctx)
}

func (a *App) emitCommandJailAttempt(sessionID, commandID string, diagnostic types.ExecAttemptDiagnostic, retrying bool) {
	if a == nil {
		return
	}
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "command_jail_attempt_failed",
		SessionID: sessionID,
		CommandID: commandID,
		Fields: map[string]any{
			"attempt":           diagnostic.Attempt,
			"protocol_stage":    diagnostic.ProtocolStage,
			"ready_bytes":       diagnostic.ReadyBytes,
			"read_error":        diagnostic.ReadError,
			"go_attempted":      diagnostic.GOAttempted,
			"wrapper_exit_code": diagnostic.WrapperExitCode,
			"wrapper_signal":    diagnostic.WrapperSignal,
			"wrapper_log_tail":  diagnostic.WrapperLogTail,
			"process_reaped":    diagnostic.ProcessReaped,
			"handlers_joined":   diagnostic.HandlersJoined,
			"cleanup_complete":  diagnostic.CleanupComplete,
			"cleanup_error":     diagnostic.CleanupError,
			"retrying":          retrying,
		},
	}
	if a.store != nil {
		_ = a.store.AppendEvent(context.Background(), ev)
	}
	if a.broker != nil {
		a.broker.Publish(ev)
	}
}

func applyCommandAttemptDiagnostics(outcome *types.ExecOutcome, attemptCount int, attempts []types.ExecAttemptDiagnostic) {
	if outcome == nil {
		return
	}
	outcome.AttemptCount = attemptCount
	if len(attempts) > 0 {
		outcome.Attempts = append([]types.ExecAttemptDiagnostic(nil), attempts...)
	}
}
