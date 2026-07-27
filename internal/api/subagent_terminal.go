package api

import (
	"context"
	"errors"
	"regexp"
	"strings"
)

type subagentTerminalState string

type subagentFailureKind string

type subagentCancellationCause string

type subagentTermination string

const (
	subagentStateCompleted subagentTerminalState = "completed"
	subagentStateFailed    subagentTerminalState = "failed"
	subagentStateCancelled subagentTerminalState = "cancelled"
	subagentStateTimedOut  subagentTerminalState = "timed_out"

	subagentFailureAuth          subagentFailureKind = "auth"
	subagentFailureModel         subagentFailureKind = "model"
	subagentFailureCompaction    subagentFailureKind = "compaction"
	subagentFailureProtocol      subagentFailureKind = "protocol"
	subagentFailureTransport     subagentFailureKind = "transport"
	subagentFailureProcess       subagentFailureKind = "process"
	subagentFailureConfiguration subagentFailureKind = "configuration"
	subagentFailureUnknown       subagentFailureKind = "unknown"

	subagentCancelUser               subagentCancellationCause = "user_cancelled"
	subagentCancelChildTimeout       subagentCancellationCause = "child_timeout"
	subagentCancelRequestTimeout     subagentCancellationCause = "request_timeout"
	subagentCancelParent             subagentCancellationCause = "parent_cancelled"
	subagentCancelClientDisconnected subagentCancellationCause = "client_disconnected"
	subagentCancelSupervisorShutdown subagentCancellationCause = "supervisor_shutdown"
	subagentCancelSupervisorRestart  subagentCancellationCause = "supervisor_restart"

	subagentTerminationNatural  subagentTermination = "natural"
	subagentTerminationGraceful subagentTermination = "graceful"
	subagentTerminationForced   subagentTermination = "forced"
)

var (
	errSubagentRequestTimeout     = errors.New("subagent request timeout")
	errSubagentUserCancelled      = errors.New("subagent cancelled by user")
	errSubagentParentCancelled    = errors.New("subagent cancelled by parent")
	errSubagentClientDisconnected = errors.New("subagent client disconnected")
	errSubagentSupervisorShutdown = errors.New("subagent supervisor is shutting down")
	errSubagentRequestComplete    = errors.New("subagent request complete")
)

var (
	subagentBearerPattern = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+`)
	subagentSecretPattern = regexp.MustCompile(`(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|cookie|password|passwd|secret)\b\s*[:=]\s*[^\s,;]+`)
)

type subagentTerminal struct {
	State                      subagentTerminalState     `json:"state"`
	FailureKind                subagentFailureKind       `json:"failure_kind,omitempty"`
	CancellationCause          subagentCancellationCause `json:"cancellation_cause,omitempty"`
	ExitCode                   int                       `json:"exit_code,omitempty"`
	Signal                     string                    `json:"signal,omitempty"`
	Termination                subagentTermination       `json:"termination,omitempty"`
	Retryable                  bool                      `json:"retryable"`
	SideEffectsMayHaveOccurred bool                      `json:"side_effects_may_have_occurred,omitempty"`
	Message                    string                    `json:"message,omitempty"`
}

func sanitizeSubagentDiagnostic(message string) string {
	message = strings.TrimSpace(message)
	message = subagentBearerPattern.ReplaceAllString(message, "Bearer [redacted]")
	message = subagentSecretPattern.ReplaceAllString(message, "$1=[redacted]")
	return truncateString(message, 2000)
}

func completedSubagentTerminal(exitCode int, termination subagentTermination) subagentTerminal {
	if termination == "" {
		termination = subagentTerminationNatural
	}
	return subagentTerminal{
		State:       subagentStateCompleted,
		ExitCode:    exitCode,
		Termination: termination,
		Retryable:   false,
	}
}

func failedSubagentTerminal(kind subagentFailureKind, exitCode int, signal string, termination subagentTermination, retryable bool, message string) subagentTerminal {
	if kind == "" {
		kind = subagentFailureUnknown
	}
	if termination == "" {
		termination = subagentTerminationNatural
	}
	return subagentTerminal{
		State:       subagentStateFailed,
		FailureKind: kind,
		ExitCode:    exitCode,
		Signal:      signal,
		Termination: termination,
		Retryable:   retryable,
		Message:     sanitizeSubagentDiagnostic(message),
	}
}

func subagentCancellationExitCode(ctx context.Context) int {
	if errors.Is(context.Cause(ctx), errSubagentRequestTimeout) || errors.Is(context.Cause(ctx), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return 124
	}
	return 130
}

func subagentCancellationFromContext(ctx context.Context) (subagentTerminalState, subagentFailureKind, subagentCancellationCause, string) {
	cause := context.Cause(ctx)
	switch {
	case errors.Is(cause, errSubagentRequestTimeout), errors.Is(cause, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
		return subagentStateTimedOut, subagentFailureProcess, subagentCancelRequestTimeout, "subagent request timed out"
	case errors.Is(cause, errSubagentUserCancelled):
		return subagentStateCancelled, "", subagentCancelUser, "subagent was cancelled by the user"
	case errors.Is(cause, errSubagentParentCancelled):
		return subagentStateCancelled, "", subagentCancelParent, "subagent was cancelled by its parent"
	case errors.Is(cause, errSubagentSupervisorShutdown):
		return subagentStateCancelled, subagentFailureProcess, subagentCancelSupervisorShutdown, "subagent was cancelled because the supervisor is shutting down"
	default:
		return subagentStateCancelled, subagentFailureTransport, subagentCancelClientDisconnected, "subagent client disconnected"
	}
}

func cancelledSubagentTerminal(ctx context.Context, exitCode int, signal string, termination subagentTermination, processStarted bool) subagentTerminal {
	state, failureKind, cancellationCause, message := subagentCancellationFromContext(ctx)
	return subagentTerminal{
		State:                      state,
		FailureKind:                failureKind,
		CancellationCause:          cancellationCause,
		ExitCode:                   exitCode,
		Signal:                     signal,
		Termination:                termination,
		Retryable:                  !processStarted,
		SideEffectsMayHaveOccurred: processStarted,
		Message:                    message,
	}
}

func subagentStopReason(terminal subagentTerminal) string {
	switch terminal.State {
	case subagentStateCompleted:
		return "completed"
	case subagentStateTimedOut:
		return "timeout"
	case subagentStateCancelled:
		return "cancelled"
	default:
		return "error"
	}
}

func setSubagentTerminal(result *subagentResult, terminal subagentTerminal) {
	if result == nil {
		return
	}
	result.Terminal = terminal
	result.ExitCode = terminal.ExitCode
	result.StopReason = subagentStopReason(terminal)
	if result.Error == "" && terminal.Message != "" && terminal.State != subagentStateCompleted {
		result.Error = terminal.Message
	}
}

func subagentResultFailed(result subagentResult) bool {
	return result.Terminal.State != "" && result.Terminal.State != subagentStateCompleted
}

func aggregateSubagentTerminal(results []subagentResult, fallbackError error) subagentTerminal {
	if len(results) == 0 {
		if fallbackError == nil {
			return completedSubagentTerminal(0, subagentTerminationNatural)
		}
		return failedSubagentTerminal(subagentFailureUnknown, 1, "", subagentTerminationNatural, true, fallbackError.Error())
	}
	for _, state := range []subagentTerminalState{subagentStateTimedOut, subagentStateCancelled, subagentStateFailed} {
		for _, result := range results {
			if result.Terminal.State == state {
				return result.Terminal
			}
		}
	}
	return completedSubagentTerminal(0, subagentTerminationNatural)
}

func likelySubagentAuthFailure(values ...string) bool {
	text := strings.ToLower(strings.Join(values, "\n"))
	for _, marker := range []string{"authentication failed", "not authenticated", "not logged in", "unauthorized", "login required", "oauth"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}
