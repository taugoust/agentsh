package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/agentsh/agentsh/pkg/types"
	"google.golang.org/grpc/codes"
)

func normalizeExecOutcome(started bool, exitCode int, err error) *types.ExecOutcome {
	o := &types.ExecOutcome{CommandStarted: started, DispatchState: "started", FailureKind: types.ExecFailureNone}
	if !started {
		o.DispatchState = "not_dispatched"
	}
	if err == nil {
		if started && exitCode != 0 {
			o.FailureKind = types.ExecFailureChildExit
			o.Code = "E_CHILD_EXIT"
		}
		return o
	}
	o.Message = err.Error()
	var enforcement *preExecEnforcementError
	var validation *commandPreStartError
	var start *commandStartError
	switch {
	case errors.As(err, &enforcement):
		o.Code, o.FailureKind, o.DispatchState = enforcement.code, types.ExecFailurePreExec, "pre_exec_refused"
	case errors.As(err, &validation):
		o.Code, o.FailureKind, o.DispatchState = validation.code, types.ExecFailureValidation, "pre_start_refused"
	case errors.As(err, &start):
		o.Code, o.FailureKind, o.DispatchState = "E_COMMAND_START", types.ExecFailureStart, "start_failed"
	case errors.Is(err, context.DeadlineExceeded):
		o.Code, o.FailureKind = "E_COMMAND_TIMEOUT", types.ExecFailureCommandTimeout
	case errors.Is(err, context.Canceled):
		o.Code, o.FailureKind = "E_CALLER_CANCELLED", types.ExecFailureCancellation
	default:
		o.Code, o.FailureKind = "E_COMMAND_FAILED", types.ExecFailureInternal
	}
	if jailFailure := commandJailFailureFrom(err); jailFailure != nil {
		o.Code = jailFailure.code()
		applyCommandAttemptDiagnostics(o, 1, []types.ExecAttemptDiagnostic{jailFailure.diagnostic(1)})
	}
	return o
}

func execFailureHTTPStatus(o *types.ExecOutcome) int {
	if o == nil {
		return http.StatusInternalServerError
	}
	switch o.FailureKind {
	case types.ExecFailurePreExec:
		return http.StatusServiceUnavailable
	case types.ExecFailureValidation:
		return http.StatusBadRequest
	case types.ExecFailureStart:
		return http.StatusUnprocessableEntity
	case types.ExecFailureCancellation, types.ExecFailureQueueTimeout:
		return http.StatusRequestTimeout
	default:
		return http.StatusInternalServerError
	}
}

func grpcCodeForOutcome(o *types.ExecOutcome) codes.Code {
	if o == nil {
		return codes.Internal
	}
	switch o.FailureKind {
	case types.ExecFailurePreExec:
		return codes.FailedPrecondition
	case types.ExecFailureValidation, types.ExecFailureStart:
		return codes.InvalidArgument
	case types.ExecFailureCancellation:
		return codes.Canceled
	case types.ExecFailureQueueTimeout:
		return codes.DeadlineExceeded
	default:
		return codes.Internal
	}
}
