package api

import (
	"context"
	"errors"
	"io"
	"testing"
)

func TestCommandJailReadyEOFRetryRequiresCompleteCleanup(t *testing.T) {
	exitCode := 1
	failure := newCommandJailReadyFailure(0, io.EOF)
	failure.finalize(&exitCode, "", "command jail: stage=mount_propagation_private: operation not permitted", true, true, nil)

	if !failure.retryableReadyEOF(context.Background()) {
		t.Fatal("clean pre-GO READY EOF was not retryable")
	}
	if !failure.provenCleanPreGO() {
		t.Fatal("clean pre-GO failure was not classified as clean")
	}
	if shouldRecordNetworkEnforcementFailure(markPreExecEnforcementError(failure.code(), failure)) {
		t.Fatal("clean pre-GO wrapper failure would poison session readiness")
	}

	diagnostic := failure.diagnostic(1)
	if diagnostic.GOAttempted || !diagnostic.ProcessReaped || !diagnostic.HandlersJoined || !diagnostic.CleanupComplete {
		t.Fatalf("incomplete diagnostic: %+v", diagnostic)
	}
	if diagnostic.WrapperExitCode == nil || *diagnostic.WrapperExitCode != 1 {
		t.Fatalf("wrapper exit evidence = %v, want 1", diagnostic.WrapperExitCode)
	}
}

func TestCommandJailRetryControllerAllowsOnlyOneFreshAttempt(t *testing.T) {
	failure := newCommandJailReadyFailure(0, io.EOF)
	failure.finalize(nil, "SIGKILL", "", true, true, nil)
	err := markPreExecEnforcementError(failure.code(), failure)
	if !shouldRetryCommandJailAttempt(context.Background(), 1, err) {
		t.Fatal("first clean READY EOF did not permit the one retry")
	}
	if shouldRetryCommandJailAttempt(context.Background(), 2, err) {
		t.Fatal("second READY EOF permitted another retry")
	}
}

func TestCommandJailReadyEOFCleanupFailureIsStickyAndNotRetryable(t *testing.T) {
	cleanupErr := errors.New("injected helper cleanup failure")
	failure := newCommandJailReadyFailure(0, io.EOF)
	failure.finalize(nil, "SIGKILL", "", true, true, cleanupErr)
	wrapped := markPreExecEnforcementError(failure.code(), failure)

	if failure.retryableReadyEOF(context.Background()) {
		t.Fatal("READY EOF with failed cleanup was retryable")
	}
	if failure.provenCleanPreGO() {
		t.Fatal("READY EOF with failed cleanup was classified as clean")
	}
	if !shouldRecordNetworkEnforcementFailure(wrapped) {
		t.Fatal("helper cleanup failure was not sticky")
	}
}

func TestCommandJailReadyEOFDoesNotRetryAfterContextCancellation(t *testing.T) {
	failure := newCommandJailReadyFailure(0, io.EOF)
	failure.finalize(nil, "SIGKILL", "", true, true, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if failure.retryableReadyEOF(ctx) {
		t.Fatal("cancelled request was retryable")
	}
}

func TestCommandJailGOWriteFailureIsAmbiguousButDoesNotPoisonAfterCleanup(t *testing.T) {
	failure := newCommandJailGOFailure(io.ErrClosedPipe)
	failure.finalize(nil, "SIGKILL", "", true, true, nil)
	wrapped := markPreExecEnforcementError(failure.code(), failure)
	if failure.retryableReadyEOF(context.Background()) {
		t.Fatal("GO write failure was retryable")
	}
	if failure.provenCleanPreGO() {
		t.Fatal("GO write failure was classified as clean pre-GO")
	}
	if !failure.boundaryCleanupComplete() {
		t.Fatal("fully reaped GO failure did not retain cleanup evidence")
	}
	if shouldRecordNetworkEnforcementFailure(wrapped) {
		t.Fatal("fully cleaned ambiguous dispatch would poison future session commands")
	}
	if failure.code() != "E_COMMAND_JAIL_GO" {
		t.Fatalf("code = %q", failure.code())
	}
}

func TestCommandJailUnexpectedREADYByteIsNotRetried(t *testing.T) {
	failure := newCommandJailReadyFailure(1, errors.New("unexpected READY byte"))
	failure.finalize(nil, "SIGKILL", "", true, true, nil)
	if failure.retryableReadyEOF(context.Background()) {
		t.Fatal("malformed READY was retryable")
	}
	if !failure.provenCleanPreGO() {
		t.Fatal("fully cleaned malformed pre-GO attempt should not poison session readiness")
	}
}
