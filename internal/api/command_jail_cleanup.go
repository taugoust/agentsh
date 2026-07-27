package api

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

const (
	commandJailNaturalExitGrace = 100 * time.Millisecond
	commandJailHandlerJoinLimit = 2 * time.Second
)

// finalizeCommandBoundaryFailure kills and reaps an unreleased wrapper, joins
// every parent-side handler/log drain, and only then removes helper/eBPF/cgroup
// resources. The resulting commandJailFailure is the sole retry authority.
func finalizePTYCommandBoundaryFailure(processState *os.ProcessState, waitErr, cleanupErr error, lifecycle *wrapperHandlerLifecycle, runErr error) error {
	processReaped := processState != nil
	handlersJoined := lifecycle.stopAndWait(commandJailHandlerJoinLimit)
	if failure := commandJailFailureFrom(runErr); failure != nil {
		exitCode, signal := processExitEvidence(processState)
		failure.finalize(exitCode, signal, lifecycle.wrapperLogTail(), processReaped, handlersJoined, cleanupErr)
	}
	resultErr := runErr
	if !processReaped && waitErr != nil {
		resultErr = errors.Join(resultErr, fmt.Errorf("reap command-jail wrapper: %w", waitErr))
	}
	if !handlersJoined {
		resultErr = errors.Join(resultErr, errors.New("command-jail handler cleanup did not complete"))
	}
	if cleanupErr != nil {
		resultErr = errors.Join(resultErr, markPostStartCleanupError(cleanupErr))
	}
	return resultErr
}

func finalizeCommandBoundaryFailure(cmd *exec.Cmd, pgid int, barrier *preExecBarrier, lifecycle *wrapperHandlerLifecycle, runErr error) error {
	failure := commandJailFailureFrom(runErr)
	var waitErr error

	if cmd != nil && cmd.Process != nil {
		waitDone := make(chan error, 1)
		if failure != nil && failure.observedReadyEOF() {
			// EOF normally means fatalf is already exiting. Give Wait a short
			// opportunity to preserve the wrapper's natural status instead of
			// overwriting it with our cleanup SIGKILL.
			go func() { waitDone <- cmd.Wait() }()
			select {
			case waitErr = <-waitDone:
			case <-time.After(commandJailNaturalExitGrace):
				_ = killProcessHard(cmd.Process.Pid)
				_ = killProcessGroup(pgid)
				waitErr = <-waitDone
			}
		} else {
			_ = killProcessHard(cmd.Process.Pid)
			_ = killProcessGroup(pgid)
			waitErr = cmd.Wait()
		}
	}

	processReaped := cmd != nil && cmd.ProcessState != nil
	handlersJoined := lifecycle.stopAndWait(commandJailHandlerJoinLimit)
	cleanupErr := barrier.Cleanup()

	if failure != nil {
		exitCode, signal := processExitEvidence(cmd.ProcessState)
		failure.finalize(exitCode, signal, lifecycle.wrapperLogTail(), processReaped, handlersJoined, cleanupErr)
	}

	resultErr := runErr
	if !processReaped && waitErr != nil {
		resultErr = errors.Join(resultErr, fmt.Errorf("reap command-jail wrapper: %w", waitErr))
	}
	if !handlersJoined {
		resultErr = errors.Join(resultErr, errors.New("command-jail handler cleanup did not complete"))
	}
	if cleanupErr != nil {
		resultErr = errors.Join(resultErr, markPostStartCleanupError(cleanupErr))
	}
	return resultErr
}
