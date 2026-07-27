package api

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

const subagentTerminationGracePeriod = 2 * time.Second

type subagentProcessOutcome struct {
	RunError    error
	Termination subagentTermination
	Signal      string
	Started     bool
}

func runOwnedSubagentProcess(ctx context.Context, cmd *exec.Cmd, gracePeriod time.Duration) subagentProcessOutcome {
	return runOwnedSubagentProcessWithStart(ctx, cmd, gracePeriod, nil)
}

func runOwnedSubagentProcessWithStart(ctx context.Context, cmd *exec.Cmd, gracePeriod time.Duration, onStart func(pid, processGroupID int) error) subagentProcessOutcome {
	if err := ctx.Err(); err != nil {
		return subagentProcessOutcome{RunError: err, Termination: subagentTerminationNatural}
	}
	cmd.SysProcAttr = getSubagentSysProcAttr()
	if err := cmd.Start(); err != nil {
		return subagentProcessOutcome{RunError: err, Termination: subagentTerminationNatural}
	}
	if onStart != nil {
		if err := onStart(cmd.Process.Pid, getProcessGroupID(cmd.Process.Pid)); err != nil {
			_ = killProcessHard(cmd.Process.Pid)
			waitErr := cmd.Wait()
			if waitErr != nil {
				err = errors.Join(err, waitErr)
			}
			return subagentProcessOutcome{RunError: err, Termination: subagentTerminationForced, Signal: subagentProcessSignal(cmd), Started: true}
		}
	}

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	select {
	case err := <-waitCh:
		return subagentProcessOutcome{RunError: err, Termination: subagentTerminationNatural, Signal: subagentProcessSignal(cmd), Started: true}
	case <-ctx.Done():
		// Prefer a concurrently completed natural exit over sending a signal to a
		// process ID that may already have been reaped and reused.
		select {
		case err := <-waitCh:
			return subagentProcessOutcome{RunError: err, Termination: subagentTerminationNatural, Signal: subagentProcessSignal(cmd), Started: true}
		default:
		}
	}

	pid := cmd.Process.Pid
	_ = killProcess(pid)
	if gracePeriod <= 0 {
		gracePeriod = subagentTerminationGracePeriod
	}
	graceTimer := time.NewTimer(gracePeriod)
	defer graceTimer.Stop()
	select {
	case err := <-waitCh:
		return subagentProcessOutcome{RunError: err, Termination: subagentTerminationGraceful, Signal: subagentProcessSignal(cmd), Started: true}
	case <-graceTimer.C:
		_ = killProcessHard(pid)
		err := <-waitCh
		return subagentProcessOutcome{RunError: err, Termination: subagentTerminationForced, Signal: subagentProcessSignal(cmd), Started: true}
	}
}
