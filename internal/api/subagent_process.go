package api

import (
	"context"
	"os/exec"
	"time"
)

const subagentTerminationGracePeriod = 2 * time.Second

type subagentProcessOutcome struct {
	RunError    error
	Termination subagentTermination
	Signal      string
}

func runOwnedSubagentProcess(ctx context.Context, cmd *exec.Cmd, gracePeriod time.Duration) subagentProcessOutcome {
	if err := ctx.Err(); err != nil {
		return subagentProcessOutcome{RunError: err, Termination: subagentTerminationNatural}
	}
	cmd.SysProcAttr = getSysProcAttr()
	if err := cmd.Start(); err != nil {
		return subagentProcessOutcome{RunError: err, Termination: subagentTerminationNatural}
	}

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	select {
	case err := <-waitCh:
		return subagentProcessOutcome{RunError: err, Termination: subagentTerminationNatural, Signal: subagentProcessSignal(cmd)}
	case <-ctx.Done():
		// Prefer a concurrently completed natural exit over sending a signal to a
		// process ID that may already have been reaped and reused.
		select {
		case err := <-waitCh:
			return subagentProcessOutcome{RunError: err, Termination: subagentTerminationNatural, Signal: subagentProcessSignal(cmd)}
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
		return subagentProcessOutcome{RunError: err, Termination: subagentTerminationGraceful, Signal: subagentProcessSignal(cmd)}
	case <-graceTimer.C:
		_ = killProcessHard(pid)
		err := <-waitCh
		return subagentProcessOutcome{RunError: err, Termination: subagentTerminationForced, Signal: subagentProcessSignal(cmd)}
	}
}
