//go:build linux

package externalrunner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/agentsh/agentsh/internal/detached"
)

func launchDetachedHostMonitor(executable, stateDir string) (HostProcessIdentity, error) {
	layout, err := HostMonitorPaths(stateDir)
	if err != nil {
		return HostProcessIdentity{}, err
	}
	log, err := os.OpenFile(filepath.Join(layout.LogsDir, "host-monitor.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return HostProcessIdentity{}, err
	}
	cmd := exec.Command(executable, "runtime-monitor", "--state-dir", stateDir)
	cmd.Env = []string{"HOME=" + layout.HostDir}
	cmd.Dir = layout.HostDir
	cmd.Stdin = nil
	cmd.Stdout = log
	cmd.Stderr = log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = log.Close()
		return HostProcessIdentity{}, err
	}
	_ = log.Close()
	start, boot, err := detached.CurrentProcessIdentity(cmd.Process.Pid)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return HostProcessIdentity{}, err
	}
	identity := HostProcessIdentity{PID: cmd.Process.Pid, ProcessGroup: cmd.Process.Pid, StartIdentity: start, BootID: boot}
	if err := cmd.Process.Release(); err != nil {
		_ = syscall.Kill(cmd.Process.Pid, syscall.SIGKILL)
		return HostProcessIdentity{}, err
	}
	return identity, nil
}

func stopExactHostMonitor(ctx context.Context, stateDir string, identity HostProcessIdentity) error {
	if identity.PID <= 0 {
		return nil
	}
	if exactHostMonitorTerminalEvidence(stateDir, identity) {
		return nil
	}
	if !detached.ProcessIdentityMatches(identity.PID, identity.StartIdentity, identity.BootID) {
		return fmt.Errorf("exact host monitor exited without terminal teardown evidence")
	}
	process, err := os.FindProcess(identity.PID)
	if err != nil {
		return err
	}
	if err := process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	for {
		// The monitor persists this only after the runner is reaped and the relay
		// is closed. Accepting that exact evidence avoids treating an exited but
		// not-yet-reaped monitor process as an ambiguous teardown.
		if exactHostMonitorTerminalEvidence(stateDir, identity) {
			return nil
		}
		if !detached.ProcessIdentityMatches(identity.PID, identity.StartIdentity, identity.BootID) {
			return fmt.Errorf("exact host monitor exited without terminal teardown evidence")
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for exact host monitor stop: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func exactHostMonitorTerminalEvidence(stateDir string, identity HostProcessIdentity) bool {
	status, err := ReadHostMonitorStatus(stateDir)
	return err == nil && exactHostMonitorStatusTerminal(status, identity)
}

func exactHostMonitorStatusTerminal(status HostMonitorStatus, identity HostProcessIdentity) bool {
	if status.Monitor.PID != identity.PID || status.Monitor.StartIdentity != identity.StartIdentity || status.Monitor.BootID != identity.BootID {
		return false
	}
	return (status.State == HostMonitorStopped || status.State == HostMonitorFailed) && status.RunnerReaped && status.RelayClosed
}
