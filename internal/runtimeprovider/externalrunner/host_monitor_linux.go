//go:build linux

package externalrunner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/agentsh/agentsh/internal/detached"
	"golang.org/x/sys/unix"
)

type linuxHostRunner struct {
	identity HostProcessIdentity
	cmd      *exec.Cmd
	pidfd    int
	done     chan hostRunnerResult
	exited   chan struct{}

	forceOnce sync.Once
	forceErr  error
	waitOnce  sync.Once
	waitDone  chan struct{}
	result    hostRunnerResult
	waitErr   error
}

func (r *linuxHostRunner) Identity() HostProcessIdentity { return r.identity }
func (r *linuxHostRunner) Done() <-chan hostRunnerResult { return r.done }

func (r *linuxHostRunner) ForceStop() error {
	r.forceOnce.Do(func() {
		// The pidfd binds the direct runner across PID reuse. The unreaped leader
		// pins its PGID until EnsureStopped has killed residual members.
		pidErr := unix.PidfdSendSignal(r.pidfd, unix.SIGKILL, nil, 0)
		groupErr := syscall.Kill(-r.identity.ProcessGroup, syscall.SIGKILL)
		if errors.Is(pidErr, syscall.ESRCH) {
			pidErr = nil
		}
		if errors.Is(groupErr, syscall.ESRCH) {
			groupErr = nil
		}
		r.forceErr = errors.Join(pidErr, groupErr)
	})
	return r.forceErr
}

func (r *linuxHostRunner) EnsureStopped(ctx context.Context) (*hostRunnerResult, error) {
	select {
	case <-r.exited:
	case <-ctx.Done():
		return nil, fmt.Errorf("wait for external runner exit: %w", ctx.Err())
	}
	r.waitOnce.Do(func() {
		// The leader is still unreaped, so its PID/PGID cannot be recycled while
		// residual members are killed. Only then reap the direct child.
		groupErr := syscall.Kill(-r.identity.ProcessGroup, syscall.SIGKILL)
		if errors.Is(groupErr, syscall.ESRCH) {
			groupErr = nil
		}
		waitErr := r.cmd.Wait()
		r.result.Err = waitErr
		if state := r.cmd.ProcessState; state != nil {
			r.result.Exit.ExitCode = state.ExitCode()
			if wait, ok := state.Sys().(syscall.WaitStatus); ok {
				r.result.Exit.Signaled = wait.Signaled()
			}
		}
		closeErr := unix.Close(r.pidfd)
		if errors.Is(closeErr, syscall.EBADF) {
			closeErr = nil
		}
		// The immutable direct-exec contract has no runner sidecars. Killing the
		// pinned group before reaping and then successfully waiting the leader is
		// the complete process model; never inspect a reusable PGID after reap.
		r.waitErr = errors.Join(groupErr, closeErr)
		close(r.waitDone)
	})
	select {
	case <-r.waitDone:
		result := r.result
		return &result, r.waitErr
	case <-ctx.Done():
		return nil, fmt.Errorf("reap external runner: %w", ctx.Err())
	}
}

func startHostRunner(profile Profile, layout HostMonitorLayout, cid uint32, output io.Writer) (hostRunner, error) {
	runnerFile, err := os.Open(profile.Runner.Path)
	if err != nil {
		return nil, fmt.Errorf("open verified external runner: %w", err)
	}
	defer runnerFile.Close()
	info, err := runnerFile.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o222 != 0 || info.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("verified external runner file is unsafe")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, runnerFile); err != nil {
		return nil, fmt.Errorf("rehash external runner before exec: %w", err)
	}
	if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != profile.Runner.SHA256 {
		return nil, fmt.Errorf("external runner changed before exec")
	}
	if _, err := runnerFile.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	// Execute the exact hashed descriptor rather than reopening the profile path.
	runnerFDPath := filepath.Join(string(filepath.Separator), "proc", "self", "fd", "3")
	cmd := exec.Command(runnerFDPath)
	cmd.ExtraFiles = []*os.File{runnerFile}
	cmd.Dir = layout.RuntimeDir
	cmd.Env = []string{"PI_AGENT_MICROVM_VSOCK_CID=" + strconv.FormatUint(uint64(cid), 10)}
	cmd.Stdin = nil
	cmd.Stdout = output
	cmd.Stderr = output
	cmd.WaitDelay = time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start verified external runner: %w", err)
	}
	pidfd, pidfdErr := unix.PidfdOpen(cmd.Process.Pid, 0)
	startIdentity, bootID, identityErr := detached.CurrentProcessIdentity(cmd.Process.Pid)
	processGroup, groupErr := syscall.Getpgid(cmd.Process.Pid)
	if err := errors.Join(pidfdErr, identityErr, groupErr); err != nil || processGroup != cmd.Process.Pid {
		if pidfdErr == nil {
			_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
			_ = unix.Close(pidfd)
		} else {
			_ = cmd.Process.Kill()
		}
		if groupErr == nil && processGroup == cmd.Process.Pid {
			_ = syscall.Kill(-processGroup, syscall.SIGKILL)
		}
		cleanupErr := waitHostRunnerCommand(cmd)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("capture external runner identity: %w", err), cleanupErr)
		}
		return nil, errors.Join(fmt.Errorf("external runner did not become its exact process-group leader"), cleanupErr)
	}
	runner := &linuxHostRunner{
		identity: HostProcessIdentity{PID: cmd.Process.Pid, ProcessGroup: processGroup, StartIdentity: startIdentity, BootID: bootID},
		cmd:      cmd, pidfd: pidfd, done: make(chan hostRunnerResult, 1), exited: make(chan struct{}), waitDone: make(chan struct{}),
	}
	go func() {
		poll := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
		for {
			if _, err := unix.Poll(poll, -1); err == nil || !errors.Is(err, syscall.EINTR) {
				break
			}
		}
		close(runner.exited)
		runner.done <- hostRunnerResult{Err: fmt.Errorf("external runner exited")}
	}()
	return runner, nil
}

func waitHostRunnerCommand(cmd *exec.Cmd) error {
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	select {
	case err := <-waited:
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil
		}
		return err
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timed out reaping failed external runner")
	}
}

func validateHostMonitorDirectory(path string) error {
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != 0o700 || !ok || !trustedCIDOwner(stat.Uid) {
		return fmt.Errorf("unsafe directory identity or permissions")
	}
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	opened, err := dir.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return fmt.Errorf("directory identity changed while opening")
	}
	return nil
}

func acquireHostMonitorLock(ctx context.Context, path string) (io.Closer, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open host monitor lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), HostMonitorLockName)
	info, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect host monitor lock: %w", statErr)
	}
	stat, statOK := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !statOK || !trustedCIDOwner(stat.Uid) {
		_ = file.Close()
		return nil, fmt.Errorf("host monitor lock has unsafe identity or permissions")
	}
	if err := ctx.Err(); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err == nil {
		return &hostMonitorFlock{File: file, fd: fd}, nil
	} else if err == unix.EWOULDBLOCK || err == unix.EAGAIN {
		_ = file.Close()
		return nil, fmt.Errorf("host monitor is already active")
	} else {
		_ = file.Close()
		return nil, fmt.Errorf("lock host monitor: %w", err)
	}
}

type hostMonitorFlock struct {
	*os.File
	fd int
}

func (f *hostMonitorFlock) Close() error {
	return errors.Join(unix.Flock(f.fd, unix.LOCK_UN), f.File.Close())
}
