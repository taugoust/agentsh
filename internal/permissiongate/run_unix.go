//go:build !windows

package permissiongate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const (
	exitedSocketGrace       = 100 * time.Millisecond
	defaultHandshakeTimeout = 30 * time.Second
)

func run(ctx context.Context, options RunOptions) (RunResult, error) {
	var result RunResult
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if len(options.Command) == 0 || strings.TrimSpace(options.Command[0]) == "" {
		return result, errors.New("permission-gate command is required")
	}

	auditPath := strings.TrimSpace(options.AuditPath)
	runID := ""
	var err error
	if auditPath == "" {
		auditPath, runID, err = defaultAuditPath()
		if err != nil {
			return result, err
		}
	} else {
		runID, err = randomRunID()
		if err != nil {
			return result, err
		}
	}
	audit, err := OpenAuditLog(auditPath)
	if err != nil {
		return result, err
	}
	result.AuditPath = audit.Path()
	result.RunID = runID
	defer func() { _ = audit.Close() }()

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return result, fmt.Errorf("create permission gate socketpair: %w", err)
	}
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])
	parentFile := os.NewFile(uintptr(fds[0]), "permission-gate-parent")
	childFile := os.NewFile(uintptr(fds[1]), "permission-gate-child")
	if parentFile == nil || childFile == nil {
		if parentFile != nil {
			_ = parentFile.Close()
		}
		if childFile != nil {
			_ = childFile.Close()
		}
		return result, errors.New("create permission gate socket files")
	}
	defer childFile.Close()

	transport, err := net.FileConn(parentFile)
	_ = parentFile.Close()
	if err != nil {
		return result, fmt.Errorf("open permission gate transport: %w", err)
	}
	defer transport.Close()
	handshakeTimeout := options.HandshakeTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = defaultHandshakeTimeout
	}
	if err := transport.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return result, fmt.Errorf("bound permission gate handshake: %w", err)
	}

	command := exec.Command(options.Command[0], options.Command[1:]...)
	command.Env = withPermissionGateFD(os.Environ(), 3)
	command.ExtraFiles = []*os.File{childFile}
	command.Stdin = options.Stdin
	if command.Stdin == nil {
		command.Stdin = os.Stdin
	}
	command.Stdout = options.Stdout
	if command.Stdout == nil {
		command.Stdout = os.Stdout
	}
	command.Stderr = options.Stderr
	if command.Stderr == nil {
		command.Stderr = os.Stderr
	}

	foregroundTTY := options.Stdin == nil && term.IsTerminal(int(os.Stdin.Fd()))
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if foregroundTTY {
		command.SysProcAttr.Foreground = true
		command.SysProcAttr.Ctty = 0
	}

	if err := command.Start(); err != nil {
		return result, fmt.Errorf("start permission-gated command: %w", err)
	}
	_ = childFile.Close()

	stopSignals := forwardSignals(command.Process.Pid)
	defer stopSignals()
	if foregroundTTY {
		defer reclaimForegroundTerminal()
	}

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- command.Wait()
	}()
	brokerCh := make(chan error, 1)
	go func() {
		brokerCh <- NewBroker(transport, audit, runID).Serve()
	}()

	var waitErr error
	select {
	case waitErr = <-waitCh:
		// Process exit owns this path. Closing the local transport unblocks the
		// broker; an EOF observed after Wait is not a live fail-open condition.
		_ = transport.Close()
		<-brokerCh
	case brokerErr := <-brokerCh:
		if errors.Is(brokerErr, ErrUnexpectedEOF) {
			// Socket teardown and wait notification race during ordinary exit.
			// Give the wait goroutine one short scheduling window; a client that
			// merely drops authority and keeps running is still killed.
			timer := time.NewTimer(exitedSocketGrace)
			select {
			case waitErr = <-waitCh:
				if !timer.Stop() {
					<-timer.C
				}
			case <-timer.C:
				killProcessGroup(command.Process.Pid)
				waitErr = <-waitCh
				result.ExitCode = childExitCode(waitErr)
				return result, fmt.Errorf("permission gate broker failed: %w", brokerErr)
			}
		} else {
			killProcessGroup(command.Process.Pid)
			waitErr = <-waitCh
			result.ExitCode = childExitCode(waitErr)
			return result, fmt.Errorf("permission gate broker failed: %w", brokerErr)
		}
	case <-ctx.Done():
		killProcessGroup(command.Process.Pid)
		waitErr = <-waitCh
		_ = transport.Close()
		<-brokerCh
		result.ExitCode = childExitCode(waitErr)
		return result, ctx.Err()
	}

	result.ExitCode = childExitCode(waitErr)
	if waitErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(waitErr, &exitErr) {
			return result, fmt.Errorf("wait for permission-gated command: %w", waitErr)
		}
	}
	return result, nil
}

func withPermissionGateFD(environment []string, fd int) []string {
	filtered := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		key, _, found := strings.Cut(entry, "=")
		if found && strings.EqualFold(key, EnvFD) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return append(filtered, fmt.Sprintf("%s=%d", EnvFD, fd))
}

func forwardSignals(processGroup int) func() {
	signals := make(chan os.Signal, 8)
	done := make(chan struct{})
	signal.Notify(signals,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGQUIT,
		syscall.SIGTERM,
		syscall.SIGUSR1,
		syscall.SIGUSR2,
		syscall.SIGWINCH,
	)
	go func() {
		defer close(done)
		for received := range signals {
			unixSignal, ok := received.(syscall.Signal)
			if !ok {
				continue
			}
			_ = syscall.Kill(-processGroup, unixSignal)
		}
	}()
	return func() {
		signal.Stop(signals)
		close(signals)
		<-done
	}
}

func killProcessGroup(processGroup int) {
	if processGroup <= 0 {
		return
	}
	_ = syscall.Kill(-processGroup, syscall.SIGKILL)
}

func childExitCode(waitErr error) int {
	if waitErr == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if !errors.As(waitErr, &exitErr) {
		return 1
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok {
		return 1
	}
	if status.Signaled() {
		return 128 + int(status.Signal())
	}
	return status.ExitStatus()
}

func reclaimForegroundTerminal() {
	signal.Ignore(syscall.SIGTTOU)
	defer signal.Reset(syscall.SIGTTOU)
	processGroup := int32(unix.Getpgrp())
	_, _, _ = unix.Syscall(unix.SYS_IOCTL, os.Stdin.Fd(), unix.TIOCSPGRP, uintptr(unsafe.Pointer(&processGroup)))
}
