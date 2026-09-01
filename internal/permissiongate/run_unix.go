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
	"path/filepath"
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

	handshakeTimeout := options.HandshakeTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = defaultHandshakeTimeout
	}

	tempRoot, err := filepath.Abs(os.TempDir())
	if err != nil {
		return result, fmt.Errorf("resolve permission gate temporary directory: %w", err)
	}
	rendezvousDir, err := os.MkdirTemp(tempRoot, "agpg-")
	if err != nil {
		return result, fmt.Errorf("create permission gate rendezvous directory: %w", err)
	}
	if err := os.Chmod(rendezvousDir, 0o700); err != nil {
		_ = os.RemoveAll(rendezvousDir)
		return result, fmt.Errorf("secure permission gate rendezvous directory: %w", err)
	}
	socketPath := filepath.Join(rendezvousDir, "s")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		_ = os.RemoveAll(rendezvousDir)
		return result, fmt.Errorf("listen for permission gate rendezvous: %w", err)
	}
	listener.SetUnlinkOnClose(true)
	rendezvousOpen := true
	cleanupRendezvous := func() error {
		var cleanupErrs []error
		if rendezvousOpen {
			rendezvousOpen = false
			if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("close listener: %w", closeErr))
			}
		}
		if removeErr := os.Remove(socketPath); removeErr != nil && !os.IsNotExist(removeErr) {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("unlink socket: %w", removeErr))
		}
		if removeErr := os.RemoveAll(rendezvousDir); removeErr != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("remove private directory: %w", removeErr))
		}
		return errors.Join(cleanupErrs...)
	}
	defer func() { _ = cleanupRendezvous() }()

	handshakeDeadline := time.Now().Add(handshakeTimeout)
	if err := listener.SetDeadline(handshakeDeadline); err != nil {
		return result, fmt.Errorf("bound permission gate rendezvous: %w", err)
	}

	command := exec.Command(options.Command[0], options.Command[1:]...)
	command.Env = withPermissionGateSocket(os.Environ(), socketPath)
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

	stopSignals := forwardSignals(command.Process.Pid)
	defer stopSignals()
	if foregroundTTY {
		defer reclaimForegroundTerminal()
	}

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- command.Wait()
	}()
	acceptCh := make(chan struct {
		connection *net.UnixConn
		err        error
	}, 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		acceptCh <- struct {
			connection *net.UnixConn
			err        error
		}{connection: connection, err: acceptErr}
	}()

	var transport *net.UnixConn
	select {
	case accepted := <-acceptCh:
		if accepted.err != nil {
			_ = cleanupRendezvous()
			killProcessGroup(command.Process.Pid)
			waitErr := <-waitCh
			result.ExitCode = childExitCode(waitErr)
			return result, fmt.Errorf("permission gate broker failed: accept rendezvous: %w", accepted.err)
		}
		if accepted.connection == nil {
			_ = cleanupRendezvous()
			killProcessGroup(command.Process.Pid)
			waitErr := <-waitCh
			result.ExitCode = childExitCode(waitErr)
			return result, errors.New("permission gate broker failed: accepted nil rendezvous connection")
		}
		transport = accepted.connection
		if err := verifyPermissionGatePeer(transport, command.Process.Pid); err != nil {
			_ = transport.Close()
			_ = cleanupRendezvous()
			killProcessGroup(command.Process.Pid)
			waitErr := <-waitCh
			result.ExitCode = childExitCode(waitErr)
			return result, fmt.Errorf("permission gate broker failed: verify rendezvous peer: %w", err)
		}
		// The rendezvous is one-shot. Retire its listener, socket path, and
		// private directory before reading any protocol data from the client.
		if err := cleanupRendezvous(); err != nil {
			_ = transport.Close()
			killProcessGroup(command.Process.Pid)
			waitErr := <-waitCh
			result.ExitCode = childExitCode(waitErr)
			return result, fmt.Errorf("permission gate broker failed: retire rendezvous: %w", err)
		}
	case waitErr := <-waitCh:
		_ = cleanupRendezvous()
		accepted := <-acceptCh
		if accepted.connection != nil {
			_ = accepted.connection.Close()
		}
		return finishRunResult(result, waitErr)
	case <-ctx.Done():
		_ = cleanupRendezvous()
		accepted := <-acceptCh
		if accepted.connection != nil {
			_ = accepted.connection.Close()
		}
		killProcessGroup(command.Process.Pid)
		waitErr := <-waitCh
		result.ExitCode = childExitCode(waitErr)
		return result, ctx.Err()
	}
	defer transport.Close()
	if err := transport.SetReadDeadline(handshakeDeadline); err != nil {
		killProcessGroup(command.Process.Pid)
		waitErr := <-waitCh
		result.ExitCode = childExitCode(waitErr)
		return result, fmt.Errorf("permission gate broker failed: bound handshake: %w", err)
	}

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

	return finishRunResult(result, waitErr)
}

func withPermissionGateSocket(environment []string, socketPath string) []string {
	filtered := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		key, _, found := strings.Cut(entry, "=")
		if found && strings.EqualFold(key, EnvSocket) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return append(filtered, EnvSocket+"="+socketPath)
}

func finishRunResult(result RunResult, waitErr error) (RunResult, error) {
	result.ExitCode = childExitCode(waitErr)
	if waitErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(waitErr, &exitErr) {
			return result, fmt.Errorf("wait for permission-gated command: %w", waitErr)
		}
	}
	return result, nil
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
