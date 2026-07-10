//go:build !windows

package pty

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

type Winsize struct {
	Rows uint16
	Cols uint16
}

type StartRequest struct {
	Command string
	Args    []string

	Argv0 string
	Dir   string
	Env   []string

	InitialSize     Winsize
	ExtraFiles      []*os.File
	CommandBoundary *types.LinuxCommandJailRequirements

	// PreExec runs while the Linux child is stopped. The callback owns the
	// one-shot enforcement/READY/GO sequence and must call resume exactly once
	// after setup succeeds. A non-nil callback is fail-closed on other platforms.
	PreExec func(pid int, resume func() error) (cleanup func() error, err error)
}

type Session struct {
	cmd    *exec.Cmd
	master *os.File

	outCh   chan []byte
	outDone chan struct{}

	pid int

	cleanupOnce sync.Once
	cleanup     func() error
	cleanupErr  error
}

func (s *Session) Output() <-chan []byte { return s.outCh }

func (s *Session) PID() int {
	if s == nil {
		return 0
	}
	return s.pid
}

func (s *Session) runCleanup() error {
	if s == nil {
		return nil
	}
	s.cleanupOnce.Do(func() {
		if s.cleanup != nil {
			s.cleanupErr = s.cleanup()
		}
	})
	return s.cleanupErr
}

func (s *Session) Write(p []byte) (int, error) {
	if s == nil || s.master == nil {
		return 0, io.ErrClosedPipe
	}
	return s.master.Write(p)
}

func (s *Session) Resize(rows, cols uint16) error {
	if s == nil || s.master == nil {
		return io.ErrClosedPipe
	}
	ws := &unix.Winsize{Row: rows, Col: cols}
	return unix.IoctlSetWinsize(int(s.master.Fd()), unix.TIOCSWINSZ, ws)
}

func (s *Session) Signal(sig syscall.Signal) error {
	if s == nil || s.cmd == nil || s.cmd.Process == nil {
		return errors.New("process not started")
	}
	// Signal the process group for job control semantics.
	pgid, err := syscall.Getpgid(s.cmd.Process.Pid)
	if err != nil {
		return s.cmd.Process.Signal(sig)
	}
	return syscall.Kill(-pgid, sig)
}

func (s *Session) Wait() (exitCode int, err error) {
	if s == nil || s.cmd == nil {
		return 127, errors.New("process not started")
	}
	err = s.cmd.Wait()
	if s.outDone != nil {
		<-s.outDone
	}
	cleanupErr := s.runCleanup()
	if err == nil {
		return 0, cleanupErr
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), cleanupErr
	}
	return 127, errors.Join(err, cleanupErr)
}

type Engine struct{}

func New() *Engine { return &Engine{} }

func (e *Engine) Start(ctx context.Context, req StartRequest) (*Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if req.Command == "" {
		return nil, errors.New("command is required")
	}

	master, slave, err := openPTY(req.InitialSize)
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, req.Command, req.Args...)
	if req.Dir != "" {
		cmd.Dir = req.Dir
	}
	if len(req.Env) > 0 {
		cmd.Env = req.Env
	}
	if req.Argv0 != "" && len(cmd.Args) > 0 {
		cmd.Args[0] = req.Argv0
	}

	// New session + controlling TTY for interactive behavior.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:  true,
		Setctty: true,
		// Use stdin (fd 0) as controlling TTY after the child maps slave onto stdio.
		Ctty: 0,
	}
	if req.CommandBoundary != nil && req.PreExec == nil {
		_ = master.Close()
		_ = slave.Close()
		return nil, ErrPreExecBarrierUnavailable
	}
	if err := configureStoppedStart(cmd.SysProcAttr, req.PreExec != nil, req.CommandBoundary); err != nil {
		_ = master.Close()
		_ = slave.Close()
		return nil, err
	}

	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	if len(req.ExtraFiles) > 0 {
		cmd.ExtraFiles = append(cmd.ExtraFiles, req.ExtraFiles...)
	}

	outCh := make(chan []byte, 16)
	outDone := make(chan struct{})
	sess := &Session{cmd: cmd, master: master, outCh: outCh, outDone: outDone}

	if err := cmd.Start(); err != nil {
		_ = master.Close()
		_ = slave.Close()
		close(outCh)
		close(outDone)
		return nil, err
	}
	if cmd.Process != nil {
		sess.pid = cmd.Process.Pid
	}
	if req.PreExec != nil {
		cleanup, hookErr := req.PreExec(sess.pid, func() error { return resumeStoppedProcess(sess.pid) })
		if hookErr != nil {
			// Keep the child stopped, kill and reap it, then remove partial
			// cgroup/helper resources. Cgroup removal before reap would fail.
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			if cleanup != nil {
				if cleanupErr := cleanup(); cleanupErr != nil {
					hookErr = errors.Join(hookErr, cleanupErr)
				}
			}
			_ = master.Close()
			_ = slave.Close()
			close(outCh)
			close(outDone)
			return nil, hookErr
		}
		sess.cleanup = cleanup
	}

	// Parent no longer needs the slave FD.
	_ = slave.Close()

	go func() {
		defer func() { _ = master.Close() }()
		defer close(outDone)
		defer close(outCh)
		buf := make([]byte, 32*1024)
		for {
			n, rerr := master.Read(buf)
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				outCh <- b
			}
			if rerr != nil {
				return
			}
		}
	}()

	return sess, nil
}

func openPTY(size Winsize) (master, slave *os.File, err error) {
	master, slave, err = pty.Open()
	if err != nil {
		return nil, nil, err
	}
	if size.Rows > 0 && size.Cols > 0 {
		_ = unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: size.Rows, Col: size.Cols})
	}
	return master, slave, nil
}
