package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

// preExecBarrier owns the one-shot post-start enforcement hook for a command.
// A command runner must call Release only after the child is stopped. Release
// runs the hook exactly once and performs trusted-wrapper/GO steps only after
// the hook succeeds. Cleanup is likewise run at most once.
type preExecEnforcementError struct {
	code string
	err  error
}

func (e *preExecEnforcementError) Error() string { return e.err.Error() }
func (e *preExecEnforcementError) Unwrap() error { return e.err }

func markPreExecEnforcementError(code string, err error) error {
	if err == nil {
		return nil
	}
	var existing *preExecEnforcementError
	if errors.As(err, &existing) {
		return err
	}
	return &preExecEnforcementError{code: code, err: err}
}

type preExecBarrier struct {
	hook postStartHook

	enforceOnce sync.Once
	releaseOnce sync.Once
	cleanupOnce sync.Once
	cleanup     func() error
	cleanupErr  error
	err         error
	releaseErr  error
}

type preExecReleaseStep struct {
	name string
	run  func() error
}

func newPreExecBarrier(hook postStartHook) *preExecBarrier {
	return &preExecBarrier{hook: hook}
}

func (b *preExecBarrier) Enforce(pid int) error {
	if b == nil {
		return nil
	}
	b.enforceOnce.Do(func() {
		if b.hook == nil {
			return
		}
		cleanup, err := b.hook(pid)
		// Preserve partial-boundary cleanup even on failure. Release callers kill
		// and reap the still-stopped child before their deferred Cleanup runs;
		// trying to remove its populated cgroup here would fail and leak it.
		b.cleanup = cleanup
		if err != nil {
			b.err = markPreExecEnforcementError("E_PRE_EXEC_ENFORCEMENT", fmt.Errorf("post-start hook: %w", err))
		}
	})
	return b.err
}

func (b *preExecBarrier) Release(pid int, steps ...preExecReleaseStep) error {
	if b == nil {
		return nil
	}
	b.releaseOnce.Do(func() {
		if err := b.Enforce(pid); err != nil {
			b.releaseErr = err
			return
		}
		for _, step := range steps {
			if step.run == nil {
				continue
			}
			if err := step.run(); err != nil {
				if step.name == "" {
					b.releaseErr = markPreExecEnforcementError("E_PRE_EXEC_RELEASE", err)
				} else {
					b.releaseErr = markPreExecEnforcementError("E_PRE_EXEC_RELEASE", fmt.Errorf("%s: %w", step.name, err))
				}
				return
			}
		}
	})
	return b.releaseErr
}

func (b *preExecBarrier) Cleanup() error {
	if b == nil {
		return nil
	}
	b.cleanupOnce.Do(func() {
		if b.cleanup != nil {
			b.cleanupErr = b.cleanup()
		}
	})
	return b.cleanupErr
}

func (b *preExecBarrier) CleanupFunc() func() error {
	if b == nil {
		return nil
	}
	return b.Cleanup
}

func commandBoundaryRequired(extra *extraProcConfig) bool {
	return extra != nil && extra.commandBoundary != nil
}

// validatePreExecBarrierPath rejects execution paths that cannot prove a
// stopped child. A ptrace tracer normally attaches after Start and therefore
// races user code; the sole safe tracer path is the wrapper READY/GO protocol,
// where the trusted wrapper blocks before it execs the requested command.
func validatePreExecBarrierPath(hook postStartHook, tracer any, extra *extraProcConfig) error {
	if commandBoundaryRequired(extra) {
		if !extra.commandBoundary.Complete() {
			return markPreExecEnforcementError("E_PRE_EXEC_BOUNDARY", fmt.Errorf("strict command boundary requirements are incomplete"))
		}
		if hook == nil {
			return markPreExecEnforcementError("E_PRE_EXEC_BOUNDARY", fmt.Errorf("strict command boundary requires a stopped-child enforcement hook"))
		}
		if tracer != nil {
			return markPreExecEnforcementError("E_PRE_EXEC_BOUNDARY", fmt.Errorf("strict command boundary is unavailable with ptrace execution"))
		}
		if extra.notifyParentSock == nil {
			return markPreExecEnforcementError("E_PRE_EXEC_BOUNDARY", fmt.Errorf("strict command boundary requires a wrapper ACK/READY/GO control socket"))
		}
	}
	if hook == nil {
		return nil
	}
	if !preExecStoppedStartSupported() {
		return markPreExecEnforcementError("E_PRE_EXEC_BARRIER", fmt.Errorf("pre-exec enforcement barrier is unavailable on this platform"))
	}
	if tracer != nil && (extra == nil || !extra.ptraceSync) {
		return markPreExecEnforcementError("E_PRE_EXEC_BARRIER", fmt.Errorf("pre-exec enforcement barrier requires wrapper READY/GO synchronization with ptrace"))
	}
	return nil
}

func waitPreExecReady(ctx context.Context, ready <-chan error) error {
	if ready == nil {
		return fmt.Errorf("wrapper READY channel is unavailable")
	}
	select {
	case err, ok := <-ready:
		if !ok {
			return fmt.Errorf("wrapper READY channel closed without a status")
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func writePreExecControlByte(w io.Writer, value byte) error {
	if w == nil {
		return fmt.Errorf("wrapper control socket is unavailable")
	}
	n, err := w.Write([]byte{value})
	if err != nil {
		return err
	}
	if n != 1 {
		return io.ErrShortWrite
	}
	return nil
}

func commandBoundaryReleaseSteps(ctx context.Context, extra *extraProcConfig, ready <-chan error) []preExecReleaseStep {
	if !commandBoundaryRequired(extra) {
		return nil
	}
	return []preExecReleaseStep{
		{name: "wait for command-jail READY", run: func() error { return waitPreExecReady(ctx, ready) }},
		{name: "release command-jail GO barrier", run: func() error { return writePreExecControlByte(extra.notifyParentSock, 'G') }},
	}
}
