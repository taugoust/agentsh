package api

import (
	"context"
	"errors"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
)

type commandTimeoutExtender struct {
	ctx      context.Context
	cancel   context.CancelCauseFunc
	extendCh chan time.Duration
	doneCh   chan struct{}
}

func withExtendableCommandTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		ctx, cancel := context.WithCancel(parent)
		return approvals.WithCommandTimeoutExtension(ctx, func(time.Duration) {}), cancel
	}
	baseCtx, cancelCause := context.WithCancelCause(parent)
	extender := &commandTimeoutExtender{
		ctx:      baseCtx,
		cancel:   cancelCause,
		extendCh: make(chan time.Duration, 16),
		doneCh:   make(chan struct{}),
	}
	go extender.run(timeout)
	return approvals.WithCommandTimeoutExtension(baseCtx, extender.extend), extender.cancelContext
}

func (e *commandTimeoutExtender) run(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-e.doneCh:
			return
		case extra := <-e.extendCh:
			if extra <= 0 {
				continue
			}
			deadline = deadline.Add(extra)
			resetTimer(timer, time.Until(deadline))
		case <-timer.C:
			e.cancel(context.DeadlineExceeded)
			return
		}
	}
}

func (e *commandTimeoutExtender) extend(extra time.Duration) {
	if extra <= 0 {
		return
	}
	select {
	case e.extendCh <- extra:
	case <-e.ctx.Done():
	case <-e.doneCh:
	}
}

func (e *commandTimeoutExtender) cancelContext() {
	select {
	case <-e.doneCh:
	default:
		close(e.doneCh)
	}
	e.cancel(context.Canceled)
}

func resetTimer(timer *time.Timer, duration time.Duration) {
	if duration < 0 {
		duration = 0
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(duration)
}

func commandTimedOut(ctx context.Context) bool {
	return errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(context.Cause(ctx), context.DeadlineExceeded)
}
