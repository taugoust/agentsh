package approvals

import (
	"context"
	"time"
)

type commandTimeoutExtensionKey struct{}

// WithCommandTimeoutExtension installs a callback that approval waits can use to
// grant the surrounding command extra runtime budget. Callers remain responsible
// for enforcing the command timeout itself.
func WithCommandTimeoutExtension(ctx context.Context, extend func(time.Duration)) context.Context {
	if extend == nil {
		return ctx
	}
	return context.WithValue(ctx, commandTimeoutExtensionKey{}, extend)
}

// ExtendCommandTimeoutForApproval asks the surrounding command, when present, to
// add approval wait slack to its execution timeout. It is a no-op for callers
// that are not running under an extendable command timeout.
func ExtendCommandTimeoutForApproval(ctx context.Context, extra time.Duration) {
	if ctx == nil || extra <= 0 {
		return
	}
	extend, ok := ctx.Value(commandTimeoutExtensionKey{}).(func(time.Duration))
	if !ok || extend == nil {
		return
	}
	extend(extra)
}
