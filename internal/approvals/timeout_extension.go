package approvals

import (
	"context"
	"time"
)

type commandTimeoutExtensionKey struct{}

// WithCommandTimeoutExtension installs a callback that approval waits can use to
// request runtime slack for the surrounding command. The command timeout owner
// is responsible for enforcing one cumulative allowance across all requests.
func WithCommandTimeoutExtension(ctx context.Context, extend func(time.Duration)) context.Context {
	if extend == nil {
		return ctx
	}
	return context.WithValue(ctx, commandTimeoutExtensionKey{}, extend)
}

// ExtendCommandTimeoutForApproval asks the surrounding command, when present,
// to reserve approval-wait slack. For ordinary commands, the first positive
// request establishes the cumulative cap; later requests cannot add another
// allowance. It is a no-op outside an extendable command timeout.
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
