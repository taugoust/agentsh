//go:build windows

package permissiongate

import "context"

func run(_ context.Context, _ RunOptions) (RunResult, error) {
	return RunResult{}, ErrUnsupported
}
