package pty

import "errors"

// ErrPreExecBarrierUnavailable means the platform cannot start a PTY child in
// a state where post-start enforcement can complete before user code runs.
var ErrPreExecBarrierUnavailable = errors.New("PTY pre-exec enforcement barrier is unavailable on this platform")
