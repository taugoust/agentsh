package permissiongate

import (
	"context"
	"errors"
	"io"
	"time"
)

// ErrUnsupported is returned on platforms without Unix sockets and process
// groups.
var ErrUnsupported = errors.New("permission-gate run is unsupported on this platform")

// RunOptions describes a direct guard-only child launch.
type RunOptions struct {
	Command   []string
	AuditPath string
	// HandshakeTimeout bounds the Pi rendezvous and initial hello. Zero uses the
	// secure platform default.
	HandshakeTimeout time.Duration

	// Nil streams inherit the agentsh process streams. The explicit fields are
	// primarily useful to deterministic launch tests.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// RunResult reports the exact child status and the per-run audit location.
type RunResult struct {
	ExitCode  int
	AuditPath string
	RunID     string
}

// Run directly launches the requested command and brokers its private gate
// connection. Platform files provide the Unix implementation and Windows stub.
func Run(ctx context.Context, options RunOptions) (RunResult, error) {
	return run(ctx, options)
}
