//go:build !linux || !cgo

package api

import (
	"context"
	"fmt"
	"os"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
)

// createExecveHandler is a no-op on non-Linux platforms.
func createExecveHandler(cfg config.ExecveConfig, pol *policy.Engine, approvalMgr *approvals.Manager) any {
	return nil
}

// startNotifyHandler is a no-op on non-Linux platforms or without CGO.
// Unix socket enforcement via seccomp user-notify is Linux-only.
func startNotifyHandler(ctx context.Context, parentSock *os.File, sessID string, pol *policy.Engine, store eventStore, broker eventBroker, execveHandler any, fileMonitorCfg config.SandboxSeccompFileMonitorConfig, landlockEnabled bool, blockList any, ptraceReady chan<- error, commandJailRequired bool, approvalsMgr *approvals.Manager, sess *session.Session, expectedWrapperPID int, compositionControlRoot string, compositionSetup *os.File, configureComposition compositionConfigurer) <-chan struct{} {
	done := make(chan struct{})
	defer close(done)
	// Unix socket enforcement not available on this platform
	if parentSock != nil {
		_ = parentSock.Close()
	}
	if compositionSetup != nil {
		_ = compositionSetup.Close()
	}
	if ptraceReady != nil {
		select {
		case ptraceReady <- fmt.Errorf("seccomp notify pre-exec barrier is unavailable on this build"):
		default:
		}
	}
	return done
}
