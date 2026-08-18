//go:build linux && cgo

package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/wraphandoff"
	"golang.org/x/sys/unix"
)

// acceptNotifyFDLineage owns the production two-phase client-spawned handoff.
// Returning true prevents the legacy one-packet implementation in wrap.go from
// running. The legacy body remains only as a source-compatibility fallback on
// non-Linux builds and for removal in a later protocol cleanup.
func (a *App) acceptNotifyFDLineage(ctx context.Context, listener net.Listener, socketPath, sessionID string, s *session.Session, execveEnabled bool, expectedUID int, shimMode bool, approvalUI *approvalUIEndpoint) bool {
	// Production wrap-init always binds the exact serialized wrapper config.
	// Direct legacy unit callers intentionally omit it and continue through the
	// one-packet compatibility body in wrap.go.
	if _, bound := ctx.Value(wrapSeccompConfigContextKey{}).(seccompWrapperConfig); !bound {
		return false
	}
	_ = shimMode
	defer listener.Close()
	defer os.RemoveAll(filepath.Dir(socketPath))
	if unixListener, ok := listener.(*net.UnixListener); ok {
		_ = unixListener.SetDeadline(time.Now().Add(30 * time.Second))
	}

	var connection *net.UnixConn
	var peer peerCreds
	for {
		next, err := listener.Accept()
		if err != nil {
			slog.Debug("wrap: lineage accept failed", "error", err, "session_id", sessionID)
			return true
		}
		candidate, ok := next.(*net.UnixConn)
		if !ok {
			_ = next.Close()
			continue
		}
		peer = getConnPeerCreds(candidate)
		if expectedUID < 0 || expectedUID > 0 && peer.UID != uint32(expectedUID) {
			_ = candidate.Close()
			if expectedUID < 0 {
				return true
			}
			continue
		}
		connection = candidate
		break
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(30 * time.Second))

	prelude, err := wraphandoff.RecvPrelude(connection)
	if err != nil {
		_ = wraphandoff.WriteStatus(connection, false)
		slog.Debug("wrap: lineage prelude rejected", "error", err, "session_id", sessionID)
		return true
	}
	wrapperPID := prelude.WrapperPID
	wrapperPin, err := validateWrapperPIDForNotifyHook(wrapperPID, peer.PID, peer.UID)
	if err != nil {
		_ = wraphandoff.WriteStatus(connection, false)
		slog.Warn("wrap: untrusted lineage wrapper prelude", "error", err, "wrapper_pid", wrapperPID, "peer_pid", peer.PID, "session_id", sessionID)
		return true
	}
	if wrapperPin != nil {
		defer wrapperPin.Close()
	}

	commandBoundary := commandJailRequirements(commandJailRequired(a.cfg))
	if (commandBoundary != nil) != prelude.CommandJail || commandBoundary != nil && !commandBoundary.Complete() {
		_ = wraphandoff.WriteStatus(connection, false)
		slog.Warn("wrap: lineage command-jail capability mismatch", "wrapper_pid", wrapperPID, "session_id", sessionID)
		return true
	}
	if commandBoundary != nil && !wrapNeedsCgroupBeforeAck(a, s) {
		_ = wraphandoff.WriteStatus(connection, false)
		return true
	}

	var strictUnlock func()
	lockTransferred := false
	defer func() {
		if strictUnlock != nil && !lockTransferred {
			strictUnlock()
		}
	}()
	if commandBoundary != nil && s != nil {
		strictUnlock, err = s.LockExecContext(ctx)
		if err != nil {
			_ = wraphandoff.WriteStatus(connection, false)
			return true
		}
		ctx = context.WithValue(ctx, wrapExecLockContextKey{}, true)
	}

	barrier := newPreExecBarrier(func(pid int) (func() error, error) {
		return wrapCgroupSetupForNotifyHook(ctx, a, s, sessionID, pid)
	})
	if wrapNeedsCgroupBeforeAck(a, s) {
		if err := barrier.Enforce(wrapperPID); err != nil {
			_ = wraphandoff.WriteStatus(connection, false)
			_ = terminatePinnedWrapper(wrapperPin)
			if cleanupErr := barrier.Cleanup(); cleanupErr != nil {
				err = errors.Join(err, cleanupErr)
			}
			slog.Warn("wrap: pre-fork cgroup setup failed", "error", err, "wrapper_pid", wrapperPID, "session_id", sessionID)
			return true
		}
	}
	cleanup := barrier.CleanupFunc()
	if strictUnlock != nil {
		boundaryCleanup := cleanup
		var releaseOnce sync.Once
		cleanup = func() error {
			cleanupErr := boundaryCleanup()
			releaseOnce.Do(strictUnlock)
			return cleanupErr
		}
		lockTransferred = true
	}
	cleanupTransferred := false
	defer func() {
		if cleanupTransferred || cleanup == nil {
			return
		}
		_ = terminatePinnedWrapper(wrapperPin)
		_ = cleanup()
	}()

	if wrapperPin != nil {
		if err := validateWrapperPIDPinForNotify(wrapperPin); err != nil {
			_ = wraphandoff.WriteStatus(connection, false)
			return true
		}
	}
	if err := wraphandoff.WriteStatus(connection, true); err != nil {
		return true
	}

	handoff, err := wraphandoff.RecvHandoff(connection)
	if err != nil || handoff == nil || handoff.NotifyFD == nil {
		if handoff != nil {
			handoff.Close()
		}
		_ = wraphandoff.WriteStatus(connection, false)
		slog.Debug("wrap: lineage payload handoff failed", "error", err, "wrapper_pid", wrapperPID, "session_id", sessionID)
		return true
	}
	defer handoff.Close()
	meta := handoff.Metadata
	if !handoff.HasMetadata || meta.WrapperPID != wrapperPID || meta.PayloadPID <= 0 || meta.CommandJail != prelude.CommandJail || !payloadLineageMatches(meta.PayloadPID, wrapperPID) {
		_ = wraphandoff.WriteStatus(connection, false)
		slog.Warn("wrap: lineage payload identity rejected", "wrapper_pid", wrapperPID, "payload_pid", meta.PayloadPID, "session_id", sessionID)
		return true
	}
	if meta.FileLookupBroker != (handoff.FileLookupBroker != nil) {
		_ = wraphandoff.WriteStatus(connection, false)
		return true
	}

	expectedConfig, configBound := ctx.Value(wrapSeccompConfigContextKey{}).(seccompWrapperConfig)
	compositionSelected := configBound && expectedConfig.SandboxComposition != ""
	if !configBound {
		compositionSelected = s != nil && s.CurrentSandboxComposition() != ""
	}
	if compositionSelected != (handoff.CompositionSetup != nil) || compositionSelected != meta.CompositionSetup {
		_ = wraphandoff.WriteStatus(connection, false)
		return true
	}

	notifyFD := handoff.NotifyFD
	compositionSetup := handoff.CompositionSetup
	lookupEndpoint := handoff.FileLookupBroker
	handoff.NotifyFD = nil
	handoff.CompositionSetup = nil
	handoff.FileLookupBroker = nil
	lineageContext := wrapLineageContext{PayloadPID: meta.PayloadPID, FileLookupBroker: lookupEndpoint}
	ctx = context.WithValue(ctx, wrapLineageContextKey{}, lineageContext)
	if err := startNotifyHandlerForWrapHook(ctx, notifyFD, compositionSetup, sessionID, a, execveEnabled, wrapperPID, s, cleanup); err != nil {
		_ = wraphandoff.WriteStatus(connection, false)
		_ = notifyFD.Close()
		if lookupEndpoint != nil {
			_ = lookupEndpoint.Close()
		}
		if compositionSetup != nil {
			_ = compositionSetup.Close()
		}
		slog.Warn("wrap: lineage notify handler failed", "error", err, "wrapper_pid", wrapperPID, "payload_pid", meta.PayloadPID, "session_id", sessionID)
		return true
	}
	cleanupTransferred = true
	if approvalUI != nil {
		approvalUI.SetAuthorizedPID(meta.PayloadPID)
	}
	if err := wraphandoff.WriteStatus(connection, true); err != nil {
		slog.Debug("wrap: write lineage payload status failed", "error", err, "session_id", sessionID)
	}
	return true
}

func terminatePinnedWrapper(pin *os.File) error {
	if pin == nil {
		return nil
	}
	if err := unix.PidfdSendSignal(int(pin.Fd()), unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("terminate trusted wrapper: %w", err)
	}
	return nil
}
