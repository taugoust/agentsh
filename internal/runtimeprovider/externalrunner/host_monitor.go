package externalrunner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/guestcontrol"
	"github.com/agentsh/agentsh/internal/runtimeprovider"
)

const hostMonitorRunnerLogLimit = 8 << 20

type hostMonitorControl interface {
	Hello(context.Context, bool) (guestcontrol.Handshake, error)
	Shutdown(context.Context) error
}

type hostMonitorRelay interface {
	Path() string
	Serve(context.Context) error
	Close() error
}

type hostRunnerResult struct {
	Exit HostRunnerExit
	Err  error
}

type hostRunner interface {
	Identity() HostProcessIdentity
	Done() <-chan hostRunnerResult
	ForceStop() error
	EnsureStopped(context.Context) (*hostRunnerResult, error)
}

type hostMonitorDeps struct {
	newControl     func(guestcontrol.Manifest) (hostMonitorControl, error)
	newRelay       func(string, hostMonitorControl) (hostMonitorRelay, error)
	startRunner    func(Profile, HostMonitorLayout, uint32, io.Writer) (hostRunner, error)
	validateRunner func(Profile) error
	lock           func(context.Context, string) (io.Closer, error)
	now            func() time.Time
}

// RunHostMonitor owns one fixed external runner until exact terminal teardown.
// Its only caller-controlled input is a protected session state directory.
func RunHostMonitor(ctx context.Context, stateDir string) error {
	return runHostMonitor(ctx, stateDir, productionHostMonitorDeps())
}

func runHostMonitor(ctx context.Context, stateDir string, deps hostMonitorDeps) (returnErr error) {
	layout, err := validateHostMonitorLayout(stateDir)
	if err != nil {
		return err
	}
	lock, err := deps.lock(ctx, layout.LockPath)
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, statErr := os.Lstat(layout.StatusPath); !errors.Is(statErr, os.ErrNotExist) {
		if statErr == nil {
			return fmt.Errorf("host monitor request has already been consumed")
		}
		return fmt.Errorf("inspect existing host monitor status: %w", statErr)
	}
	request, err := ReadHostMonitorRequest(stateDir)
	if err != nil {
		return err
	}
	profile, profileFileDigest, err := ReadProfileSnapshot(request.ProfileFile)
	if err != nil {
		return err
	}
	if err := validateProviderLifecycleProfile(profile); err != nil {
		return err
	}
	if profile.ProfileDigest == "" || profile.Name == "" {
		return fmt.Errorf("host monitor external profile identity is incomplete")
	}
	if err := deps.validateRunner(profile); err != nil {
		return err
	}
	manifest, manifestDigest, err := ReadHostGuestManifestSnapshot(
		layout.GuestManifest, profile.Guest.Workspace, profile.Name,
		profile.Guest.ProfileDigest, []string{profile.Guest.Policy},
	)
	if err != nil {
		return fmt.Errorf("hash host monitor guest manifest: %w", err)
	}
	if err := validateHostMonitorBindings(request, profile, profileFileDigest, manifest, manifestDigest); err != nil {
		return err
	}
	if err := VerifyCIDLease(ctx, request.CIDLeaseRoot, request.CIDLease, profile.VSock.CIDMin, profile.VSock.CIDMax); err != nil {
		return fmt.Errorf("verify host monitor CID lease: %w", err)
	}

	startIdentity, bootID, err := detached.CurrentProcessIdentity(os.Getpid())
	if err != nil {
		return err
	}
	now := deps.now()
	status := HostMonitorStatus{
		SchemaVersion: HostMonitorSchemaVersion, Revision: 1,
		MonitorID: request.MonitorID, SessionID: request.SessionID,
		Profile: profile.Name, ExternalProfileDigest: profile.ProfileDigest, GuestProfileDigest: profile.Guest.ProfileDigest,
		State: HostMonitorInitializing, CreatedAt: now, UpdatedAt: now,
		Monitor:     HostProcessIdentity{PID: os.Getpid(), StartIdentity: startIdentity, BootID: bootID},
		RelayClosed: true,
	}
	persist := func(state HostMonitorState) error {
		status.State = state
		status.Revision++
		status.UpdatedAt = deps.now()
		return writeHostMonitorStatus(layout.StatusPath, status)
	}
	persistRequired := func(state HostMonitorState) {
		for {
			if err := persist(state); err == nil {
				return
			}
			time.Sleep(time.Second)
		}
	}
	if err := writeHostMonitorStatus(layout.StatusPath, status); err != nil {
		return err
	}

	logFile, err := os.OpenFile(layout.RunnerLog, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		status.LastError = boundedHostMonitorError(err, manifest.ControlToken, manifest.SupervisorToken, manifest.LaunchNonce)
		persistErr := persist(HostMonitorFailed)
		return errors.Join(fmt.Errorf("create host monitor runner log: %w", err), persistErr)
	}
	logWriter := &boundedLogWriter{writer: logFile, remaining: hostMonitorRunnerLogLimit}
	runner, err := deps.startRunner(profile, layout, manifest.VSockCID, logWriter)
	if err != nil {
		_ = logFile.Close()
		status.LastError = boundedHostMonitorError(err, manifest.ControlToken, manifest.SupervisorToken, manifest.LaunchNonce)
		persistErr := persist(HostMonitorFailed)
		return errors.Join(fmt.Errorf("start host monitor runner: %w", err), persistErr)
	}
	status.Runner = pointerTo(runner.Identity())
	status.RelayClosed = true
	if err := persist(HostMonitorBooting); err != nil {
		status.LastError = boundedHostMonitorError(err, manifest.ControlToken, manifest.SupervisorToken, manifest.LaunchNonce)
		persistRequired(HostMonitorStopping)
		forceErr := runner.ForceStop()
		var cleanupErr error
		for {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			result, attemptErr := runner.EnsureStopped(cleanupCtx)
			cancel()
			cleanupErr = attemptErr
			if result != nil {
				status.RunnerExit = &result.Exit
			}
			if cleanupErr == nil {
				status.RunnerReaped = true
				break
			}
			status.LastError = boundedHostMonitorError(errors.Join(err, forceErr, cleanupErr), manifest.ControlToken, manifest.SupervisorToken, manifest.LaunchNonce)
			_ = persist(HostMonitorFailed)
			_ = runner.ForceStop()
			time.Sleep(time.Second)
		}
		status.LastError = boundedHostMonitorError(errors.Join(err, forceErr), manifest.ControlToken, manifest.SupervisorToken, manifest.LaunchNonce)
		persistRequired(HostMonitorFailed)
		_ = logFile.Close()
		return errors.Join(err, forceErr)
	}

	var relay hostMonitorRelay
	var control hostMonitorControl
	var runnerResult *hostRunnerResult
	terminalState := HostMonitorStopped
	stopRequested := false
	forced := false
	cause := error(nil)

	readinessCtx, cancelReadiness := context.WithTimeout(ctx, profile.ReadinessTimeout())
	control, err = deps.newControl(manifest)
	if err == nil {
		var handshake guestcontrol.Handshake
		handshake, err = waitForHostGuest(readinessCtx, control, profile.Network.RequireReadyBeforePublish, runner.Done(), &runnerResult)
		if err == nil {
			secret := HostMonitorGuestSecret{
				SchemaVersion: HostMonitorSchemaVersion, MonitorID: request.MonitorID, SessionID: request.SessionID,
				Generation: handshake.Generation, IncarnationID: handshake.IncarnationID, EventToken: handshake.EventToken,
			}
			if secretErr := WriteHostMonitorGuestSecret(stateDir, request, secret); secretErr != nil {
				err = fmt.Errorf("persist authenticated guest control credential: %w", secretErr)
			} else if verifyErr := VerifyCIDLease(readinessCtx, request.CIDLeaseRoot, request.CIDLease, profile.VSock.CIDMin, profile.VSock.CIDMax); verifyErr != nil {
				err = fmt.Errorf("reverify host monitor CID lease before publication: %w", verifyErr)
			} else if relayPathErr := prepareHostMonitorRelayPath(layout.RelayPath); relayPathErr != nil {
				err = relayPathErr
			} else {
				relay, err = deps.newRelay(layout.RelayPath, control)
				if err == nil {
					guestIdentity := publicHostGuestIdentity(handshake)
					status.Guest = &guestIdentity
					status.Endpoint = &runtimeprovider.Endpoint{Transport: "unix", Address: relay.Path()}
					status.RelayClosed = false
					err = persist(HostMonitorControlReady)
				}
			}
		}
	}
	cancelReadiness()
	if err != nil {
		if ctx.Err() != nil {
			stopRequested = true
			cause = nil
		} else {
			terminalState = HostMonitorFailed
			cause = err
		}
	}

	relayResults := make(chan error, 1)
	relayCtx, cancelRelay := context.WithCancel(context.Background())
	relayStarted := false
	relayJoined := false
	if cause == nil && relay != nil {
		relayStarted = true
		go func() { relayResults <- relay.Serve(relayCtx) }()
		select {
		case result := <-runner.Done():
			runnerResult = &result
			terminalState = HostMonitorFailed
			cause = fmt.Errorf("external runner exited before stop")
		case relayErr := <-relayResults:
			relayJoined = true
			terminalState = HostMonitorFailed
			if relayErr == nil {
				cause = fmt.Errorf("host supervisor relay stopped unexpectedly")
			} else {
				cause = fmt.Errorf("host supervisor relay stopped: %w", relayErr)
			}
		case <-ctx.Done():
			stopRequested = true
			cause = nil
		}
	}

	status.StopRequested = stopRequested
	status.LastError = boundedHostMonitorError(cause, manifest.ControlToken, manifest.SupervisorToken, manifest.LaunchNonce)
	if status.Runner != nil {
		persistRequired(HostMonitorStopping)
	}
	cancelRelay()
	if relay != nil {
		closeErr := relay.Close()
		status.RelayClosed = closeErr == nil
		if closeErr != nil {
			cause = errors.Join(cause, closeErr)
			terminalState = HostMonitorFailed
		}
	} else {
		status.RelayClosed = true
	}
	for relayStarted && !relayJoined {
		select {
		case relayErr := <-relayResults:
			relayJoined = true
			if relayErr != nil && !errors.Is(relayErr, context.Canceled) {
				cause = errors.Join(cause, relayErr)
				terminalState = HostMonitorFailed
			}
		case <-time.After(5 * time.Second):
			status.RelayClosed = false
			cause = errors.Join(cause, fmt.Errorf("host supervisor relay did not terminate"))
			terminalState = HostMonitorFailed
			status.LastError = boundedHostMonitorError(cause, manifest.ControlToken, manifest.SupervisorToken, manifest.LaunchNonce)
			_ = persist(HostMonitorFailed)
		}
	}
	if control != nil && runnerResult == nil {
		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), profile.GracefulShutdownTimeout())
		shutdownErr := control.Shutdown(shutdownCtx)
		cancelShutdown()
		if shutdownErr != nil {
			cause = errors.Join(cause, fmt.Errorf("guest shutdown: %w", shutdownErr))
		}
	}
	if runnerResult == nil {
		timer := time.NewTimer(profile.GracefulShutdownTimeout())
		select {
		case result := <-runner.Done():
			runnerResult = &result
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
			forced = true
			if forceErr := runner.ForceStop(); forceErr != nil {
				cause = errors.Join(cause, forceErr)
				terminalState = HostMonitorFailed
			}
		}
	}
	for {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 5*time.Second)
		ensuredResult, ensureErr := runner.EnsureStopped(cleanupCtx)
		cancelCleanup()
		if ensuredResult != nil {
			runnerResult = ensuredResult
		}
		if ensureErr == nil {
			break
		}
		cause = errors.Join(cause, ensureErr)
		terminalState = HostMonitorFailed
		status.LastError = boundedHostMonitorError(cause, manifest.ControlToken, manifest.SupervisorToken, manifest.LaunchNonce)
		status.RunnerReaped = false
		_ = persist(HostMonitorFailed)
		_ = runner.ForceStop()
		time.Sleep(time.Second)
	}
	_ = logFile.Sync()
	if closeErr := logFile.Close(); closeErr != nil {
		cause = errors.Join(cause, closeErr)
		terminalState = HostMonitorFailed
	}
	if runnerResult != nil {
		status.RunnerExit = &runnerResult.Exit
		status.RunnerReaped = true
		if runnerResult.Err != nil && !forced {
			cause = errors.Join(cause, runnerResult.Err)
			if !stopRequested {
				terminalState = HostMonitorFailed
			}
		}
	}
	status.Forced = forced
	status.LastError = boundedHostMonitorError(cause, manifest.ControlToken, manifest.SupervisorToken, manifest.LaunchNonce)
	persistRequired(terminalState)
	if terminalState == HostMonitorFailed {
		return cause
	}
	return nil
}

func waitForHostGuest(ctx context.Context, control hostMonitorControl, requireNetwork bool, done <-chan hostRunnerResult, runnerResult **hostRunnerResult) (guestcontrol.Handshake, error) {
	for {
		attemptCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		handshake, err := control.Hello(attemptCtx, requireNetwork)
		cancel()
		if err == nil {
			return handshake, nil
		}
		select {
		case result := <-done:
			*runnerResult = &result
			return guestcontrol.Handshake{}, fmt.Errorf("external runner exited before authenticated readiness: %w", result.Err)
		case <-ctx.Done():
			return guestcontrol.Handshake{}, fmt.Errorf("wait for authenticated guest readiness: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func validateHostMonitorBindings(request HostMonitorRequest, profile Profile, profileFileDigest string, manifest guestcontrol.Manifest, manifestDigest string) error {
	if request.SessionID != manifest.SessionID || request.CIDLease.CID != manifest.VSockCID ||
		request.ProfileFileSHA256 != profileFileDigest || request.ProfileName != profile.Name || request.ProfileDigest != profile.ProfileDigest || request.GuestProfileDigest != profile.Guest.ProfileDigest ||
		request.GuestManifestSHA256 != manifestDigest || request.ExpectedGuestGeneration != manifest.ExpectedGeneration || request.LaunchNonce != manifest.LaunchNonce ||
		request.GuestPolicy != manifest.Policy || request.GuestControlPort != manifest.VSockPort || request.GuestSupervisorPort != manifest.SupervisorPort ||
		profile.Name != manifest.Profile || profile.Guest.ProfileDigest != manifest.ProfileDigest ||
		profile.Guest.Policy != manifest.Policy || profile.Guest.ControlPort != manifest.VSockPort ||
		profile.Guest.SupervisorPort != manifest.SupervisorPort {
		return fmt.Errorf("host monitor request, profile, lease, and guest manifest identities differ")
	}
	return nil
}

func validateHostMonitorLayout(stateDir string) (HostMonitorLayout, error) {
	layout, err := HostMonitorPaths(stateDir)
	if err != nil {
		return HostMonitorLayout{}, err
	}
	for name, path := range map[string]string{
		"state": layout.StateDir, "runtime": layout.RuntimeDir, "workspace": layout.WorkspaceDir,
		"control": layout.ControlDir, "host": layout.HostDir, "logs": layout.LogsDir,
	} {
		if err := validateHostMonitorDirectory(path); err != nil {
			return HostMonitorLayout{}, fmt.Errorf("host monitor %s directory is missing or unsafe: %w", name, err)
		}
	}
	return layout, nil
}

func boundedHostMonitorError(err error, secrets ...string) string {
	if err == nil {
		return ""
	}
	message := strings.ReplaceAll(err.Error(), "\x00", "")
	for _, secret := range secrets {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[redacted]")
		}
	}
	if len(message) > 4096 {
		message = message[:4096]
	}
	return message
}

func pointerTo[T any](value T) *T { return &value }

type boundedLogWriter struct {
	mu        sync.Mutex
	writer    io.Writer
	remaining int64
}

func (w *boundedLogWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	original := len(data)
	if w.remaining <= 0 {
		return original, nil
	}
	if int64(len(data)) > w.remaining {
		data = data[:w.remaining]
	}
	written, err := w.writer.Write(data)
	w.remaining -= int64(written)
	if err != nil {
		return written, err
	}
	return original, nil
}
