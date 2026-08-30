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
	"github.com/agentsh/agentsh/internal/runtimeprovider/artifact"
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
	newControl func(guestcontrol.Manifest) (hostMonitorControl, error)
	newRelay   func(string, hostMonitorControl) (hostMonitorRelay, error)
	// createVolume atomically creates or idempotently reopens the request-bound
	// volume. startRunner must return a non-nil cleanup handle with an error if a
	// direct child may have started.
	createVolume      func(context.Context, WorkspaceVolumeRequest, string) (*WorkspaceVolume, error)
	startEgressBroker func(context.Context, Profile, HostMonitorLayout, string, uint32, uint32, string, *HostEgressApprovalBinding) (hostEgressBroker, error)
	startRunner       func(Profile, HostMonitorLayout, uint32, *WorkspaceVolume, io.Writer) (hostRunner, error)
	validateRunner    func(Profile) error
	lock              func(context.Context, string) (io.Closer, error)
	now               func() time.Time
}

// RunHostMonitor owns one fixed external runner, any v2-or-later workspace
// volume, and any v3 host egress broker until exact terminal teardown. Its only
// caller-controlled input is a protected session state directory.
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
	if profile.ProfileDigest == "" || profile.Name == "" {
		return fmt.Errorf("host monitor external profile identity is incomplete")
	}
	if err := validateHostMonitorProfileBinding(request, profile, profileFileDigest); err != nil {
		return err
	}
	if err := validateHostMonitorWorkspaceLayout(profile, layout); err != nil {
		return err
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
		SchemaVersion: request.SchemaVersion, Revision: 1,
		MonitorID: request.MonitorID, SessionID: request.SessionID,
		Profile: profile.Name, ExternalProfileDigest: profile.ProfileDigest, GuestProfileDigest: profile.Guest.ProfileDigest,
		VolumeID: request.VolumeID,
		State:    HostMonitorInitializing, CreatedAt: now, UpdatedAt: now,
		Monitor:            HostProcessIdentity{PID: os.Getpid(), StartIdentity: startIdentity, BootID: bootID},
		RelayClosed:        true,
		EgressBrokerClosed: profile.Schema == ProfileSchemaV3,
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

	volumeRequired := profile.Schema == ProfileSchemaV2 || profile.Schema == ProfileSchemaV3
	var volume *WorkspaceVolume
	closeVolume := func() error {
		if !volumeRequired {
			return nil
		}
		if volume == nil {
			status.VolumeClosed = true
			return nil
		}
		closeErr := volume.Close()
		if closeErr == nil {
			status.VolumeClosed = true
		}
		return closeErr
	}
	if volumeRequired {
		volumeRequest := WorkspaceVolumeRequest{
			StateDir: stateDir, SessionID: request.SessionID,
			Profile: profile, ProfileFileSHA256: profileFileDigest,
		}
		var openErr error
		if deps.createVolume == nil {
			openErr = fmt.Errorf("host monitor workspace volume dependency is missing")
		} else {
			// The immutable schema-v2 request and initial status are durable before
			// this first lease or volume state can exist.
			volume, openErr = deps.createVolume(ctx, volumeRequest, request.VolumeID)
		}
		if openErr == nil {
			openErr = validateCreatedHostMonitorVolume(volume, volumeRequest, request.VolumeID)
		}
		if openErr != nil {
			closeErr := closeVolume()
			cause := errors.Join(openErr, closeErr)
			status.LastError = boundedHostMonitorError(cause, manifest.ControlToken, manifest.SupervisorToken, manifest.EgressToken, manifest.LaunchNonce)
			persistErr := persist(HostMonitorFailed)
			return errors.Join(fmt.Errorf("create or reopen exact host monitor workspace volume: %w", openErr), closeErr, persistErr)
		}
	}

	logFile, err := os.OpenFile(layout.RunnerLog, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		closeErr := closeVolume()
		cause := errors.Join(err, closeErr)
		status.LastError = boundedHostMonitorError(cause, manifest.ControlToken, manifest.SupervisorToken, manifest.EgressToken, manifest.LaunchNonce)
		persistErr := persist(HostMonitorFailed)
		return errors.Join(fmt.Errorf("create host monitor runner log: %w", err), closeErr, persistErr)
	}
	logWriter := &boundedLogWriter{writer: logFile, remaining: hostMonitorRunnerLogLimit}

	brokerRequired := profile.Schema == ProfileSchemaV3
	var broker hostEgressBroker
	closeBroker := func() error {
		if !brokerRequired {
			return nil
		}
		if broker == nil {
			status.EgressBrokerClosed = true
			return nil
		}
		closing := broker
		closeErr := closing.Close()
		select {
		case <-closing.Done():
			status.EgressBrokerClosed = true
		default:
			closeErr = errors.Join(closeErr, fmt.Errorf("host egress broker close returned before done"))
			status.EgressBrokerClosed = false
		}
		closeErr = errors.Join(closeErr, closing.Err())
		broker = nil
		return closeErr
	}
	if brokerRequired {
		var brokerErr error
		if deps.startEgressBroker == nil {
			brokerErr = fmt.Errorf("host monitor egress broker dependency is missing")
		} else {
			broker, brokerErr = deps.startEgressBroker(ctx, profile, layout, request.SessionID, request.CIDLease.CID, request.EgressPort, manifest.EgressToken, request.HostEgressApproval)
		}
		if brokerErr == nil && broker == nil {
			brokerErr = fmt.Errorf("host monitor egress broker startup returned no exact handle")
		}
		if brokerErr != nil {
			brokerCloseErr := closeBroker()
			logErr := errors.Join(logFile.Sync(), logFile.Close())
			volumeCloseErr := closeVolume()
			cause := errors.Join(brokerErr, brokerCloseErr, logErr, volumeCloseErr)
			status.LastError = boundedHostMonitorError(cause, manifest.ControlToken, manifest.SupervisorToken, manifest.EgressToken, manifest.LaunchNonce)
			persistErr := persist(HostMonitorFailed)
			return errors.Join(fmt.Errorf("start host monitor egress broker: %w", brokerErr), brokerCloseErr, logErr, volumeCloseErr, persistErr)
		}
		status.EgressBrokerClosed = false
		if err := persist(HostMonitorInitializing); err != nil {
			brokerCloseErr := closeBroker()
			logErr := errors.Join(logFile.Sync(), logFile.Close())
			volumeCloseErr := closeVolume()
			cause := errors.Join(err, brokerCloseErr, logErr, volumeCloseErr)
			status.LastError = boundedHostMonitorError(cause, manifest.ControlToken, manifest.SupervisorToken, manifest.EgressToken, manifest.LaunchNonce)
			persistErr := persist(HostMonitorFailed)
			return errors.Join(err, brokerCloseErr, logErr, volumeCloseErr, persistErr)
		}
	}

	runner, err := deps.startRunner(profile, layout, manifest.VSockCID, volume, logWriter)
	if err == nil && runner == nil {
		err = fmt.Errorf("external runner startup returned no exact runner handle")
	}
	if err != nil {
		startupErr := err
		brokerCloseErr := closeBroker()
		var cleanupErr error
		if runner != nil {
			// A non-nil runner paired with a startup error means a direct child may
			// exist. Reaping uses bounded attempts but fails closed indefinitely: no
			// terminal failure is published and no volume lease is released until an
			// exact exit result is available.
			var startupChildResult *hostRunnerResult
			startupChildResult, cleanupErr = reapPartiallyStartedHostRunner(runner, func(attemptErr error) {
				status.LastError = boundedHostMonitorError(errors.Join(startupErr, attemptErr), manifest.ControlToken, manifest.SupervisorToken, manifest.EgressToken, manifest.LaunchNonce)
				_ = persist(HostMonitorInitializing)
			})
			if (request.SchemaVersion == HostMonitorSchemaVersionV2 || request.SchemaVersion == HostMonitorSchemaVersionV3) && startupChildResult != nil {
				// A partially-started child has no publishable process identity. Keep
				// its exact exit separate from true no-child prelaunch evidence.
				status.StartupChildReaped = true
				status.RunnerExit = pointerTo(startupChildResult.Exit)
			}
		}
		logErr := errors.Join(logFile.Sync(), logFile.Close())
		closeErr := closeVolume()
		cause := errors.Join(startupErr, cleanupErr, brokerCloseErr, logErr, closeErr)
		status.LastError = boundedHostMonitorError(cause, manifest.ControlToken, manifest.SupervisorToken, manifest.EgressToken, manifest.LaunchNonce)
		persistErr := persist(HostMonitorFailed)
		return errors.Join(fmt.Errorf("start host monitor runner: %w", startupErr), cleanupErr, brokerCloseErr, logErr, closeErr, persistErr)
	}
	status.Runner = pointerTo(runner.Identity())
	status.RelayClosed = true
	if err := persist(HostMonitorBooting); err != nil {
		status.LastError = boundedHostMonitorError(err, manifest.ControlToken, manifest.SupervisorToken, manifest.EgressToken, manifest.LaunchNonce)
		persistRequired(HostMonitorStopping)
		brokerCloseErr := closeBroker()
		status.LastError = boundedHostMonitorError(errors.Join(err, brokerCloseErr), manifest.ControlToken, manifest.SupervisorToken, manifest.EgressToken, manifest.LaunchNonce)
		persistRequired(HostMonitorStopping)
		forceErr := runner.ForceStop()
		var cleanupErr error
		for {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			result, attemptErr := runner.EnsureStopped(cleanupCtx)
			cancel()
			if result != nil {
				status.RunnerExit = &result.Exit
			}
			if result != nil && attemptErr == nil {
				status.RunnerReaped = true
				cleanupErr = nil
				break
			}
			if attemptErr == nil {
				attemptErr = fmt.Errorf("external runner reaping returned no exact exit result")
			}
			cleanupErr = attemptErr
			status.LastError = boundedHostMonitorError(errors.Join(err, brokerCloseErr, forceErr, cleanupErr), manifest.ControlToken, manifest.SupervisorToken, manifest.EgressToken, manifest.LaunchNonce)
			_ = persist(HostMonitorFailed)
			_ = runner.ForceStop()
			time.Sleep(time.Second)
		}
		volumeCloseErr := closeVolume()
		status.LastError = boundedHostMonitorError(errors.Join(err, brokerCloseErr, forceErr, cleanupErr, volumeCloseErr), manifest.ControlToken, manifest.SupervisorToken, manifest.EgressToken, manifest.LaunchNonce)
		persistRequired(HostMonitorFailed)
		_ = logFile.Close()
		return errors.Join(err, brokerCloseErr, forceErr, cleanupErr, volumeCloseErr)
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
		requireDirectNetwork := profile.Network.RequireReadyBeforePublish && profile.Schema != ProfileSchemaV3
		handshake, err = waitForHostGuest(readinessCtx, control, requireDirectNetwork, runner.Done(), &runnerResult, broker)
		if err == nil {
			err = validateHostMonitorGuestReadiness(request, profile, manifest, volume, handshake)
		}
		if err == nil && (request.SchemaVersion == HostMonitorSchemaVersionV2 || request.SchemaVersion == HostMonitorSchemaVersionV3) {
			err = importHostMonitorGitInput(readinessCtx, stateDir, request, control)
		}
		if err == nil {
			err = hostEgressBrokerHealth(broker)
		}
		if err == nil {
			secret := HostMonitorGuestSecret{
				SchemaVersion: HostMonitorSchemaVersionV1, MonitorID: request.MonitorID, SessionID: request.SessionID,
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
					err = hostEgressBrokerHealth(broker)
				}
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
	var brokerDone <-chan struct{}
	if broker != nil {
		brokerDone = broker.Done()
	}
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
		case <-brokerDone:
			terminalState = HostMonitorFailed
			if broker.Err() != nil {
				cause = fmt.Errorf("host egress broker failed: %w", broker.Err())
			} else {
				cause = fmt.Errorf("host egress broker stopped unexpectedly")
			}
		case <-ctx.Done():
			stopRequested = true
			cause = nil
		}
	}

	status.StopRequested = stopRequested
	status.LastError = boundedHostMonitorError(cause, manifest.ControlToken, manifest.SupervisorToken, manifest.EgressToken, manifest.LaunchNonce)
	if status.Runner != nil {
		// Publish stopping while the broker is still open. Closed evidence is
		// recorded only after its Done signal below.
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
			status.LastError = boundedHostMonitorError(cause, manifest.ControlToken, manifest.SupervisorToken, manifest.EgressToken, manifest.LaunchNonce)
			_ = persist(HostMonitorStopping)
		}
	}
	brokerCloseErr := closeBroker()
	if brokerCloseErr != nil {
		cause = errors.Join(cause, fmt.Errorf("close host egress broker: %w", brokerCloseErr))
		terminalState = HostMonitorFailed
	}
	status.LastError = boundedHostMonitorError(cause, manifest.ControlToken, manifest.SupervisorToken, manifest.EgressToken, manifest.LaunchNonce)
	if status.Runner != nil {
		// This second stopping revision is the first one allowed to claim that
		// the exact broker has closed.
		persistRequired(HostMonitorStopping)
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
		if ensuredResult != nil && ensureErr == nil {
			break
		}
		if ensureErr == nil {
			ensureErr = fmt.Errorf("external runner reaping returned no exact exit result")
		}
		cause = errors.Join(cause, ensureErr)
		terminalState = HostMonitorFailed
		status.LastError = boundedHostMonitorError(cause, manifest.ControlToken, manifest.SupervisorToken, manifest.EgressToken, manifest.LaunchNonce)
		status.RunnerReaped = false
		_ = persist(HostMonitorFailed)
		_ = runner.ForceStop()
		time.Sleep(time.Second)
	}
	status.RunnerExit = &runnerResult.Exit
	status.RunnerReaped = true
	// The monitor keeps both the mutable image descriptor and its exclusive
	// lease until EnsureStopped has reaped the exact direct runner/QEMU process.
	if closeErr := closeVolume(); closeErr != nil {
		cause = errors.Join(cause, fmt.Errorf("close exact host monitor workspace volume: %w", closeErr))
		terminalState = HostMonitorFailed
	}
	_ = logFile.Sync()
	if closeErr := logFile.Close(); closeErr != nil {
		cause = errors.Join(cause, closeErr)
		terminalState = HostMonitorFailed
	}
	if runnerResult.Err != nil && !forced {
		cause = errors.Join(cause, runnerResult.Err)
		if !stopRequested {
			terminalState = HostMonitorFailed
		}
	}
	status.Forced = forced
	status.LastError = boundedHostMonitorError(cause, manifest.ControlToken, manifest.SupervisorToken, manifest.EgressToken, manifest.LaunchNonce)
	persistRequired(terminalState)
	if terminalState == HostMonitorFailed {
		return cause
	}
	return nil
}

func reapPartiallyStartedHostRunner(runner hostRunner, onRetry func(error)) (*hostRunnerResult, error) {
	// Do not ask the runner to wait until process-group cleanup succeeds. Once
	// ForceStop succeeds, never signal again: EnsureStopped may reap the leader,
	// after which both its PID and PGID are reusable.
	for {
		forceErr := runner.ForceStop()
		if forceErr == nil {
			break
		}
		if onRetry != nil {
			onRetry(forceErr)
		}
		time.Sleep(time.Second)
	}
	for {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		result, ensureErr := runner.EnsureStopped(cleanupCtx)
		cancel()
		if result != nil {
			return result, ensureErr
		}
		if ensureErr == nil {
			ensureErr = fmt.Errorf("external runner reaping returned no exact exit result")
		}
		if onRetry != nil {
			onRetry(ensureErr)
		}
		time.Sleep(time.Second)
	}
}

func hostEgressBrokerHealth(broker hostEgressBroker) error {
	if broker == nil {
		return nil
	}
	select {
	case <-broker.Done():
		if err := broker.Err(); err != nil {
			return fmt.Errorf("host egress broker failed: %w", err)
		}
		return fmt.Errorf("host egress broker stopped unexpectedly")
	default:
		return nil
	}
}

func waitForHostGuest(ctx context.Context, control hostMonitorControl, requireNetwork bool, done <-chan hostRunnerResult, runnerResult **hostRunnerResult, broker hostEgressBroker) (guestcontrol.Handshake, error) {
	var brokerDone <-chan struct{}
	if broker != nil {
		brokerDone = broker.Done()
	}
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
		case <-brokerDone:
			if err := broker.Err(); err != nil {
				return guestcontrol.Handshake{}, fmt.Errorf("host egress broker failed before authenticated readiness: %w", err)
			}
			return guestcontrol.Handshake{}, fmt.Errorf("host egress broker stopped before authenticated readiness")
		case <-ctx.Done():
			return guestcontrol.Handshake{}, fmt.Errorf("wait for authenticated guest readiness: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func validateHostMonitorBindings(request HostMonitorRequest, profile Profile, profileFileDigest string, manifest guestcontrol.Manifest, manifestDigest string) error {
	if err := validateHostMonitorProfileBinding(request, profile, profileFileDigest); err != nil {
		return err
	}
	expectedEgressPort := request.EgressPort
	if profile.Schema == ProfileSchemaV3 {
		derivedPort, err := deriveHostEgressPort(profile, request.CIDLease.CID)
		if err != nil || expectedEgressPort != derivedPort {
			return fmt.Errorf("host monitor request has an invalid per-CID egress endpoint")
		}
	}
	if request.SessionID != manifest.SessionID || request.CIDLease.CID != manifest.VSockCID ||
		request.GuestProfileDigest != profile.Guest.ProfileDigest || request.VolumeID != manifest.VolumeID ||
		request.GuestManifestSHA256 != manifestDigest || request.ExpectedGuestGeneration != manifest.ExpectedGeneration || request.LaunchNonce != manifest.LaunchNonce ||
		request.GuestPolicy != manifest.Policy || request.GuestControlPort != manifest.VSockPort || request.GuestSupervisorPort != manifest.SupervisorPort ||
		profile.Name != manifest.Profile || profile.Guest.ProfileDigest != manifest.ProfileDigest || profile.Guest.Protocol != manifest.ProtocolVersion ||
		profile.Guest.Policy != manifest.Policy || profile.Guest.ControlPort != manifest.VSockPort ||
		profile.Guest.SupervisorPort != manifest.SupervisorPort || manifest.EgressPort != expectedEgressPort ||
		(profile.Schema == ProfileSchemaV3) != guestcontrol.ValidEgressAuthenticationToken(manifest.EgressToken) {
		return fmt.Errorf("host monitor request, profile, lease, and guest manifest identities differ")
	}
	return nil
}

type hostMonitorArtifactImporter interface {
	ImportArtifact(context.Context, guestcontrol.ArtifactTransfer, io.Reader) error
}

func importHostMonitorGitInput(ctx context.Context, stateDir string, request HostMonitorRequest, control hostMonitorControl) error {
	if request.InputArtifact == nil {
		return fmt.Errorf("host monitor v2 input artifact is missing")
	}
	importer, ok := control.(hostMonitorArtifactImporter)
	if !ok {
		return fmt.Errorf("guest control does not support authenticated artifact import")
	}
	store, err := artifact.NewStore(stateDir, request.SessionID, guestcontrol.MaxArtifactTransferBytes)
	if err != nil {
		return err
	}
	file, descriptor, err := store.Open(ctx, request.InputArtifact.ArtifactID, artifact.KindGitInputBundle)
	if err != nil {
		return fmt.Errorf("open exact Git input artifact: %w", err)
	}
	defer file.Close()
	if descriptor != *request.InputArtifact {
		return fmt.Errorf("Git input artifact descriptor changed before guest transfer")
	}
	transfer := guestcontrol.ArtifactTransfer{Kind: guestcontrol.ArtifactKindGitInputBundle, SHA256: descriptor.SHA256, Size: descriptor.Size}
	if err := importer.ImportArtifact(ctx, transfer, file); err != nil {
		return fmt.Errorf("import exact Git input artifact into guest: %w", err)
	}
	return nil
}

func validateHostMonitorGuestReadiness(request HostMonitorRequest, profile Profile, manifest guestcontrol.Manifest, volume *WorkspaceVolume, handshake guestcontrol.Handshake) error {
	if err := handshake.Validate(manifest); err != nil {
		return fmt.Errorf("validate authenticated guest readiness: %w", err)
	}
	if handshake.ProtocolVersion != profile.Guest.Protocol {
		return fmt.Errorf("authenticated guest protocol differs from the immutable operator profile")
	}
	switch request.SchemaVersion {
	case HostMonitorSchemaVersionV1:
		if profile.Schema != ProfileSchemaV1 || volume != nil || request.VolumeID != "" || manifest.VolumeID != "" || handshake.VolumeID != "" {
			return fmt.Errorf("legacy authenticated guest readiness contains workspace-volume state")
		}
	case HostMonitorSchemaVersionV2, HostMonitorSchemaVersionV3:
		expectedProfileSchema := ProfileSchemaV2
		expectedEgressPort := uint32(0)
		if request.SchemaVersion == HostMonitorSchemaVersionV3 {
			expectedProfileSchema = ProfileSchemaV3
			if request.HostEgress == nil {
				return fmt.Errorf("authenticated guest readiness lacks the immutable host egress contract")
			}
			expectedEgressPort = request.EgressPort
			if handshake.NetworkReady || !handshake.EgressReady {
				return fmt.Errorf("authenticated guest readiness must prove only the explicit egress proxy, not direct-network enforcement")
			}
		}
		if profile.Schema != expectedProfileSchema || volume == nil || volume.Image == nil ||
			!canonicalWorkspaceVolumeUUID(request.VolumeID) || volume.Manifest.VolumeID != request.VolumeID ||
			manifest.VolumeID != request.VolumeID || handshake.VolumeID != request.VolumeID || manifest.EgressPort != expectedEgressPort || handshake.EgressPort != expectedEgressPort {
			return fmt.Errorf("authenticated guest readiness does not prove the exact workspace volume and egress endpoint")
		}
		volumeRequest := WorkspaceVolumeRequest{
			StateDir: request.StateDir, SessionID: request.SessionID,
			Profile: profile, ProfileFileSHA256: request.ProfileFileSHA256,
		}
		if err := volume.Manifest.matches(volumeRequest, request.VolumeID); err != nil {
			return fmt.Errorf("authenticated guest readiness exact workspace volume: %w", err)
		}
	default:
		return fmt.Errorf("host monitor schema version %d is unsupported", request.SchemaVersion)
	}
	return nil
}

func validateHostMonitorLayout(stateDir string) (HostMonitorLayout, error) {
	layout, err := HostMonitorPaths(stateDir)
	if err != nil {
		return HostMonitorLayout{}, err
	}
	for name, path := range map[string]string{
		"state": layout.StateDir, "runtime": layout.RuntimeDir,
		"control": layout.ControlDir, "host": layout.HostDir, "logs": layout.LogsDir,
	} {
		if err := validateHostMonitorDirectory(path); err != nil {
			return HostMonitorLayout{}, fmt.Errorf("host monitor %s directory is missing or unsafe: %w", name, err)
		}
	}
	return layout, nil
}

func validateHostMonitorWorkspaceLayout(profile Profile, layout HostMonitorLayout) error {
	switch profile.Schema {
	case ProfileSchemaV1:
		if err := validateHostMonitorDirectory(layout.WorkspaceDir); err != nil {
			return fmt.Errorf("host monitor workspace directory is missing or unsafe: %w", err)
		}
	case ProfileSchemaV2, ProfileSchemaV3:
		if _, err := os.Lstat(layout.WorkspaceDir); err == nil {
			return fmt.Errorf("host monitor v2 runtime contains a forbidden staged workspace")
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect host monitor v2 staged workspace path: %w", err)
		}
	default:
		return fmt.Errorf("host monitor external profile schema %q is unsupported", profile.Schema)
	}
	return nil
}

func validateCreatedHostMonitorVolume(volume *WorkspaceVolume, request WorkspaceVolumeRequest, volumeID string) error {
	if volume == nil || volume.Image == nil {
		return fmt.Errorf("host monitor workspace volume create returned no exact image")
	}
	if err := volume.Manifest.matches(request, volumeID); err != nil {
		return err
	}
	if volume.RunnerFD() != WorkspaceVolumeRunnerFD {
		return fmt.Errorf("host monitor workspace volume runner descriptor differs from the fixed contract")
	}
	return nil
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
