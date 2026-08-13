package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/runtimeprovider"
	"github.com/agentsh/agentsh/pkg/types"
)

const detachedRuntimeCleanupTimeout = 30 * time.Second

var errLegacyRuntimeProviderIdentity = errors.New("legacy detached session has no runtime-provider identity")

type nativeRuntimeProvider struct {
	configPath      string
	preflightConfig *config.Config
}

func (p *nativeRuntimeProvider) Name() string { return runtimeprovider.NativeProvider }

func (p *nativeRuntimeProvider) Preflight(_ context.Context, request runtimeprovider.Request) (runtimeprovider.Capabilities, error) {
	if p == nil || p.preflightConfig == nil {
		return runtimeprovider.Capabilities{}, fmt.Errorf("native runtime provider configuration is unavailable")
	}
	if request.Provider != runtimeprovider.NativeProvider {
		return runtimeprovider.Capabilities{}, fmt.Errorf("native runtime provider cannot start provider %q", request.Provider)
	}
	return runtimeprovider.Capabilities{
		ContractVersion: runtimeprovider.ContractVersion,
		Provider:        runtimeprovider.NativeProvider,
		Recoverable:     true,
		Transports:      []string{"unix"},
	}, nil
}

func (p *nativeRuntimeProvider) Start(ctx context.Context, request runtimeprovider.Request) (runtimeprovider.Instance, error) {
	result, err := startNativeDetachedSupervisorSession(ctx, request, p.configPath, p.preflightConfig)
	if err != nil {
		// The native launcher may have crossed process start before a readiness
		// failure. Return an exact protected-metadata handle when available so the
		// controller verifies teardown instead of merely assuming the launcher's
		// best-effort defer succeeded.
		if meta, stateDir, readErr := readSupervisorMetadata(request.SessionID); readErr == nil && filepath.Clean(stateDir) == filepath.Clean(request.StateDir) {
			return newNativeRuntimeInstance(request.Profile, stateDir, meta, nil, detached.RuntimeStatus{}), err
		}
		return nil, err
	}
	return newNativeRuntimeInstance(request.Profile, request.StateDir, result.supervisorMetadata, &result.Session, detached.RuntimeStatus{}), nil
}

func (p *nativeRuntimeProvider) Open(_ context.Context, manifest runtimeprovider.Manifest) (runtimeprovider.Instance, error) {
	meta, stateDir, err := readSupervisorMetadata(manifest.SessionID)
	if err != nil {
		return nil, err
	}
	if filepath.Clean(stateDir) != filepath.Clean(manifest.StateDir) {
		return nil, fmt.Errorf("native runtime state directory identity mismatch")
	}
	if nativeRuntimeIdentity(manifest.Profile, meta) != manifest.Identity ||
		(runtimeprovider.Endpoint{Transport: "unix", Address: meta.SupervisorSock}) != manifest.Endpoint {
		return nil, fmt.Errorf("native runtime exact incarnation mismatch")
	}
	return newNativeRuntimeInstance(manifest.Profile, stateDir, meta, nil, detached.RuntimeStatus{}), nil
}

func (p *nativeRuntimeProvider) Recover(ctx context.Context, manifest runtimeprovider.Manifest) (runtimeprovider.Instance, error) {
	status, err := recoverNativeDetachedSession(ctx, manifest.SessionID)
	if err != nil {
		// Recovery may have launched a replacement before readiness failed. Bind
		// any newly published exact generation directly from protected metadata;
		// Open intentionally refuses it because Open is bound to the prior manifest.
		if meta, stateDir, readErr := readSupervisorMetadata(manifest.SessionID); readErr == nil &&
			filepath.Clean(stateDir) == filepath.Clean(manifest.StateDir) {
			identity := nativeRuntimeIdentity(manifest.Profile, meta)
			if identity.Generation > manifest.Identity.Generation && identity.IncarnationID != manifest.Identity.IncarnationID {
				return newNativeRuntimeInstance(manifest.Profile, stateDir, meta, nil, detached.RuntimeStatus{}), err
			}
		}
		return nil, err
	}
	meta, stateDir, readErr := readSupervisorMetadata(manifest.SessionID)
	if readErr != nil {
		return nil, readErr
	}
	return newNativeRuntimeInstance(manifest.Profile, stateDir, meta, nil, status), nil
}

type nativeRuntimeInstance struct {
	profile         string
	stateDir        string
	metadata        supervisorMetadata
	startedSession  *types.Session
	recoveredStatus detached.RuntimeStatus

	cleanupOnce sync.Once
	cleanupErr  error
}

func newNativeRuntimeInstance(profile, stateDir string, meta supervisorMetadata, session *types.Session, status detached.RuntimeStatus) *nativeRuntimeInstance {
	return &nativeRuntimeInstance{
		profile: profile, stateDir: stateDir, metadata: meta,
		startedSession: session, recoveredStatus: status,
	}
}

func (i *nativeRuntimeInstance) Identity() runtimeprovider.Identity {
	return nativeRuntimeIdentity(i.profile, i.metadata)
}

func (i *nativeRuntimeInstance) Endpoint() runtimeprovider.Endpoint {
	return runtimeprovider.Endpoint{Transport: "unix", Address: i.metadata.SupervisorSock}
}

func (i *nativeRuntimeInstance) Probe(ctx context.Context) (runtimeprovider.Status, error) {
	meta, stateDir, err := readSupervisorMetadata(i.metadata.SessionID)
	if err != nil {
		return runtimeprovider.Status{}, err
	}
	if filepath.Clean(stateDir) != filepath.Clean(i.stateDir) {
		return runtimeprovider.Status{}, fmt.Errorf("native runtime probe state directory mismatch")
	}
	if nativeRuntimeIdentity(i.profile, meta) != i.Identity() || meta.SupervisorSock != i.metadata.SupervisorSock {
		return runtimeprovider.Status{}, fmt.Errorf("native runtime exact incarnation changed before probe")
	}
	client := client.NewWithTimeout("unix://"+meta.SupervisorSock, "", 3*time.Second)
	status, err := detachedRuntimeHandshakeStatus(ctx, client, meta)
	if err != nil {
		return runtimeprovider.Status{}, err
	}
	identity := nativeRuntimeIdentity(i.profile, meta)
	endpoint := runtimeprovider.Endpoint{Transport: "unix", Address: meta.SupervisorSock}
	state, ready := nativeProviderState(status.LifecycleState)
	return runtimeprovider.Status{
		Identity: identity, Endpoint: endpoint, State: state, Ready: ready,
		Recoverable: status.Recoverable, LastError: status.LastError,
	}, nil
}

func (i *nativeRuntimeInstance) ControlPlane(ctx context.Context) (runtimeprovider.ControlPlaneSnapshot, error) {
	meta, stateDir, err := readSupervisorMetadata(i.metadata.SessionID)
	if err != nil {
		return runtimeprovider.ControlPlaneSnapshot{}, err
	}
	if filepath.Clean(stateDir) != filepath.Clean(i.stateDir) || nativeRuntimeIdentity(i.profile, meta) != i.Identity() {
		return runtimeprovider.ControlPlaneSnapshot{}, fmt.Errorf("native runtime control-plane incarnation mismatch")
	}
	snapshot := runtimeprovider.ControlPlaneSnapshot{Metadata: meta, StateDir: stateDir, Status: i.recoveredStatus}
	if i.startedSession != nil {
		snapshot.Session = *i.startedSession
	}
	if snapshot.Status.SessionID == "" {
		client := client.NewWithTimeout("unix://"+meta.SupervisorSock, "", 3*time.Second)
		snapshot.Status, err = detachedRuntimeHandshakeStatus(ctx, client, meta)
		if err != nil {
			return runtimeprovider.ControlPlaneSnapshot{}, err
		}
	}
	if err := snapshot.Validate(i.Identity(), i.Endpoint()); err != nil {
		return runtimeprovider.ControlPlaneSnapshot{}, err
	}
	return snapshot, nil
}

func (i *nativeRuntimeInstance) Stop(ctx context.Context, _ runtimeprovider.StopReason) error {
	return i.cleanup(ctx)
}

func (i *nativeRuntimeInstance) Destroy(ctx context.Context) error {
	return i.cleanup(ctx)
}

func (i *nativeRuntimeInstance) cleanup(ctx context.Context) error {
	i.cleanupOnce.Do(func() {
		i.cleanupErr = stopNativeDetachedRuntimeInstanceExact(ctx, i.stateDir, i.metadata)
	})
	return i.cleanupErr
}

func nativeRuntimeIdentity(profile string, meta supervisorMetadata) runtimeprovider.Identity {
	return runtimeprovider.Identity{
		ContractVersion:    runtimeprovider.ContractVersion,
		Provider:           runtimeprovider.NativeProvider,
		Profile:            profile,
		SessionID:          meta.SessionID,
		Generation:         meta.Generation,
		IncarnationID:      meta.IncarnationID,
		OwnerPID:           meta.OwnerPID,
		OwnerStartIdentity: meta.OwnerStartIdentity,
		BootID:             meta.BootID,
	}
}

func nativeProviderState(state string) (runtimeprovider.State, bool) {
	switch state {
	case detached.LifecycleReady:
		return runtimeprovider.StateReady, true
	case detached.LifecycleDegraded, detached.LifecycleRecovering:
		return runtimeprovider.StateDegraded, true
	case detached.LifecycleProvisioning:
		return runtimeprovider.StateProvisioning, false
	case detached.LifecycleFinalizing, detached.LifecycleStopping:
		return runtimeprovider.StateStopping, false
	case detached.LifecycleStopped, detached.LifecycleFinalized:
		return runtimeprovider.StateStopped, false
	default:
		return runtimeprovider.StateFailed, false
	}
}

func prepareDetachedRuntimeRequest(requestedSessionID string, workspaces []string, workspaceMode, policyName, runtimeHomeMode, envBaseMode string, envInherit []string, requestedProfile string) (runtimeprovider.Request, string, *config.Config, error) {
	if len(workspaces) == 0 {
		workspaces = []string{"."}
	}
	realWorkspaces := make([]string, 0, len(workspaces))
	for _, workspace := range workspaces {
		realWorkspace, err := filepath.Abs(workspace)
		if err != nil {
			return runtimeprovider.Request{}, "", nil, fmt.Errorf("workspace abs: %w", err)
		}
		if resolved, err := filepath.EvalSymlinks(realWorkspace); err == nil {
			realWorkspace = resolved
		}
		if stat, err := os.Stat(realWorkspace); err != nil {
			return runtimeprovider.Request{}, "", nil, fmt.Errorf("workspace stat: %w", err)
		} else if !stat.IsDir() {
			return runtimeprovider.Request{}, "", nil, fmt.Errorf("workspace must be a directory")
		}
		realWorkspaces = append(realWorkspaces, realWorkspace)
	}
	if len(realWorkspaces) > 1 && workspaceMode != string(types.WorkspaceModeShadow) {
		return runtimeprovider.Request{}, "", nil, fmt.Errorf("multiple workspaces require workspace_mode=shadow")
	}

	configPath, _ := findDetachedSupervisorConfigPath()
	if absolute, err := filepath.Abs(configPath); err == nil {
		configPath = absolute
	}
	cfg, _, err := loadLocalConfig(configPath)
	if err != nil {
		return runtimeprovider.Request{}, "", nil, err
	}
	profileName, profile, err := cfg.Sessions.Runtime.ResolveProfile(requestedProfile)
	if err != nil {
		return runtimeprovider.Request{}, "", nil, err
	}
	if profile.Provider != runtimeprovider.NativeProvider {
		return runtimeprovider.Request{}, "", nil, fmt.Errorf("runtime profile %q selects unavailable provider %q", profileName, profile.Provider)
	}

	sessionID, err := detachedSessionID(requestedSessionID)
	if err != nil {
		return runtimeprovider.Request{}, "", nil, err
	}
	stateDir, err := reserveDetachedSessionState(sessionID)
	if err != nil {
		return runtimeprovider.Request{}, "", nil, err
	}
	realWorkspace := realWorkspaces[0]
	req := types.CreateSessionRequest{
		ID: sessionID, Workspace: realWorkspace, Policy: policyName, WorkspaceMode: workspaceMode,
		Home: userHomeDir(), RuntimeHomeMode: runtimeHomeMode, EnvBaseMode: envBaseMode, EnvInherit: envInherit,
	}
	if len(realWorkspaces) > 1 {
		for _, path := range realWorkspaces {
			req.WorkspaceRoots = append(req.WorkspaceRoots, types.WorkspaceRoot{Path: path})
		}
	}
	if workspaceMode == string(types.WorkspaceModeShadow) {
		req.Shadow = &types.CreateShadowOptions{KeepOnDestroy: true}
	} else if workspaceMode == string(types.WorkspaceModeDirect) {
		realPaths := true
		req.RealPaths = &realPaths
	}
	return runtimeprovider.Request{
		SessionID: sessionID, Provider: profile.Provider, Profile: profileName,
		StateDir: stateDir, Session: req,
	}, configPath, cfg, nil
}

func detachedRuntimeRegistry(configPath string, cfg *config.Config) (*runtimeprovider.Registry, error) {
	return runtimeprovider.NewRegistry(&nativeRuntimeProvider{configPath: configPath, preflightConfig: cfg})
}

func startDetachedRuntime(ctx context.Context, request runtimeprovider.Request, configPath string, cfg *config.Config) (*detachedSessionStartResult, error) {
	registry, err := detachedRuntimeRegistry(configPath, cfg)
	if err != nil {
		return nil, err
	}
	provider, err := registry.Resolve(request.Provider)
	if err != nil {
		return nil, err
	}
	instance, err := (runtimeprovider.Controller{CleanupTimeout: detachedRuntimeCleanupTimeout}).Start(ctx, provider, request)
	if err != nil {
		return nil, err
	}
	snapshot, err := instance.ControlPlane(ctx)
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), detachedRuntimeCleanupTimeout)
		cleanupErr := errors.Join(instance.Stop(cleanupCtx, runtimeprovider.StopReasonStartupFailed), instance.Destroy(cleanupCtx))
		cancel()
		return nil, errors.Join(fmt.Errorf("read runtime provider control plane: %w", err), cleanupErr)
	}
	if snapshot.Session.ID == "" {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), detachedRuntimeCleanupTimeout)
		cleanupErr := errors.Join(instance.Stop(cleanupCtx, runtimeprovider.StopReasonStartupFailed), instance.Destroy(cleanupCtx))
		cancel()
		return nil, errors.Join(fmt.Errorf("runtime provider %q returned no detached session result", request.Provider), cleanupErr)
	}
	return &detachedSessionStartResult{
		supervisorMetadata: snapshot.Metadata,
		Session:            snapshot.Session,
		StateDir:           snapshot.StateDir,
	}, nil
}

func runtimeManifestForDetachedSession(sessionID, stateDir string) (runtimeprovider.Manifest, bool, error) {
	manifest, err := runtimeprovider.ReadManifest(stateDir)
	if err == nil {
		if manifest.SessionID != sessionID || filepath.Clean(manifest.StateDir) != filepath.Clean(stateDir) {
			return runtimeprovider.Manifest{}, false, fmt.Errorf("runtime-provider manifest identity mismatch")
		}
		return manifest, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return runtimeprovider.Manifest{}, false, err
	}
	recovery, recoveryErr := detached.ReadRecoveryManifest(stateDir)
	if recoveryErr != nil {
		return runtimeprovider.Manifest{}, false, recoveryErr
	}
	meta, _, metaErr := readSupervisorMetadata(sessionID)
	if metaErr != nil {
		return runtimeprovider.Manifest{}, false, metaErr
	}
	if meta.ProtocolVersion < detached.ProtocolVersion || meta.Generation == 0 || strings.TrimSpace(meta.IncarnationID) == "" {
		return runtimeprovider.Manifest{}, true, errLegacyRuntimeProviderIdentity
	}
	state, cleanupComplete := inferredRuntimeState(recovery.State)
	manifest = runtimeprovider.Manifest{
		SchemaVersion:   runtimeprovider.ManifestSchemaVersion,
		ContractVersion: runtimeprovider.ContractVersion,
		Provider:        runtimeprovider.NativeProvider,
		Profile:         runtimeprovider.DefaultProfile,
		SessionID:       sessionID,
		StateDir:        stateDir,
		State:           state,
		CreatedAt:       recovery.CreatedAt,
		UpdatedAt:       recovery.UpdatedAt,
		LastError:       recovery.LastError,
		CleanupComplete: cleanupComplete,
	}
	if meta.Generation > 0 && strings.TrimSpace(meta.IncarnationID) != "" {
		manifest.Identity = nativeRuntimeIdentity(runtimeprovider.DefaultProfile, meta)
		manifest.Endpoint = runtimeprovider.Endpoint{Transport: "unix", Address: meta.SupervisorSock}
	}
	if err := manifest.Validate(); err != nil {
		return runtimeprovider.Manifest{}, false, fmt.Errorf("infer legacy native runtime provider: %w", err)
	}
	return manifest, true, nil
}

func syncNativeRuntimeProviderManifest(stateDir string, meta supervisorMetadata) error {
	return runtimeprovider.WithLifecycleLock(stateDir, func() error {
		return syncNativeRuntimeProviderManifestLocked(stateDir, meta)
	})
}

// syncNativeRuntimeProviderManifestLocked requires runtime-provider.lock. It is
// split out so BeginRuntime and provider identity publication form one atomic
// transition relative to trusted Recover/Stop operations.
func syncNativeRuntimeProviderManifestLocked(stateDir string, meta supervisorMetadata) error {
	manifest, err := runtimeprovider.ReadManifest(stateDir)
	if errors.Is(err, os.ErrNotExist) {
		// Protocol-v2 sessions created before the provider abstraction retain the
		// unchanged detached recovery path until a trusted lifecycle operation
		// infers and writes their provider manifest.
		return nil
	}
	if err != nil {
		return err
	}
	if manifest.Provider != runtimeprovider.NativeProvider || manifest.SessionID != meta.SessionID || filepath.Clean(manifest.StateDir) != filepath.Clean(stateDir) {
		return fmt.Errorf("native runtime-provider manifest identity mismatch")
	}
	if manifest.State == runtimeprovider.StateStopping || manifest.State == runtimeprovider.StateStopped {
		return nil
	}
	identity := nativeRuntimeIdentity(manifest.Profile, meta)
	if manifest.Identity.Generation > identity.Generation ||
		(manifest.Identity.Generation == identity.Generation && manifest.Identity.IncarnationID != "" && manifest.Identity != identity) {
		return fmt.Errorf("native runtime-provider supervisor attempted a stale incarnation update")
	}
	state, cleanupComplete := inferredRuntimeState(meta.State)
	manifest.State = state
	manifest.Identity = identity
	manifest.Endpoint = runtimeprovider.Endpoint{Transport: "unix", Address: meta.SupervisorSock}
	manifest.LastError = meta.LastError
	manifest.CleanupComplete = cleanupComplete
	return runtimeprovider.WriteManifest(stateDir, manifest)
}

func inferredRuntimeState(state string) (runtimeprovider.State, bool) {
	switch state {
	case detached.LifecycleProvisioning:
		return runtimeprovider.StateProvisioning, false
	case detached.LifecycleRecovering:
		return runtimeprovider.StateRecovering, false
	case detached.LifecycleReady:
		return runtimeprovider.StateReady, false
	case detached.LifecycleDegraded:
		return runtimeprovider.StateDegraded, false
	case detached.LifecycleFinalizing, detached.LifecycleStopping:
		return runtimeprovider.StateStopping, false
	case detached.LifecycleStopped, detached.LifecycleFinalized:
		return runtimeprovider.StateStopped, true
	default:
		return runtimeprovider.StateFailed, false
	}
}

func recoverDetachedSession(ctx context.Context, sessionID string) (detached.RuntimeStatus, error) {
	_, stateDir, err := readSupervisorMetadata(sessionID)
	if err != nil {
		return detached.RuntimeStatus{}, err
	}
	manifest, inferred, err := runtimeManifestForDetachedSession(sessionID, stateDir)
	if errors.Is(err, errLegacyRuntimeProviderIdentity) {
		return recoverNativeDetachedSession(ctx, sessionID)
	}
	if err != nil {
		return detached.RuntimeStatus{}, err
	}
	if inferred {
		// Preserve the established protocol-v2 recovery path. The replacement
		// supervisor will keep operating without a provider manifest; a future
		// fresh session opts into the serialized provider lifecycle at creation.
		return recoverNativeDetachedSession(ctx, sessionID)
	}
	provider := &nativeRuntimeProvider{}
	registry, err := runtimeprovider.NewRegistry(provider)
	if err != nil {
		return detached.RuntimeStatus{}, err
	}
	selected, err := registry.Resolve(manifest.Provider)
	if err != nil {
		return detached.RuntimeStatus{}, err
	}
	instance, err := (runtimeprovider.Controller{CleanupTimeout: detachedRuntimeCleanupTimeout}).Recover(ctx, selected, stateDir, manifest)
	if err != nil {
		return detached.RuntimeStatus{}, err
	}
	snapshot, err := instance.ControlPlane(ctx)
	if err != nil {
		return detached.RuntimeStatus{}, fmt.Errorf("read recovered runtime provider control plane: %w", err)
	}
	if snapshot.Status.SessionID == "" {
		return detached.RuntimeStatus{}, fmt.Errorf("runtime provider %q returned no detached recovery status", manifest.Provider)
	}
	return snapshot.Status, nil
}

func stopDetachedSessionExact(ctx context.Context, sessionID string) error {
	_, stateDir, err := readSupervisorMetadata(sessionID)
	if err != nil {
		return err
	}
	manifest, inferred, err := runtimeManifestForDetachedSession(sessionID, stateDir)
	if errors.Is(err, errLegacyRuntimeProviderIdentity) {
		return stopNativeDetachedSessionExact(ctx, sessionID)
	}
	if err != nil {
		return err
	}
	if inferred {
		return stopNativeDetachedSessionExact(ctx, sessionID)
	}
	registry, err := runtimeprovider.NewRegistry(&nativeRuntimeProvider{})
	if err != nil {
		return err
	}
	provider, err := registry.Resolve(manifest.Provider)
	if err != nil {
		return err
	}
	return (runtimeprovider.Controller{CleanupTimeout: detachedRuntimeCleanupTimeout}).Stop(ctx, provider, stateDir, manifest, runtimeprovider.StopReasonUser)
}

// Keep a compile-time assertion close to the adapter.
var _ runtimeprovider.Provider = (*nativeRuntimeProvider)(nil)
var _ runtimeprovider.Instance = (*nativeRuntimeInstance)(nil)
