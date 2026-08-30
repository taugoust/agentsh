package externalrunner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/guestcontrol"
	"github.com/agentsh/agentsh/internal/runtimeprovider"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

type ProviderOptions struct {
	Enabled           bool
	Profiles          map[string]string
	CIDLeaseRoot      string
	MonitorExecutable string
}

type providerWorkspaceVolumeDeps struct {
	newID func() (string, error)
}

type Provider struct {
	options          ProviderOptions
	workspaceVolumes providerWorkspaceVolumeDeps
}

func NewProvider(options ProviderOptions) (*Provider, error) {
	if !filepath.IsAbs(options.CIDLeaseRoot) || filepath.Clean(options.CIDLeaseRoot) != options.CIDLeaseRoot {
		return nil, fmt.Errorf("external runner CID lease root must be clean and absolute")
	}
	if !filepath.IsAbs(options.MonitorExecutable) || filepath.Clean(options.MonitorExecutable) != options.MonitorExecutable {
		return nil, fmt.Errorf("external runner monitor executable must be clean and absolute")
	}
	profiles := make(map[string]string, len(options.Profiles))
	for name, path := range options.Profiles {
		if err := runtimeprovider.ValidateName(name); err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, fmt.Errorf("external runner operator profile mapping is invalid")
		}
		profiles[name] = path
	}
	options.Profiles = profiles
	return &Provider{
		options: options,
		workspaceVolumes: providerWorkspaceVolumeDeps{
			newID: newProviderWorkspaceVolumeID,
		},
	}, nil
}

func (p *Provider) Name() string { return ProviderName }

func (p *Provider) CanResumeStopped(manifest runtimeprovider.Manifest) bool {
	profile, _, err := p.profile(manifest.Profile)
	return err == nil && (profile.Schema == ProfileSchemaV2 || profile.Schema == ProfileSchemaV3) && manifest.Provider == ProviderName
}

func (p *Provider) Preflight(_ context.Context, request runtimeprovider.Request) (runtimeprovider.Capabilities, error) {
	if err := request.Validate(); err != nil {
		return runtimeprovider.Capabilities{}, err
	}
	if p == nil || !p.options.Enabled {
		return runtimeprovider.Capabilities{}, fmt.Errorf("external runner operator ceiling is disabled")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return runtimeprovider.Capabilities{}, fmt.Errorf("external MicroVM runners require x86_64 Linux")
	}
	profile, _, err := p.profile(request.Profile)
	if err != nil {
		return runtimeprovider.Capabilities{}, err
	}
	if err := validateProviderLifecycleProfile(profile); err != nil {
		return runtimeprovider.Capabilities{}, err
	}
	if request.Provider != ProviderName || request.Session.Policy != profile.Guest.Policy || request.Session.WorkspaceMode != string(types.WorkspaceModeShadow) ||
		len(request.Session.WorkspaceRoots) > 1 {
		return runtimeprovider.Capabilities{}, fmt.Errorf("external runner requires one isolated shadow workspace and its fixed guest policy")
	}
	if (profile.Schema == ProfileSchemaV1) != (request.InputArtifact == nil) {
		return runtimeprovider.Capabilities{}, fmt.Errorf("only external runner v2 accepts and requires a Git input artifact")
	}
	return runtimeprovider.Capabilities{
		ContractVersion: runtimeprovider.ContractVersion, Provider: ProviderName,
		Recoverable: profile.Schema == ProfileSchemaV2 || profile.Schema == ProfileSchemaV3, Transports: []string{"unix"},
	}, nil
}

func createExternalRunnerLayout(layout HostMonitorLayout) error {
	if err := os.Mkdir(layout.RuntimeDir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create external runner runtime directory: %w", err)
	}
	info, err := os.Lstat(layout.RuntimeDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("external runner runtime directory is unsafe")
	}
	// Input artifact ingestion may create runtime/artifacts before provider
	// startup. All provider-owned children remain exclusive so stale monitor
	// state can never be mistaken for a fresh generation.
	for _, path := range []string{layout.ControlDir, layout.HostDir, layout.LogsDir} {
		if err := os.Mkdir(path, 0o700); err != nil {
			return fmt.Errorf("create external runner layout: %w", err)
		}
	}
	return nil
}

func (p *Provider) Start(ctx context.Context, request runtimeprovider.Request) (runtimeprovider.Instance, error) {
	if _, err := p.Preflight(ctx, request); err != nil {
		return nil, err
	}
	profile, profileFileDigest, err := p.profile(request.Profile)
	if err != nil {
		return nil, err
	}
	// Re-check after Preflight because the operator-owned profile file is read
	// again and must remain an admitted lifecycle schema.
	if err := validateProviderLifecycleProfile(profile); err != nil {
		return nil, err
	}
	layout, err := HostMonitorPaths(request.StateDir)
	if err != nil {
		return nil, err
	}
	if err := createExternalRunnerLayout(layout); err != nil {
		return nil, err
	}
	volumeID := ""
	switch profile.Schema {
	case ProfileSchemaV1:
		baseline, err := stageWorkspace(ctx, request.Session.Workspace, layout.WorkspaceDir)
		if err != nil {
			return nil, err
		}
		if err := WriteWorkspaceBaseline(layout.BaselinePath, baseline); err != nil {
			return nil, err
		}
	case ProfileSchemaV2, ProfileSchemaV3:
		if p.workspaceVolumes.newID == nil {
			return nil, fmt.Errorf("external runner workspace volume identity dependency is missing")
		}
		volumeID, err = p.workspaceVolumes.newID()
		if err != nil {
			return nil, fmt.Errorf("generate external runner workspace volume identity: %w", err)
		}
		if !canonicalWorkspaceVolumeUUID(volumeID) {
			return nil, fmt.Errorf("generated external runner workspace volume identity is invalid")
		}
		// The provider persists only an opaque identity. After this identity is in
		// the durable schema-v2 monitor request, the monitor creates or
		// idempotently reopens the volume and acquires its first lease.
		// Public Start cannot reach this branch while v2 admission is gated.
	default:
		return nil, fmt.Errorf("external runner profile schema %q is unsupported", profile.Schema)
	}
	lease, err := AllocateCID(ctx, p.options.CIDLeaseRoot, request.SessionID, profile.VSock.CIDMin, profile.VSock.CIDMax)
	if err != nil {
		return nil, err
	}
	keepLease := false
	defer func() {
		if !keepLease {
			_ = ReleaseCID(context.Background(), p.options.CIDLeaseRoot, lease, profile.VSock.CIDMin, profile.VSock.CIDMax)
		}
	}()
	launchNonce, err := newProviderSecret()
	if err != nil {
		return nil, err
	}
	controlToken, err := newProviderSecret()
	if err != nil {
		return nil, err
	}
	supervisorToken, err := newProviderSecret()
	if err != nil {
		return nil, err
	}
	egressToken := ""
	if profile.Schema == ProfileSchemaV3 {
		egressToken, err = newProviderSecret()
		if err != nil {
			return nil, err
		}
	}
	manifest, err := newProviderGuestManifest(request.SessionID, profile, lease.CID, launchNonce, controlToken, supervisorToken, egressToken, volumeID)
	if err != nil {
		return nil, err
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	manifestData = append(manifestData, '\n')
	if err := writeExclusivePrivateFile(layout.GuestManifest, manifestData); err != nil {
		return nil, fmt.Errorf("write authoritative external runner guest manifest: %w", err)
	}
	if err := writeExclusivePrivateFile(layout.GuestManifestDelivery, manifestData); err != nil {
		return nil, fmt.Errorf("write external runner guest manifest delivery copy: %w", err)
	}
	manifestDigest, err := HostMonitorFileSHA256(layout.GuestManifest)
	if err != nil {
		return nil, err
	}
	monitorID, err := newProviderSecret()
	if err != nil {
		return nil, err
	}
	monitorSchema, err := hostMonitorSchemaVersionForProfile(profile.Schema)
	if err != nil {
		return nil, err
	}
	launchRequest := HostMonitorRequest{
		SchemaVersion: monitorSchema, MonitorID: monitorID,
		SessionID: request.SessionID, StateDir: request.StateDir, SourceWorkspace: request.Session.Workspace,
		ProfileFile: p.options.Profiles[request.Profile], ProfileFileSHA256: profileFileDigest,
		ProfileName: profile.Name, ProfileDigest: profile.ProfileDigest, GuestProfileDigest: profile.Guest.ProfileDigest,
		GuestPolicy: profile.Guest.Policy, GuestControlPort: profile.Guest.ControlPort, GuestSupervisorPort: profile.Guest.SupervisorPort,
		GuestManifestSHA256: manifestDigest, ExpectedGuestGeneration: 1, LaunchNonce: launchNonce,
		CIDLeaseRoot: p.options.CIDLeaseRoot, CIDLease: lease, CreatedAt: time.Now().UTC(),
	}
	if profile.Schema == ProfileSchemaV2 || profile.Schema == ProfileSchemaV3 {
		contract := *profile.WorkspaceVolume
		launchRequest.ProfileSchema = profile.Schema
		launchRequest.WorkspaceVolume = &contract
		launchRequest.VolumeID = volumeID
		launchRequest.InputArtifact = request.InputArtifact
		if profile.Schema == ProfileSchemaV3 {
			hostEgress := *profile.HostEgress
			launchRequest.HostEgress = &hostEgress
			launchRequest.EgressPort = manifest.EgressPort
			approvalBinding, bindingErr := hostEgressApprovalBindingFromEnvironment()
			if bindingErr != nil {
				return nil, bindingErr
			}
			launchRequest.HostEgressApproval = approvalBinding
		}
	}
	if err := WriteHostMonitorRequest(request.StateDir, launchRequest); err != nil {
		return nil, err
	}
	monitor, err := launchDetachedHostMonitor(p.options.MonitorExecutable, request.StateDir)
	if err != nil {
		return nil, err
	}
	stopOnFailure := true
	defer func() {
		if stopOnFailure {
			_ = stopExactHostMonitor(context.Background(), request.StateDir, monitor)
		}
	}()
	status, err := waitForHostMonitorReady(ctx, request.StateDir, monitor, profile.ReadinessTimeout())
	if err != nil {
		return nil, err
	}
	instance, err := p.instanceFromStatus(request.StateDir, profile, profileFileDigest, status)
	if err != nil {
		return nil, err
	}
	if _, err := instance.ControlPlane(ctx); err != nil {
		return nil, err
	}
	keepLease = true
	stopOnFailure = false
	return instance, nil
}

func (p *Provider) Open(_ context.Context, manifest runtimeprovider.Manifest) (runtimeprovider.Instance, error) {
	profile, profileFileDigest, err := p.profile(manifest.Profile)
	if err != nil {
		return nil, err
	}
	status, err := ReadHostMonitorStatus(manifest.StateDir)
	if err != nil {
		return nil, err
	}
	instance, err := p.instanceFromStatus(manifest.StateDir, profile, profileFileDigest, status)
	if err != nil {
		return nil, err
	}
	if manifest.Identity != (runtimeprovider.Identity{}) && (instance.Identity() != manifest.Identity || instance.Endpoint() != manifest.Endpoint) {
		return nil, fmt.Errorf("external runner exact incarnation mismatch")
	}
	return instance, nil
}

func (p *Provider) Recover(ctx context.Context, manifest runtimeprovider.Manifest) (runtimeprovider.Instance, error) {
	profile, _, profileErr := p.profile(manifest.Profile)
	if profileErr != nil {
		return nil, profileErr
	}
	instance, err := p.Open(ctx, manifest)
	if err == nil {
		status, probeErr := instance.Probe(ctx)
		if probeErr == nil && status.Ready {
			return instance, nil
		}
	}
	if profile.Schema == ProfileSchemaV2 || profile.Schema == ProfileSchemaV3 {
		recovered, recoverErr := p.recoverV2(ctx, manifest.SessionID, manifest.StateDir, manifest.Profile)
		if recoverErr != nil {
			return nil, recoverErr
		}
		return recovered, nil
	}
	if err != nil {
		return nil, fmt.Errorf("legacy diagnostic external runner cannot recreate a stopped instance: %w", err)
	}
	return nil, fmt.Errorf("legacy diagnostic external runner is not live and cannot be recreated")
}

func validateProviderLifecycleProfile(profile Profile) error {
	switch profile.Schema {
	case ProfileSchemaV1, ProfileSchemaV2, ProfileSchemaV3:
		return nil
	default:
		return fmt.Errorf("external runner profile schema %q is unavailable", profile.Schema)
	}
}

func (p *Provider) profile(name string) (Profile, string, error) {
	path, ok := p.options.Profiles[name]
	if !ok {
		return Profile{}, "", fmt.Errorf("external runner profile %q is not operator-configured", name)
	}
	profile, digest, err := ReadProfileSnapshot(path)
	if err != nil {
		return Profile{}, "", err
	}
	if profile.Name != name || profile.Provider != ProviderName {
		return Profile{}, "", fmt.Errorf("external runner profile mapping identity mismatch")
	}
	return profile, digest, nil
}

func (p *Provider) instanceFromStatus(stateDir string, profile Profile, profileFileDigest string, status HostMonitorStatus) (*providerInstance, error) {
	if status.Guest == nil || status.Endpoint == nil || status.Profile != profile.Name || status.GuestProfileDigest != profile.Guest.ProfileDigest {
		return nil, fmt.Errorf("external runner status lacks an authenticated guest endpoint")
	}
	request, err := ReadHostMonitorRequest(stateDir)
	if err != nil {
		return nil, err
	}
	configuredProfile, ok := p.options.Profiles[profile.Name]
	if !ok || request.ProfileFile != configuredProfile || request.StateDir != stateDir {
		return nil, fmt.Errorf("external runner immutable request profile path binding differs from operator configuration")
	}
	if err := validateHostMonitorProfileBinding(request, profile, profileFileDigest); err != nil {
		return nil, fmt.Errorf("external runner immutable request profile binding: %w", err)
	}
	secret, err := ReadHostMonitorGuestSecret(stateDir, request)
	if err != nil {
		return nil, err
	}
	if secret.Generation != status.Guest.Generation || secret.IncarnationID != status.Guest.IncarnationID {
		return nil, fmt.Errorf("external runner guest credential identity mismatch")
	}
	return &providerInstance{provider: p, profile: profile, request: request, status: status, eventToken: secret.EventToken}, nil
}

type providerInstance struct {
	provider    *Provider
	profile     Profile
	request     HostMonitorRequest
	status      HostMonitorStatus
	eventToken  string
	stopOnce    sync.Once
	stopErr     error
	destroyOnce sync.Once
	destroyErr  error
}

func (i *providerInstance) Identity() runtimeprovider.Identity {
	return runtimeprovider.Identity{
		ContractVersion: runtimeprovider.ContractVersion, Provider: ProviderName, Profile: i.profile.Name,
		SessionID: i.request.SessionID, Generation: i.status.Guest.Generation, IncarnationID: i.status.Guest.IncarnationID,
		OwnerPID: i.status.Monitor.PID, OwnerStartIdentity: i.status.Monitor.StartIdentity, BootID: i.status.Monitor.BootID,
	}
}
func (i *providerInstance) Endpoint() runtimeprovider.Endpoint { return *i.status.Endpoint }

func (i *providerInstance) Probe(ctx context.Context) (runtimeprovider.Status, error) {
	status, err := ReadHostMonitorStatus(i.request.StateDir)
	if err != nil {
		return runtimeprovider.Status{}, err
	}
	state, ready := providerMonitorState(status.State)
	if ready && !detached.ProcessIdentityMatches(status.Monitor.PID, status.Monitor.StartIdentity, status.Monitor.BootID) {
		return runtimeprovider.Status{}, fmt.Errorf("external runner host monitor identity is no longer live")
	}
	identity := i.Identity()
	return runtimeprovider.Status{Identity: identity, Endpoint: i.Endpoint(), State: state, Ready: ready, Recoverable: i.profile.Schema == ProfileSchemaV2 || i.profile.Schema == ProfileSchemaV3, LastError: status.LastError}, ctx.Err()
}

func (i *providerInstance) ControlPlane(ctx context.Context) (runtimeprovider.ControlPlaneSnapshot, error) {
	if i.status.Endpoint == nil || i.status.Guest == nil {
		return runtimeprovider.ControlPlaneSnapshot{}, fmt.Errorf("external runner control plane lacks an authenticated endpoint")
	}
	if (i.request.SchemaVersion == HostMonitorSchemaVersionV1) != (i.profile.Schema == ProfileSchemaV1) ||
		(i.request.SchemaVersion == HostMonitorSchemaVersionV2) != (i.profile.Schema == ProfileSchemaV2) ||
		(i.request.SchemaVersion == HostMonitorSchemaVersionV3) != (i.profile.Schema == ProfileSchemaV3) {
		return runtimeprovider.ControlPlaneSnapshot{}, fmt.Errorf("external runner control-plane schema binding is inconsistent")
	}
	c := client.NewWithTimeout("unix://"+i.Endpoint().Address, "", 30*time.Second)
	session, err := c.GetSession(ctx, i.request.SessionID)
	if err != nil {
		return runtimeprovider.ControlPlaneSnapshot{}, err
	}
	var guestStatus detached.RuntimeStatus
	if err := c.DoRawJSON(ctx, http.MethodGet, "/api/v1/detached/status", nil, &guestStatus); err != nil {
		return runtimeprovider.ControlPlaneSnapshot{}, err
	}
	if guestStatus.SessionID != i.request.SessionID || guestStatus.Generation != i.status.Guest.Generation || guestStatus.IncarnationID != i.status.Guest.IncarnationID {
		return runtimeprovider.ControlPlaneSnapshot{}, fmt.Errorf("external runner guest control-plane identity mismatch")
	}
	var network detached.NetworkEnforcement
	networkPath := "/api/v1/sessions/" + url.PathEscape(i.request.SessionID) + "/network-enforcement"
	if err := c.DoRawJSON(ctx, http.MethodGet, networkPath, nil, &network); err != nil {
		return runtimeprovider.ControlPlaneSnapshot{}, err
	}
	network.Normalize()
	layout, err := HostMonitorPaths(i.request.StateDir)
	if err != nil {
		return runtimeprovider.ControlPlaneSnapshot{}, err
	}
	worktree := layout.WorkspaceDir
	if i.profile.Schema == ProfileSchemaV2 || i.profile.Schema == ProfileSchemaV3 {
		// The v2 workspace exists only inside the authenticated private volume.
		// Publishing the fixed guest mount preserves provider-neutral cwd metadata
		// without inventing a host path or exposing the qcow2 image location.
		worktree = i.profile.Guest.Workspace
	}
	metadata := detached.Metadata{
		SessionID: i.request.SessionID, ID: i.request.SessionID, CreatedAt: i.request.CreatedAt,
		State: detached.LifecycleReady, Policy: i.request.GuestPolicy,
		RealWorkspace: i.request.SourceWorkspace, WorkspaceMode: string(types.WorkspaceModeShadow), Worktree: worktree,
		SupervisorSock: i.Endpoint().Address, EventToken: i.eventToken,
		OwnerPID: i.status.Monitor.PID, OwnerStartIdentity: i.status.Monitor.StartIdentity, BootID: i.status.Monitor.BootID,
		Generation: i.status.Guest.Generation, IncarnationID: i.status.Guest.IncarnationID,
		IncarnationStartedAt: i.request.CreatedAt, HeartbeatAt: time.Now().UTC(),
		NetworkEnforcement: &network, ProtocolVersion: detached.ProtocolVersion,
	}
	if err := detached.WriteMetadata(i.request.StateDir, metadata); err != nil {
		return runtimeprovider.ControlPlaneSnapshot{}, err
	}
	return runtimeprovider.ControlPlaneSnapshot{Metadata: metadata, Session: session, StateDir: i.request.StateDir, Status: guestStatus}, nil
}

func (i *providerInstance) Stop(ctx context.Context, _ runtimeprovider.StopReason) error {
	i.stopOnce.Do(func() {
		i.stopErr = stopExactHostMonitor(ctx, i.request.StateDir, i.status.Monitor)
	})
	return i.stopErr
}

func (i *providerInstance) Destroy(ctx context.Context) error {
	i.destroyOnce.Do(func() {
		status, err := ReadHostMonitorStatus(i.request.StateDir)
		if err != nil {
			i.destroyErr = err
			return
		}
		if !hostMonitorStatusTerminal(status) {
			i.destroyErr = fmt.Errorf("external runner lacks terminal teardown evidence")
			return
		}
		// Workspace storage has a separate explicit lifecycle. Provider teardown
		// releases only the runtime CID and never deletes a retained v2 volume;
		// deletion remains gated by higher-level terminal session evidence.
		i.destroyErr = ReleaseCID(ctx, i.request.CIDLeaseRoot, i.request.CIDLease, i.profile.VSock.CIDMin, i.profile.VSock.CIDMax)
	})
	return i.destroyErr
}

func hostMonitorStatusTerminal(status HostMonitorStatus) bool {
	switch status.SchemaVersion {
	case HostMonitorSchemaVersionV1:
		if status.VolumeID != "" || status.VolumeClosed || status.StartupChildReaped {
			return false
		}
	case HostMonitorSchemaVersionV2:
		if !canonicalWorkspaceVolumeUUID(status.VolumeID) || !status.VolumeClosed || status.EgressBrokerClosed {
			return false
		}
	case HostMonitorSchemaVersionV3:
		if !canonicalWorkspaceVolumeUUID(status.VolumeID) || !status.VolumeClosed || !status.EgressBrokerClosed {
			return false
		}
	default:
		return false
	}
	if !status.RelayClosed {
		return false
	}
	switch status.State {
	case HostMonitorStopped:
		return !status.StartupChildReaped && status.Runner != nil && status.Runner.Validate(true) == nil &&
			status.RunnerExit != nil && status.RunnerReaped
	case HostMonitorFailed:
		if validateHostMonitorFailedRunnerEvidence(status) != nil {
			return false
		}
		if status.Runner == nil {
			// Schema v2 has two distinct terminal startup-failure shapes: true
			// no-child prelaunch evidence, or startup_child_reaped plus an exact
			// exit. The shared validator rejects every mixed shape.
			return true
		}
		return status.RunnerExit != nil && status.RunnerReaped
	default:
		return false
	}
}

func exactHostMonitorStatusTerminal(status HostMonitorStatus, identity HostProcessIdentity) bool {
	if status.Monitor.PID != identity.PID || status.Monitor.StartIdentity != identity.StartIdentity || status.Monitor.BootID != identity.BootID {
		return false
	}
	return hostMonitorStatusTerminal(status)
}

func providerMonitorState(state HostMonitorState) (runtimeprovider.State, bool) {
	switch state {
	case HostMonitorControlReady:
		return runtimeprovider.StateReady, true
	case HostMonitorInitializing, HostMonitorBooting:
		return runtimeprovider.StateProvisioning, false
	case HostMonitorStopping:
		return runtimeprovider.StateStopping, false
	case HostMonitorStopped:
		return runtimeprovider.StateStopped, false
	default:
		return runtimeprovider.StateFailed, false
	}
}

func waitForHostMonitorReady(ctx context.Context, stateDir string, monitor HostProcessIdentity, timeout time.Duration) (HostMonitorStatus, error) {
	deadline := time.Now().Add(timeout)
	for {
		if err := ctx.Err(); err != nil {
			return HostMonitorStatus{}, err
		}
		status, err := ReadHostMonitorStatus(stateDir)
		if err == nil {
			if status.Monitor.PID != monitor.PID || status.Monitor.StartIdentity != monitor.StartIdentity || status.Monitor.BootID != monitor.BootID {
				return HostMonitorStatus{}, fmt.Errorf("external runner launched a different host monitor identity")
			}
			switch status.State {
			case HostMonitorControlReady:
				return status, nil
			case HostMonitorFailed, HostMonitorStopped:
				return HostMonitorStatus{}, fmt.Errorf("external runner host monitor became %s: %s", status.State, status.LastError)
			}
		}
		if !detached.ProcessIdentityMatches(monitor.PID, monitor.StartIdentity, monitor.BootID) {
			return HostMonitorStatus{}, fmt.Errorf("external runner host monitor exited before readiness")
		}
		if time.Now().After(deadline) {
			return HostMonitorStatus{}, fmt.Errorf("timed out waiting for external runner host monitor")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func newProviderGuestManifest(sessionID string, profile Profile, cid uint32, launchNonce, controlToken, supervisorToken, egressToken, volumeID string) (guestcontrol.Manifest, error) {
	egressPort := uint32(0)
	if profile.Schema == ProfileSchemaV3 {
		var err error
		egressPort, err = deriveHostEgressPort(profile, cid)
		if err != nil {
			return guestcontrol.Manifest{}, err
		}
		if !guestcontrol.ValidEgressAuthenticationToken(egressToken) {
			return guestcontrol.Manifest{}, fmt.Errorf("external runner v3 egress token is invalid")
		}
	} else if egressToken != "" {
		return guestcontrol.Manifest{}, fmt.Errorf("legacy external runner manifest cannot carry an egress token")
	}
	manifest := guestcontrol.Manifest{
		ProtocolVersion: profile.Guest.Protocol, SessionID: sessionID,
		LaunchNonce: launchNonce, ControlToken: controlToken, SupervisorToken: supervisorToken,
		Profile: profile.Name, ProfileDigest: profile.Guest.ProfileDigest, Policy: profile.Guest.Policy,
		Workspace: profile.Guest.Workspace, VSockCID: cid, VSockPort: profile.Guest.ControlPort,
		SupervisorPort: profile.Guest.SupervisorPort, ExpectedGeneration: 1,
		VolumeID: volumeID, EgressPort: egressPort, EgressToken: egressToken,
	}
	if err := manifest.Validate(profile.Guest.Workspace, profile.Name, profile.Guest.ProfileDigest, []string{profile.Guest.Policy}); err != nil {
		return guestcontrol.Manifest{}, err
	}
	return manifest, nil
}

func newProviderSecret() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func newProviderWorkspaceVolumeID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

var _ runtimeprovider.Provider = (*Provider)(nil)
var _ runtimeprovider.Instance = (*providerInstance)(nil)
