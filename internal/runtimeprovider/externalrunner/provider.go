package externalrunner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
)

type ProviderOptions struct {
	Enabled           bool
	Profiles          map[string]string
	CIDLeaseRoot      string
	MonitorExecutable string
}

type Provider struct {
	options ProviderOptions
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
	return &Provider{options: options}, nil
}

func (p *Provider) Name() string { return ProviderName }

func (p *Provider) Preflight(_ context.Context, request runtimeprovider.Request) (runtimeprovider.Capabilities, error) {
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
	if request.Provider != ProviderName || request.Session.Policy != profile.Guest.Policy || request.Session.WorkspaceMode != string(types.WorkspaceModeShadow) ||
		len(request.Session.WorkspaceRoots) > 1 {
		return runtimeprovider.Capabilities{}, fmt.Errorf("diagnostic external runner requires one staged shadow workspace and its fixed guest policy")
	}
	return runtimeprovider.Capabilities{
		ContractVersion: runtimeprovider.ContractVersion, Provider: ProviderName,
		Recoverable: false, Transports: []string{"unix"},
	}, nil
}

func (p *Provider) Start(ctx context.Context, request runtimeprovider.Request) (runtimeprovider.Instance, error) {
	if _, err := p.Preflight(ctx, request); err != nil {
		return nil, err
	}
	profile, profileFileDigest, err := p.profile(request.Profile)
	if err != nil {
		return nil, err
	}
	layout, err := HostMonitorPaths(request.StateDir)
	if err != nil {
		return nil, err
	}
	for _, path := range []string{layout.RuntimeDir, layout.ControlDir, layout.HostDir, layout.LogsDir} {
		if err := os.Mkdir(path, 0o700); err != nil {
			return nil, fmt.Errorf("create external runner layout: %w", err)
		}
	}
	if err := stageWorkspace(ctx, request.Session.Workspace, layout.WorkspaceDir); err != nil {
		return nil, err
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
	manifest := guestcontrol.Manifest{
		ProtocolVersion: guestcontrol.ProtocolVersion, SessionID: request.SessionID,
		LaunchNonce: launchNonce, ControlToken: controlToken, SupervisorToken: supervisorToken,
		Profile: profile.Name, ProfileDigest: profile.Guest.ProfileDigest, Policy: profile.Guest.Policy,
		Workspace: profile.Guest.Workspace, VSockCID: lease.CID, VSockPort: profile.Guest.ControlPort,
		SupervisorPort: profile.Guest.SupervisorPort, ExpectedGeneration: 1,
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeExclusivePrivateFile(layout.GuestManifest, append(manifestData, '\n')); err != nil {
		return nil, fmt.Errorf("write external runner guest manifest: %w", err)
	}
	manifestDigest, err := HostMonitorFileSHA256(layout.GuestManifest)
	if err != nil {
		return nil, err
	}
	monitorID, err := newProviderSecret()
	if err != nil {
		return nil, err
	}
	launchRequest := HostMonitorRequest{
		SchemaVersion: HostMonitorSchemaVersion, MonitorID: monitorID,
		SessionID: request.SessionID, StateDir: request.StateDir, SourceWorkspace: request.Session.Workspace,
		ProfileFile: p.options.Profiles[request.Profile], ProfileFileSHA256: profileFileDigest,
		ProfileName: profile.Name, ProfileDigest: profile.ProfileDigest, GuestProfileDigest: profile.Guest.ProfileDigest,
		GuestPolicy: profile.Guest.Policy, GuestControlPort: profile.Guest.ControlPort, GuestSupervisorPort: profile.Guest.SupervisorPort,
		GuestManifestSHA256: manifestDigest, ExpectedGuestGeneration: 1, LaunchNonce: launchNonce,
		CIDLeaseRoot: p.options.CIDLeaseRoot, CIDLease: lease, CreatedAt: time.Now().UTC(),
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
			_ = stopExactHostMonitor(context.Background(), monitor)
		}
	}()
	status, err := waitForHostMonitorReady(ctx, request.StateDir, monitor, profile.ReadinessTimeout())
	if err != nil {
		return nil, err
	}
	instance, err := p.instanceFromStatus(request.StateDir, profile, status)
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
	profile, _, err := p.profile(manifest.Profile)
	if err != nil {
		return nil, err
	}
	status, err := ReadHostMonitorStatus(manifest.StateDir)
	if err != nil {
		return nil, err
	}
	instance, err := p.instanceFromStatus(manifest.StateDir, profile, status)
	if err != nil {
		return nil, err
	}
	if manifest.Identity != (runtimeprovider.Identity{}) && (instance.Identity() != manifest.Identity || instance.Endpoint() != manifest.Endpoint) {
		return nil, fmt.Errorf("external runner exact incarnation mismatch")
	}
	return instance, nil
}

func (p *Provider) Recover(ctx context.Context, manifest runtimeprovider.Manifest) (runtimeprovider.Instance, error) {
	instance, err := p.Open(ctx, manifest)
	if err != nil {
		return nil, fmt.Errorf("diagnostic external runner cannot recreate a stopped instance: %w", err)
	}
	status, err := instance.Probe(ctx)
	if err != nil || !status.Ready {
		return nil, fmt.Errorf("diagnostic external runner is not live and cannot be recreated")
	}
	return instance, nil
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

func (p *Provider) instanceFromStatus(stateDir string, profile Profile, status HostMonitorStatus) (*providerInstance, error) {
	if status.Guest == nil || status.Endpoint == nil || status.Profile != profile.Name || status.GuestProfileDigest != profile.Guest.ProfileDigest {
		return nil, fmt.Errorf("external runner status lacks an authenticated guest endpoint")
	}
	request, err := ReadHostMonitorRequest(stateDir)
	if err != nil {
		return nil, err
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
	return runtimeprovider.Status{Identity: identity, Endpoint: i.Endpoint(), State: state, Ready: ready, Recoverable: false, LastError: status.LastError}, ctx.Err()
}

func (i *providerInstance) ControlPlane(ctx context.Context) (runtimeprovider.ControlPlaneSnapshot, error) {
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
	metadata := detached.Metadata{
		SessionID: i.request.SessionID, ID: i.request.SessionID, CreatedAt: i.request.CreatedAt,
		State: detached.LifecycleReady, Policy: i.request.GuestPolicy,
		RealWorkspace: i.request.SourceWorkspace, WorkspaceMode: string(types.WorkspaceModeShadow), Worktree: layout.WorkspaceDir,
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
		i.stopErr = stopExactHostMonitor(ctx, i.status.Monitor)
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
		if status.State != HostMonitorStopped && !(status.State == HostMonitorFailed && status.RunnerReaped && status.RelayClosed) {
			i.destroyErr = fmt.Errorf("external runner lacks terminal teardown evidence")
			return
		}
		i.destroyErr = ReleaseCID(ctx, i.request.CIDLeaseRoot, i.request.CIDLease, i.profile.VSock.CIDMin, i.profile.VSock.CIDMax)
	})
	return i.destroyErr
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

func newProviderSecret() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

var _ runtimeprovider.Provider = (*Provider)(nil)
var _ runtimeprovider.Instance = (*providerInstance)(nil)
