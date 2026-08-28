//go:build linux

package externalrunner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/guestcontrol"
	"github.com/agentsh/agentsh/internal/runtimeprovider"
	"github.com/agentsh/agentsh/internal/runtimeprovider/artifact"
	"github.com/agentsh/agentsh/pkg/types"
)

func testProviderV2Profile(t *testing.T) Profile {
	t.Helper()
	profile := testProfile(t)
	profile.Schema = ProfileSchemaV2
	profile.Name = "pi-linux-qemu-v2"
	profile.Guest.Protocol = guestcontrol.ProtocolVersionV3
	profile.WorkspaceVolume = &WorkspaceVolumeSpec{
		Model: WorkspaceVolumeModel, Format: WorkspaceVolumeFormat, Filesystem: WorkspaceVolumeFilesystem,
		RunnerFD: WorkspaceVolumeRunnerFD, VirtualSizeBytes: 8 << 30,
	}
	return profile
}

func testProviderV2Request(t *testing.T, profile Profile) runtimeprovider.Request {
	t.Helper()
	sessionID := "session-11111111-1111-4111-8111-111111111111"
	stateDir := filepath.Join(t.TempDir(), sessionID)
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	descriptor := artifact.Descriptor{
		SchemaVersion: artifact.SchemaVersion, ArtifactID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", SessionID: sessionID,
		Kind: artifact.KindGitInputBundle, MediaType: artifact.MediaTypeGitBundle, SHA256: digest([]byte("input")), Size: 5, Complete: true, CreatedAt: time.Now().UTC(),
	}
	return runtimeprovider.Request{
		SessionID: sessionID, Provider: ProviderName, Profile: profile.Name, StateDir: stateDir, InputArtifact: &descriptor,
		Session: types.CreateSessionRequest{
			ID: sessionID, Workspace: t.TempDir(), WorkspaceMode: string(types.WorkspaceModeShadow), Policy: profile.Guest.Policy,
		},
	}
}

func TestProviderPreflightAdmitsV2WithExactGitInputArtifact(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("external runner provider preflight is x86_64-only")
	}
	profile := testProviderV2Profile(t)
	provider, err := NewProvider(ProviderOptions{
		Enabled: true, Profiles: map[string]string{profile.Name: writeProfile(t, profile)},
		CIDLeaseRoot: filepath.Join(t.TempDir(), "cid-leases"), MonitorExecutable: filepath.Join(t.TempDir(), "agentsh"),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := testProviderV2Request(t, profile)
	if _, err := provider.Preflight(context.Background(), request); err != nil {
		t.Fatalf("v2 Preflight error = %v", err)
	}
	missing := *request.InputArtifact
	request.InputArtifact = nil
	if _, err := provider.Preflight(context.Background(), request); err == nil {
		t.Fatal("v2 Preflight accepted a missing Git input artifact")
	}
	request.InputArtifact = &missing
	request.InputArtifact.SessionID = "session-22222222-2222-4222-8222-222222222222"
	if _, err := provider.Preflight(context.Background(), request); err == nil {
		t.Fatal("v2 Preflight accepted a cross-session Git input artifact")
	}
}

func TestProviderDormantV2ManifestCarriesExactRequestVolume(t *testing.T) {
	profile := testProviderV2Profile(t)
	request := testProviderV2Request(t, profile)
	manifest := newProviderGuestManifest(
		request.SessionID, profile, 41001,
		strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64), testWorkspaceVolumeID,
	)
	if manifest.ProtocolVersion != guestcontrol.ProtocolVersionV3 || manifest.VolumeID != testWorkspaceVolumeID {
		t.Fatalf("dormant v2 manifest = %+v", manifest)
	}
	if err := manifest.Validate(profile.Guest.Workspace, profile.Name, profile.Guest.ProfileDigest, []string{profile.Guest.Policy}); err != nil {
		t.Fatal(err)
	}
}

func TestProviderOpenBindsImmutableRequestProfileSnapshot(t *testing.T) {
	stateDir, request, profile, manifest := prepareHostMonitorFixture(t)
	writeReadyProviderFixture(t, stateDir, request, profile, manifest)
	provider, err := NewProvider(ProviderOptions{
		Enabled: true, Profiles: map[string]string{profile.Name: request.ProfileFile},
		CIDLeaseRoot: request.CIDLeaseRoot, MonitorExecutable: filepath.Join(t.TempDir(), "agentsh"),
	})
	if err != nil {
		t.Fatal(err)
	}
	providerManifest := runtimeprovider.Manifest{Profile: profile.Name, StateDir: stateDir}
	if _, err := provider.Open(context.Background(), providerManifest); err != nil {
		t.Fatalf("open exact immutable profile: %v", err)
	}

	// Keep the separately pinned profile digest unchanged while changing valid
	// operator-profile bytes. Open must bind the file snapshot hash too.
	profile.Timeouts.ReadinessSeconds++
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(request.ProfileFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Open(context.Background(), providerManifest); err == nil || !strings.Contains(err.Error(), "immutable request profile binding") {
		t.Fatalf("Open accepted operator profile file drift: %v", err)
	}
}

func TestProviderInstanceBindingRejectsProfileDigestSchemaAndVolumeContractDrift(t *testing.T) {
	_, request, profile, _ := prepareV2HostMonitorFixture(t)
	if err := validateHostMonitorProfileBinding(request, profile, request.ProfileFileSHA256); err != nil {
		t.Fatalf("exact v2 profile binding: %v", err)
	}

	digestDrift := profile
	digestDrift.ProfileDigest = digest([]byte("different-operator-profile"))
	if err := validateHostMonitorProfileBinding(request, digestDrift, request.ProfileFileSHA256); err == nil {
		t.Fatal("instance binding accepted profile digest drift")
	}
	schemaDrift := profile
	schemaDrift.Schema = ProfileSchemaV1
	schemaDrift.WorkspaceVolume = nil
	if err := validateHostMonitorProfileBinding(request, schemaDrift, request.ProfileFileSHA256); err == nil {
		t.Fatal("instance binding accepted profile schema drift")
	}
	contractDrift := profile
	contract := *profile.WorkspaceVolume
	contract.VirtualSizeBytes += 1 << 30
	contractDrift.WorkspaceVolume = &contract
	if err := validateHostMonitorProfileBinding(request, contractDrift, request.ProfileFileSHA256); err == nil {
		t.Fatal("instance binding accepted workspace volume contract drift")
	}
}

func TestProviderV2ControlPlaneRequiresAuthenticatedEndpoint(t *testing.T) {
	stateDir, request, profile, _ := prepareV2HostMonitorFixture(t)
	instance := &providerInstance{profile: profile, request: request}
	if _, err := instance.ControlPlane(context.Background()); err == nil {
		t.Fatal("v2 control plane published without an authenticated endpoint")
	}
	if _, err := os.Lstat(detached.MetadataPath(stateDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("v2 control plane published premature metadata: %v", err)
	}
}

func TestProviderV2DestroyReleasesCIDButRetainsWorkspaceVolume(t *testing.T) {
	stateDir, request, profile, _ := prepareV2HostMonitorFixture(t)
	marker := filepath.Join(stateDir, "runtime", "volumes", "workspace", "retained")
	if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte("retained\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	monitor := HostProcessIdentity{PID: 101, StartIdentity: "monitor-start", BootID: "boot-id"}
	status := HostMonitorStatus{
		SchemaVersion: request.SchemaVersion, Revision: 2,
		MonitorID: request.MonitorID, SessionID: request.SessionID,
		Profile: profile.Name, ExternalProfileDigest: profile.ProfileDigest, GuestProfileDigest: profile.Guest.ProfileDigest,
		VolumeID: request.VolumeID, State: HostMonitorStopped, CreatedAt: now, UpdatedAt: now,
		Monitor: monitor,
		Runner: &HostProcessIdentity{
			PID: 102, ProcessGroup: 102, StartIdentity: "runner-start", BootID: "boot-id",
		},
		RunnerExit: &HostRunnerExit{ExitCode: 0}, RunnerReaped: true, RelayClosed: true, VolumeClosed: true,
	}
	layout, err := HostMonitorPaths(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeHostMonitorStatus(layout.StatusPath, status); err != nil {
		t.Fatal(err)
	}
	instance := &providerInstance{profile: profile, request: request, status: HostMonitorStatus{Monitor: monitor}}
	if err := instance.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCIDLease(context.Background(), request.CIDLeaseRoot, request.CIDLease, profile.VSock.CIDMin, profile.VSock.CIDMax); err == nil {
		t.Fatal("provider Destroy retained the CID lease")
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "retained\n" {
		t.Fatalf("provider Destroy deleted the workspace volume: %q, %v", data, err)
	}
}

func TestExactHostMonitorStatusTerminalAcceptsConsistentTerminalEvidence(t *testing.T) {
	monitor := HostProcessIdentity{PID: 101, StartIdentity: "monitor-start", BootID: "boot-id"}
	runner := &HostProcessIdentity{PID: 102, ProcessGroup: 102, StartIdentity: "runner-start", BootID: "boot-id"}
	exit := &HostRunnerExit{ExitCode: 1}
	volumeID := "22222222-2222-4222-8222-222222222222"
	for name, status := range map[string]HostMonitorStatus{
		"v1-stopped": {
			SchemaVersion: HostMonitorSchemaVersionV1, State: HostMonitorStopped, Monitor: monitor,
			Runner: runner, RunnerExit: exit, RunnerReaped: true, RelayClosed: true,
		},
		"v1-failed-after-runner": {
			SchemaVersion: HostMonitorSchemaVersionV1, State: HostMonitorFailed, Monitor: monitor,
			Runner: runner, RunnerExit: exit, RunnerReaped: true, RelayClosed: true,
		},
		"v1-true-no-child": {
			SchemaVersion: HostMonitorSchemaVersionV1, State: HostMonitorFailed, Monitor: monitor, RelayClosed: true,
		},
		"v2-true-no-child": {
			SchemaVersion: HostMonitorSchemaVersionV2, State: HostMonitorFailed, Monitor: monitor,
			VolumeID: volumeID, RelayClosed: true, VolumeClosed: true,
		},
		"v2-startup-child-reaped": {
			SchemaVersion: HostMonitorSchemaVersionV2, State: HostMonitorFailed, Monitor: monitor,
			VolumeID: volumeID, RunnerExit: exit, StartupChildReaped: true, RelayClosed: true, VolumeClosed: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if !exactHostMonitorStatusTerminal(status, monitor) {
				t.Fatal("exact terminal teardown evidence was not accepted")
			}
			wrongMonitor := monitor
			wrongMonitor.StartIdentity = "replacement"
			if exactHostMonitorStatusTerminal(status, wrongMonitor) {
				t.Fatal("terminal evidence for a different monitor identity was accepted")
			}
		})
	}
}

func TestExactHostMonitorStatusTerminalRejectsIncompleteOrMixedEvidence(t *testing.T) {
	monitor := HostProcessIdentity{PID: 101, StartIdentity: "monitor-start", BootID: "boot-id"}
	runner := &HostProcessIdentity{PID: 102, ProcessGroup: 102, StartIdentity: "runner-start", BootID: "boot-id"}
	exit := &HostRunnerExit{ExitCode: 1}
	volumeID := "22222222-2222-4222-8222-222222222222"
	validRunnerFailure := HostMonitorStatus{
		SchemaVersion: HostMonitorSchemaVersionV2, State: HostMonitorFailed, Monitor: monitor, VolumeID: volumeID,
		Runner: runner, RunnerExit: exit, RunnerReaped: true, RelayClosed: true, VolumeClosed: true,
	}
	openRelay := validRunnerFailure
	openRelay.RelayClosed = false
	openVolume := validRunnerFailure
	openVolume.VolumeClosed = false
	missingStoppedRunner := validRunnerFailure
	missingStoppedRunner.State = HostMonitorStopped
	missingStoppedRunner.Runner = nil
	exitWithoutStartupMarker := validRunnerFailure
	exitWithoutStartupMarker.Runner = nil
	exitWithoutStartupMarker.RunnerReaped = false
	startupMarkerWithoutExit := validRunnerFailure
	startupMarkerWithoutExit.Runner = nil
	startupMarkerWithoutExit.RunnerExit = nil
	startupMarkerWithoutExit.RunnerReaped = false
	startupMarkerWithoutExit.StartupChildReaped = true
	startupMarkerWithRunnerReaped := validRunnerFailure
	startupMarkerWithRunnerReaped.Runner = nil
	startupMarkerWithRunnerReaped.StartupChildReaped = true
	startupMarkerWithRunner := validRunnerFailure
	startupMarkerWithRunner.StartupChildReaped = true
	v1StartupMarker := HostMonitorStatus{
		SchemaVersion: HostMonitorSchemaVersionV1, State: HostMonitorFailed, Monitor: monitor,
		RunnerExit: exit, StartupChildReaped: true, RelayClosed: true,
	}
	for name, status := range map[string]HostMonitorStatus{
		"open-relay":                           openRelay,
		"open-volume":                          openVolume,
		"stopped-without-runner":               missingStoppedRunner,
		"exit-without-startup-marker":          exitWithoutStartupMarker,
		"startup-marker-without-exit":          startupMarkerWithoutExit,
		"startup-marker-with-runner-reaped":    startupMarkerWithRunnerReaped,
		"startup-marker-with-published-runner": startupMarkerWithRunner,
		"schema-v1-startup-marker":             v1StartupMarker,
	} {
		t.Run(name, func(t *testing.T) {
			if exactHostMonitorStatusTerminal(status, monitor) {
				t.Fatal("incomplete or mixed terminal evidence was accepted")
			}
		})
	}
}

func writeReadyProviderFixture(t *testing.T, stateDir string, request HostMonitorRequest, profile Profile, manifest guestcontrol.Manifest) {
	t.Helper()
	start, boot, err := detached.CurrentProcessIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	handshake := testHostHandshake(manifest)
	secret := HostMonitorGuestSecret{
		SchemaVersion: HostMonitorSchemaVersionV1, MonitorID: request.MonitorID, SessionID: request.SessionID,
		Generation: handshake.Generation, IncarnationID: handshake.IncarnationID, EventToken: handshake.EventToken,
	}
	if err := WriteHostMonitorGuestSecret(stateDir, request, secret); err != nil {
		t.Fatal(err)
	}
	layout, err := HostMonitorPaths(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	status := HostMonitorStatus{
		SchemaVersion: request.SchemaVersion, Revision: 1,
		MonitorID: request.MonitorID, SessionID: request.SessionID,
		Profile: profile.Name, ExternalProfileDigest: profile.ProfileDigest, GuestProfileDigest: profile.Guest.ProfileDigest,
		VolumeID: request.VolumeID, State: HostMonitorControlReady, CreatedAt: now, UpdatedAt: now,
		Monitor:     HostProcessIdentity{PID: os.Getpid(), StartIdentity: start, BootID: boot},
		Runner:      &HostProcessIdentity{PID: os.Getpid(), ProcessGroup: os.Getpid(), StartIdentity: start, BootID: boot},
		Guest:       pointerTo(publicHostGuestIdentity(handshake)),
		Endpoint:    &runtimeprovider.Endpoint{Transport: "unix", Address: layout.RelayPath},
		RelayClosed: false,
	}
	if err := writeHostMonitorStatus(layout.StatusPath, status); err != nil {
		t.Fatal(err)
	}
}
