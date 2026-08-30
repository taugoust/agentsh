package externalrunner

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/guestcontrol"
	"github.com/agentsh/agentsh/internal/runtimeprovider"
	"github.com/agentsh/agentsh/internal/runtimeprovider/artifact"
	"github.com/google/uuid"
)

const (
	HostMonitorSchemaVersionV1 = 1
	HostMonitorSchemaVersionV2 = 2
	HostMonitorSchemaVersionV3 = 3

	// HostMonitorSchemaVersion remains the v1 value for source compatibility.
	// New artifacts must select a version from their bound profile schema.
	HostMonitorSchemaVersion = HostMonitorSchemaVersionV1

	HostMonitorRequestName     = "host-monitor-request.json"
	HostMonitorStatusName      = "host-monitor-status.json"
	HostMonitorLockName        = "host-monitor.lock"
	HostMonitorSocketName      = "supervisor.sock"
	HostMonitorGuestSecretName = "guest-secret.json"
	WorkspaceBaselineName      = "workspace-baseline.json"
	HostMonitorMaxFileBytes    = 64 * 1024
)

type HostMonitorState string

const (
	HostMonitorInitializing HostMonitorState = "initializing"
	HostMonitorBooting      HostMonitorState = "booting"
	HostMonitorControlReady HostMonitorState = "control_ready"
	HostMonitorStopping     HostMonitorState = "stopping"
	HostMonitorStopped      HostMonitorState = "stopped"
	HostMonitorFailed       HostMonitorState = "failed"
)

type HostMonitorLayout struct {
	StateDir     string
	RuntimeDir   string
	WorkspaceDir string
	ControlDir   string
	HostDir      string
	LogsDir      string
	RequestPath  string
	StatusPath   string
	LockPath     string
	// GuestManifest is the host-authoritative launch manifest snapshot. It must
	// never reside in a directory exposed writable to the guest.
	GuestManifest string
	// GuestManifestDelivery is an untrusted one-way delivery copy consumed by
	// the external runner. A hostile guest may corrupt it; host code must never
	// reread it as authority.
	GuestManifestDelivery string
	RelayPath             string
	RunnerLog             string
	NetworkAudit          string
	GuestSecret           string
	BaselinePath          string
}

func HostMonitorPaths(stateDir string) (HostMonitorLayout, error) {
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir || filepath.Base(stateDir) == stateDir {
		return HostMonitorLayout{}, fmt.Errorf("host monitor state directory must be clean and absolute")
	}
	runtimeDir := filepath.Join(stateDir, "runtime")
	hostDir := filepath.Join(runtimeDir, "host")
	controlDir := filepath.Join(runtimeDir, "control")
	layout := HostMonitorLayout{
		StateDir: stateDir, RuntimeDir: runtimeDir,
		WorkspaceDir: filepath.Join(runtimeDir, "workspace"),
		ControlDir:   controlDir, HostDir: hostDir, LogsDir: filepath.Join(runtimeDir, "logs"),
		RequestPath:           filepath.Join(hostDir, HostMonitorRequestName),
		StatusPath:            filepath.Join(hostDir, HostMonitorStatusName),
		LockPath:              filepath.Join(hostDir, HostMonitorLockName),
		GuestManifest:         filepath.Join(hostDir, "guest-manifest.json"),
		GuestManifestDelivery: filepath.Join(controlDir, "request.json"),
		RelayPath:             hostMonitorRelayPath(stateDir, hostDir),
		RunnerLog:             filepath.Join(runtimeDir, "logs", "runner.log"),
		NetworkAudit:          filepath.Join(runtimeDir, "logs", HostEgressAuditName),
		GuestSecret:           filepath.Join(hostDir, HostMonitorGuestSecretName),
		BaselinePath:          filepath.Join(hostDir, WorkspaceBaselineName),
	}
	return layout, nil
}

const (
	HostEgressApprovalTokenEnv      = "AGENTSH_HOST_EGRESS_APPROVAL_TOKEN"
	HostEgressApprovalCredentialEnv = "AGENTSH_HOST_EGRESS_APPROVAL_CREDENTIAL_FILE"
	HostEgressApprovalSessionEnv    = "AGENTSH_HOST_EGRESS_APPROVAL_SESSION_ID"
	HostEgressApprovalSupervisorEnv = "AGENTSH_HOST_EGRESS_APPROVAL_SUPERVISOR"
	HostEgressApprovalHeader        = "X-AgentSH-Guest-Egress-Approval"
)

type HostEgressApprovalBinding struct {
	ParentSessionID string `json:"parent_session_id"`
	SupervisorURL   string `json:"supervisor_url"`
	Token           string `json:"token"`
}

func (b HostEgressApprovalBinding) Validate() error {
	decoded, tokenErr := base64.RawURLEncoding.DecodeString(b.Token)
	socketPath := strings.TrimPrefix(b.SupervisorURL, "unix://")
	if runtimeprovider.ValidateName(b.ParentSessionID) != nil || !strings.HasPrefix(b.ParentSessionID, "session-") || tokenErr != nil || len(decoded) != 32 ||
		!strings.HasPrefix(b.SupervisorURL, "unix://") || !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath {
		return fmt.Errorf("host egress approval binding is invalid")
	}
	return nil
}

type HostMonitorRequest struct {
	SchemaVersion           int                        `json:"schema_version"`
	MonitorID               string                     `json:"monitor_id"`
	SessionID               string                     `json:"session_id"`
	StateDir                string                     `json:"state_dir"`
	SourceWorkspace         string                     `json:"source_workspace"`
	VolumeID                string                     `json:"volume_id,omitempty"`
	ProfileFile             string                     `json:"profile_file"`
	ProfileFileSHA256       string                     `json:"profile_file_sha256"`
	ProfileName             string                     `json:"profile_name"`
	ProfileDigest           string                     `json:"profile_digest"`
	ProfileSchema           string                     `json:"profile_schema,omitempty"`
	WorkspaceVolume         *WorkspaceVolumeSpec       `json:"workspace_volume,omitempty"`
	HostEgress              *HostEgressSpec            `json:"host_egress,omitempty"`
	EgressPort              uint32                     `json:"egress_port,omitempty"`
	HostEgressApproval      *HostEgressApprovalBinding `json:"host_egress_approval,omitempty"`
	InputArtifact           *artifact.Descriptor       `json:"input_artifact,omitempty"`
	GuestProfileDigest      string                     `json:"guest_profile_digest"`
	GuestPolicy             string                     `json:"guest_policy"`
	GuestControlPort        uint32                     `json:"guest_control_port"`
	GuestSupervisorPort     uint32                     `json:"guest_supervisor_port"`
	GuestManifestSHA256     string                     `json:"guest_manifest_sha256"`
	ExpectedGuestGeneration uint64                     `json:"expected_guest_generation"`
	LaunchNonce             string                     `json:"launch_nonce"`
	CIDLeaseRoot            string                     `json:"cid_lease_root"`
	CIDLease                CIDLease                   `json:"cid_lease"`
	CreatedAt               time.Time                  `json:"created_at"`
}

func (r HostMonitorRequest) Validate(stateDir string) error {
	if (r.SchemaVersion != HostMonitorSchemaVersionV1 && r.SchemaVersion != HostMonitorSchemaVersionV2 && r.SchemaVersion != HostMonitorSchemaVersionV3) || !validHexSecret(r.MonitorID) {
		return fmt.Errorf("host monitor request schema or identity is invalid")
	}
	switch r.SchemaVersion {
	case HostMonitorSchemaVersionV1:
		if r.VolumeID != "" || r.ProfileSchema != "" || r.WorkspaceVolume != nil || r.HostEgress != nil || r.EgressPort != 0 || r.HostEgressApproval != nil || r.InputArtifact != nil {
			return fmt.Errorf("host monitor v1 request contains schema-v2 workspace volume fields")
		}
	case HostMonitorSchemaVersionV2:
		if !canonicalWorkspaceVolumeUUID(r.VolumeID) || r.ProfileSchema != ProfileSchemaV2 || r.WorkspaceVolume == nil || r.WorkspaceVolume.Validate() != nil || r.HostEgress != nil || r.EgressPort != 0 || r.HostEgressApproval != nil ||
			r.InputArtifact == nil || r.InputArtifact.Validate() != nil || r.InputArtifact.SessionID != r.SessionID || r.InputArtifact.Kind != artifact.KindGitInputBundle {
			return fmt.Errorf("host monitor v2 workspace volume or input artifact binding is invalid")
		}
	case HostMonitorSchemaVersionV3:
		if !canonicalWorkspaceVolumeUUID(r.VolumeID) || r.ProfileSchema != ProfileSchemaV3 || r.WorkspaceVolume == nil || r.WorkspaceVolume.Validate() != nil ||
			r.HostEgress == nil || r.HostEgress.Validate() != nil || !validPort(r.EgressPort) || (r.HostEgressApproval != nil && r.HostEgressApproval.Validate() != nil) || r.InputArtifact == nil || r.InputArtifact.Validate() != nil ||
			r.InputArtifact.SessionID != r.SessionID || r.InputArtifact.Kind != artifact.KindGitInputBundle {
			return fmt.Errorf("host monitor v3 workspace, egress, or input artifact binding is invalid")
		}
	}
	if err := runtimeprovider.ValidateName(r.SessionID); err != nil || !strings.HasPrefix(r.SessionID, "session-") {
		return fmt.Errorf("host monitor session identity is invalid")
	}
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir || r.StateDir != stateDir || filepath.Base(stateDir) != r.SessionID ||
		!filepath.IsAbs(r.SourceWorkspace) || filepath.Clean(r.SourceWorkspace) != r.SourceWorkspace || pathsOverlap(r.SourceWorkspace, stateDir) {
		return fmt.Errorf("host monitor request is not bound to its exact state directory")
	}
	profileErr := runtimeprovider.ValidateName(r.ProfileName)
	policyErr := runtimeprovider.ValidateName(r.GuestPolicy)
	if profileErr != nil || policyErr != nil || !validSHA256(r.ProfileFileSHA256) || !validSHA256(r.ProfileDigest) || !validSHA256(r.GuestProfileDigest) ||
		!validSHA256(r.GuestManifestSHA256) || !validHexSecret(r.LaunchNonce) || r.ExpectedGuestGeneration == 0 ||
		!validPort(r.GuestControlPort) || !validPort(r.GuestSupervisorPort) || r.GuestControlPort == r.GuestSupervisorPort ||
		r.SchemaVersion == HostMonitorSchemaVersionV3 && (r.EgressPort == r.GuestControlPort || r.EgressPort == r.GuestSupervisorPort || r.EgressPort != r.CIDLease.CID && validPort(r.CIDLease.CID) && r.CIDLease.CID != r.GuestControlPort && r.CIDLease.CID != r.GuestSupervisorPort) {
		return fmt.Errorf("host monitor immutable launch binding is invalid")
	}
	for name, path := range map[string]string{"profile": r.ProfileFile, "CID lease root": r.CIDLeaseRoot} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("host monitor %s path must be clean and absolute", name)
		}
	}
	if err := r.CIDLease.Validate(r.CIDLease.CID, r.CIDLease.CID); err != nil || r.CIDLease.SessionID != r.SessionID {
		return fmt.Errorf("host monitor CID lease identity is invalid")
	}
	if r.CreatedAt.IsZero() || r.CreatedAt.After(time.Now().UTC().Add(5*time.Minute)) {
		return fmt.Errorf("host monitor request timestamp is invalid")
	}
	return nil
}

// UnmarshalJSON preserves the exact v1 unknown-field contract even though the
// in-memory request type also carries schema-v2 fields.
func (r *HostMonitorRequest) UnmarshalJSON(data []byte) error {
	switch hostMonitorJSONSchemaVersion(data) {
	case HostMonitorSchemaVersionV1:
		if err := rejectHostMonitorJSONFields(data, "volume_id", "profile_schema", "workspace_volume", "host_egress", "egress_port", "input_artifact"); err != nil {
			return err
		}
	case HostMonitorSchemaVersionV2:
		if err := rejectHostMonitorJSONFields(data, "host_egress", "egress_port"); err != nil {
			return err
		}
	}
	type requestAlias HostMonitorRequest
	var decoded requestAlias
	if err := decodeStrictHostMonitorJSON(data, &decoded); err != nil {
		return err
	}
	*r = HostMonitorRequest(decoded)
	return nil
}

func hostMonitorSchemaVersionForProfile(profileSchema string) (int, error) {
	switch profileSchema {
	case ProfileSchemaV1:
		return HostMonitorSchemaVersionV1, nil
	case ProfileSchemaV2:
		return HostMonitorSchemaVersionV2, nil
	case ProfileSchemaV3:
		return HostMonitorSchemaVersionV3, nil
	default:
		return 0, fmt.Errorf("host monitor external profile schema %q is unsupported", profileSchema)
	}
}

func guestProtocolVersionForHostMonitorSchema(schemaVersion int) (int, error) {
	switch schemaVersion {
	case HostMonitorSchemaVersionV1:
		return guestcontrol.ProtocolVersionV2, nil
	case HostMonitorSchemaVersionV2:
		return guestcontrol.ProtocolVersionV3, nil
	case HostMonitorSchemaVersionV3:
		return guestcontrol.ProtocolVersionV4, nil
	default:
		return 0, fmt.Errorf("host monitor schema version %d is unsupported", schemaVersion)
	}
}

func validateHostMonitorProfileBinding(request HostMonitorRequest, profile Profile, profileFileDigest string) error {
	expectedSchema, err := hostMonitorSchemaVersionForProfile(profile.Schema)
	if err != nil {
		return err
	}
	if request.SchemaVersion != expectedSchema || request.ProfileFileSHA256 != profileFileDigest ||
		request.ProfileName != profile.Name || request.ProfileDigest != profile.ProfileDigest || request.GuestProfileDigest != profile.Guest.ProfileDigest {
		return fmt.Errorf("host monitor request and immutable operator profile identity differ")
	}
	switch profile.Schema {
	case ProfileSchemaV1:
		if request.ProfileSchema != "" || request.WorkspaceVolume != nil || request.HostEgress != nil || request.EgressPort != 0 || request.VolumeID != "" || request.InputArtifact != nil {
			return fmt.Errorf("host monitor v1 request contains a workspace volume or input artifact contract")
		}
	case ProfileSchemaV2:
		if request.ProfileSchema != profile.Schema || request.WorkspaceVolume == nil || profile.WorkspaceVolume == nil || request.HostEgress != nil || request.EgressPort != 0 ||
			*request.WorkspaceVolume != *profile.WorkspaceVolume || !canonicalWorkspaceVolumeUUID(request.VolumeID) || request.InputArtifact == nil ||
			request.InputArtifact.Validate() != nil || request.InputArtifact.SessionID != request.SessionID || request.InputArtifact.Kind != artifact.KindGitInputBundle {
			return fmt.Errorf("host monitor v2 request workspace volume or input artifact contract differs from its immutable operator profile")
		}
	case ProfileSchemaV3:
		expectedPort, portErr := deriveHostEgressPort(profile, request.CIDLease.CID)
		if request.ProfileSchema != profile.Schema || request.WorkspaceVolume == nil || profile.WorkspaceVolume == nil || request.HostEgress == nil || profile.HostEgress == nil ||
			*request.WorkspaceVolume != *profile.WorkspaceVolume || *request.HostEgress != *profile.HostEgress || request.EgressPort != expectedPort || portErr != nil || !canonicalWorkspaceVolumeUUID(request.VolumeID) ||
			request.InputArtifact == nil || request.InputArtifact.Validate() != nil || request.InputArtifact.SessionID != request.SessionID || request.InputArtifact.Kind != artifact.KindGitInputBundle {
			return fmt.Errorf("host monitor v3 request contract differs from its immutable operator profile")
		}
	}
	return nil
}

type HostMonitorGuestSecret struct {
	SchemaVersion int    `json:"schema_version"`
	MonitorID     string `json:"monitor_id"`
	SessionID     string `json:"session_id"`
	Generation    uint64 `json:"generation"`
	IncarnationID string `json:"incarnation_id"`
	EventToken    string `json:"event_token"`
}

func (s HostMonitorGuestSecret) Validate(request HostMonitorRequest) error {
	if s.SchemaVersion != HostMonitorSchemaVersionV1 || s.MonitorID != request.MonitorID || s.SessionID != request.SessionID ||
		s.Generation != request.ExpectedGuestGeneration || !canonicalHostMonitorUUID(s.IncarnationID) || !validHexSecret(s.EventToken) {
		return fmt.Errorf("host monitor guest secret identity is invalid")
	}
	return nil
}

func WriteHostMonitorGuestSecret(stateDir string, request HostMonitorRequest, secret HostMonitorGuestSecret) error {
	layout, err := HostMonitorPaths(stateDir)
	if err != nil {
		return err
	}
	if err := secret.Validate(request); err != nil {
		return err
	}
	data, err := json.MarshalIndent(secret, "", "  ")
	if err != nil {
		return err
	}
	return writeExclusivePrivateFile(layout.GuestSecret, append(data, '\n'))
}

func ReadHostMonitorGuestSecret(stateDir string, request HostMonitorRequest) (HostMonitorGuestSecret, error) {
	layout, err := HostMonitorPaths(stateDir)
	if err != nil {
		return HostMonitorGuestSecret{}, err
	}
	var secret HostMonitorGuestSecret
	if err := readStrictPrivateJSON(layout.GuestSecret, &secret); err != nil {
		return HostMonitorGuestSecret{}, err
	}
	if err := secret.Validate(request); err != nil {
		return HostMonitorGuestSecret{}, err
	}
	return secret, nil
}

type HostProcessIdentity struct {
	PID           int    `json:"pid"`
	ProcessGroup  int    `json:"process_group,omitempty"`
	StartIdentity string `json:"start_identity"`
	BootID        string `json:"boot_id"`
}

func (i HostProcessIdentity) Validate(requireGroup bool) error {
	if i.PID <= 0 || strings.TrimSpace(i.StartIdentity) == "" || strings.TrimSpace(i.BootID) == "" {
		return fmt.Errorf("host monitor process identity is incomplete")
	}
	if requireGroup && i.ProcessGroup <= 0 {
		return fmt.Errorf("host monitor runner process group is missing")
	}
	return nil
}

type HostGuestIdentity struct {
	ProtocolVersion int    `json:"protocol_version"`
	SessionID       string `json:"session_id"`
	Generation      uint64 `json:"generation"`
	IncarnationID   string `json:"incarnation_id"`
	GuestBootID     string `json:"guest_boot_id"`
	Profile         string `json:"profile"`
	ProfileDigest   string `json:"profile_digest"`
	Policy          string `json:"policy"`
	VSockCID        uint32 `json:"vsock_cid"`
	VSockPort       uint32 `json:"vsock_port"`
	SupervisorPort  uint32 `json:"supervisor_port"`
	NetworkReady    bool   `json:"network_ready"`
	VolumeID        string `json:"volume_id,omitempty"`
	EgressPort      uint32 `json:"egress_port,omitempty"`
	EgressReady     bool   `json:"egress_ready,omitempty"`
}

func (i *HostGuestIdentity) UnmarshalJSON(data []byte) error {
	var envelope struct {
		ProtocolVersion int `json:"protocol_version"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return err
	}
	if envelope.ProtocolVersion == guestcontrol.ProtocolVersionV2 || envelope.ProtocolVersion == guestcontrol.ProtocolVersionV3 {
		if err := rejectHostMonitorJSONFields(data, "egress_port", "egress_ready"); err != nil {
			return err
		}
	}
	type identityAlias HostGuestIdentity
	var decoded identityAlias
	if err := decodeStrictHostMonitorJSON(data, &decoded); err != nil {
		return err
	}
	*i = HostGuestIdentity(decoded)
	return nil
}

func publicHostGuestIdentity(handshake guestcontrol.Handshake) HostGuestIdentity {
	return HostGuestIdentity{
		ProtocolVersion: handshake.ProtocolVersion, SessionID: handshake.SessionID,
		Generation: handshake.Generation, IncarnationID: handshake.IncarnationID,
		GuestBootID: handshake.GuestBootID,
		Profile:     handshake.Profile, ProfileDigest: handshake.ProfileDigest, Policy: handshake.Policy,
		VSockCID: handshake.VSockCID, VSockPort: handshake.VSockPort, SupervisorPort: handshake.SupervisorPort,
		NetworkReady: handshake.NetworkReady, VolumeID: handshake.VolumeID, EgressPort: handshake.EgressPort, EgressReady: handshake.EgressReady,
	}
}

type HostRunnerExit struct {
	ExitCode int  `json:"exit_code"`
	Signaled bool `json:"signaled,omitempty"`
}

type HostMonitorStatus struct {
	SchemaVersion         int                       `json:"schema_version"`
	Revision              uint64                    `json:"revision"`
	MonitorID             string                    `json:"monitor_id"`
	SessionID             string                    `json:"session_id"`
	Profile               string                    `json:"profile,omitempty"`
	ExternalProfileDigest string                    `json:"external_profile_digest,omitempty"`
	GuestProfileDigest    string                    `json:"guest_profile_digest,omitempty"`
	VolumeID              string                    `json:"volume_id,omitempty"`
	State                 HostMonitorState          `json:"state"`
	CreatedAt             time.Time                 `json:"created_at"`
	UpdatedAt             time.Time                 `json:"updated_at"`
	Monitor               HostProcessIdentity       `json:"monitor"`
	Runner                *HostProcessIdentity      `json:"runner,omitempty"`
	Guest                 *HostGuestIdentity        `json:"guest,omitempty"`
	Endpoint              *runtimeprovider.Endpoint `json:"endpoint,omitempty"`
	StopRequested         bool                      `json:"stop_requested,omitempty"`
	Forced                bool                      `json:"forced,omitempty"`
	RunnerExit            *HostRunnerExit           `json:"runner_exit,omitempty"`
	RunnerReaped          bool                      `json:"runner_reaped,omitempty"`
	StartupChildReaped    bool                      `json:"startup_child_reaped,omitempty"`
	RelayClosed           bool                      `json:"relay_closed,omitempty"`
	VolumeClosed          bool                      `json:"volume_closed,omitempty"`
	EgressBrokerClosed    bool                      `json:"egress_broker_closed,omitempty"`
	LastError             string                    `json:"last_error,omitempty"`
}

func (s HostMonitorStatus) Validate() error {
	if (s.SchemaVersion != HostMonitorSchemaVersionV1 && s.SchemaVersion != HostMonitorSchemaVersionV2 && s.SchemaVersion != HostMonitorSchemaVersionV3) || s.Revision == 0 || !validHexSecret(s.MonitorID) {
		return fmt.Errorf("host monitor status schema or identity is invalid")
	}
	if err := runtimeprovider.ValidateName(s.SessionID); err != nil || !strings.HasPrefix(s.SessionID, "session-") {
		return fmt.Errorf("host monitor status session identity is invalid")
	}
	if s.CreatedAt.IsZero() || s.UpdatedAt.Before(s.CreatedAt) {
		return fmt.Errorf("host monitor status timestamps are invalid")
	}
	if err := s.Monitor.Validate(false); err != nil {
		return err
	}
	if strings.ContainsRune(s.LastError, '\x00') || len(s.LastError) > 4096 {
		return fmt.Errorf("host monitor status error is invalid")
	}
	if s.SchemaVersion == HostMonitorSchemaVersionV1 {
		if s.VolumeID != "" || s.VolumeClosed || s.StartupChildReaped || s.EgressBrokerClosed ||
			s.Guest != nil && (s.Guest.ProtocolVersion != guestcontrol.ProtocolVersionV2 || s.Guest.VolumeID != "" || s.Guest.EgressPort != 0 || s.Guest.EgressReady) {
			return fmt.Errorf("host monitor v1 status contains schema-v2 guest or volume fields")
		}
		return validateHostMonitorStatusV1State(s)
	}
	if !canonicalWorkspaceVolumeUUID(s.VolumeID) {
		return fmt.Errorf("host monitor v2 workspace volume status is invalid")
	}
	if s.SchemaVersion == HostMonitorSchemaVersionV2 {
		if s.EgressBrokerClosed || s.Guest != nil && (s.Guest.ProtocolVersion != guestcontrol.ProtocolVersionV3 || s.Guest.VolumeID != s.VolumeID || s.Guest.EgressPort != 0 || s.Guest.EgressReady) {
			return fmt.Errorf("host monitor v2 guest volume identity is invalid")
		}
	} else if s.Guest != nil && (s.Guest.ProtocolVersion != guestcontrol.ProtocolVersionV4 || s.Guest.VolumeID != s.VolumeID || !validPort(s.Guest.EgressPort) || !s.Guest.EgressReady || s.Guest.NetworkReady) {
		return fmt.Errorf("host monitor v3 guest volume or egress identity is invalid")
	}
	if s.SchemaVersion == HostMonitorSchemaVersionV3 {
		return validateHostMonitorStatusV3State(s)
	}
	if s.StartupChildReaped && s.State != HostMonitorFailed {
		return fmt.Errorf("host monitor startup-child reap evidence is outside failed state")
	}
	if s.Runner != nil && s.VolumeClosed && !s.RunnerReaped {
		return fmt.Errorf("host monitor closed its workspace volume before exact runner reaping")
	}
	return validateHostMonitorStatusV2State(s)
}

// Keep this state validator semantically exact with the schema-v1 protocol:
// adding schema v2 must not make a formerly invalid v1 status valid or vice
// versa.
func validateHostMonitorStatusV1State(s HostMonitorStatus) error {
	switch s.State {
	case HostMonitorInitializing:
	case HostMonitorBooting, HostMonitorStopping:
		if s.Runner == nil || s.Runner.Validate(true) != nil {
			return fmt.Errorf("host monitor state %s requires a runner identity", s.State)
		}
	case HostMonitorControlReady:
		if s.Runner == nil || s.Runner.Validate(true) != nil || s.Guest == nil || s.Endpoint == nil || s.Endpoint.Validate() != nil || s.RelayClosed ||
			s.Guest.SessionID != s.SessionID || s.Guest.Profile != s.Profile || s.Guest.ProfileDigest != s.GuestProfileDigest {
			return fmt.Errorf("host monitor control-ready state is incomplete")
		}
	case HostMonitorStopped:
		if s.Runner == nil || s.Runner.Validate(true) != nil || s.RunnerExit == nil || !s.RunnerReaped || !s.RelayClosed {
			return fmt.Errorf("host monitor stopped state lacks exact teardown evidence")
		}
	case HostMonitorFailed:
		if s.Runner == nil && !s.RelayClosed {
			return fmt.Errorf("host monitor prelaunch failure state has an open relay")
		}
		if err := validateHostMonitorFailedRunnerEvidence(s); err != nil {
			return err
		}
	default:
		return fmt.Errorf("host monitor state %q is unsupported", s.State)
	}
	return nil
}

func validateHostMonitorFailedRunnerEvidence(s HostMonitorStatus) error {
	if s.Runner == nil {
		if s.StartupChildReaped {
			if (s.SchemaVersion != HostMonitorSchemaVersionV2 && s.SchemaVersion != HostMonitorSchemaVersionV3) || s.RunnerExit == nil || s.RunnerReaped {
				return fmt.Errorf("host monitor startup-child reap evidence is inconsistent")
			}
			return nil
		}
		if s.RunnerExit != nil || s.RunnerReaped {
			return fmt.Errorf("host monitor no-child prelaunch failure evidence is inconsistent")
		}
		return nil
	}
	if s.StartupChildReaped || s.Runner.Validate(true) != nil || (s.RunnerReaped && s.RunnerExit == nil) {
		return fmt.Errorf("host monitor failed state has inconsistent runner evidence")
	}
	return nil
}

func validateHostMonitorStatusV2State(s HostMonitorStatus) error {
	switch s.State {
	case HostMonitorInitializing:
	case HostMonitorBooting, HostMonitorStopping:
		if s.Runner == nil || s.Runner.Validate(true) != nil {
			return fmt.Errorf("host monitor state %s requires a runner identity", s.State)
		}
		if s.VolumeClosed {
			return fmt.Errorf("host monitor state %s cannot have a closed workspace volume", s.State)
		}
	case HostMonitorControlReady:
		if s.Runner == nil || s.Runner.Validate(true) != nil || s.Guest == nil || s.Endpoint == nil || s.Endpoint.Validate() != nil || s.RelayClosed ||
			s.VolumeClosed || s.Guest.SessionID != s.SessionID || s.Guest.Profile != s.Profile || s.Guest.ProfileDigest != s.GuestProfileDigest {
			return fmt.Errorf("host monitor control-ready state is incomplete")
		}
	case HostMonitorStopped:
		if s.Runner == nil || s.Runner.Validate(true) != nil || s.RunnerExit == nil || !s.RunnerReaped || !s.RelayClosed || !s.VolumeClosed {
			return fmt.Errorf("host monitor stopped state lacks exact teardown evidence")
		}
	case HostMonitorFailed:
		if s.Runner == nil && !s.RelayClosed {
			return fmt.Errorf("host monitor prelaunch failure state has an open relay")
		}
		if err := validateHostMonitorFailedRunnerEvidence(s); err != nil {
			return err
		}
	default:
		return fmt.Errorf("host monitor state %q is unsupported", s.State)
	}
	return nil
}

func validateHostMonitorStatusV3State(s HostMonitorStatus) error {
	if s.StartupChildReaped && s.State != HostMonitorFailed {
		return fmt.Errorf("host monitor startup-child reap evidence is outside failed state")
	}
	if s.Runner != nil && s.VolumeClosed && !s.RunnerReaped {
		return fmt.Errorf("host monitor closed its workspace volume before exact runner reaping")
	}
	switch s.State {
	case HostMonitorInitializing:
	case HostMonitorBooting:
		if s.Runner == nil || s.Runner.Validate(true) != nil || s.VolumeClosed || s.EgressBrokerClosed {
			return fmt.Errorf("host monitor state %s requires an open egress broker, volume, and runner identity", s.State)
		}
	case HostMonitorStopping:
		if s.Runner == nil || s.Runner.Validate(true) != nil || s.VolumeClosed {
			return fmt.Errorf("host monitor state %s requires a runner identity and open volume", s.State)
		}
	case HostMonitorControlReady:
		if s.Runner == nil || s.Runner.Validate(true) != nil || s.Guest == nil || s.Endpoint == nil || s.Endpoint.Validate() != nil || s.RelayClosed ||
			s.VolumeClosed || s.EgressBrokerClosed || s.Guest.SessionID != s.SessionID || s.Guest.Profile != s.Profile || s.Guest.ProfileDigest != s.GuestProfileDigest {
			return fmt.Errorf("host monitor control-ready state is incomplete")
		}
	case HostMonitorStopped:
		if s.Runner == nil || s.Runner.Validate(true) != nil || s.RunnerExit == nil || !s.RunnerReaped || !s.RelayClosed || !s.VolumeClosed || !s.EgressBrokerClosed {
			return fmt.Errorf("host monitor stopped state lacks exact teardown evidence")
		}
	case HostMonitorFailed:
		if s.Runner == nil && !s.RelayClosed {
			return fmt.Errorf("host monitor prelaunch failure state has an open relay")
		}
		if !s.EgressBrokerClosed {
			return fmt.Errorf("host monitor failed state has an open egress broker")
		}
		if err := validateHostMonitorFailedRunnerEvidence(s); err != nil {
			return err
		}
	default:
		return fmt.Errorf("host monitor state %q is unsupported", s.State)
	}
	return nil
}

// UnmarshalJSON keeps later status fields unknown to older schemas.
func (s *HostMonitorStatus) UnmarshalJSON(data []byte) error {
	switch hostMonitorJSONSchemaVersion(data) {
	case HostMonitorSchemaVersionV1:
		if err := rejectHostMonitorJSONFields(data, "volume_id", "volume_closed", "startup_child_reaped", "egress_broker_closed"); err != nil {
			return err
		}
	case HostMonitorSchemaVersionV2:
		if err := rejectHostMonitorJSONFields(data, "egress_broker_closed"); err != nil {
			return err
		}
	}
	type statusAlias HostMonitorStatus
	var decoded statusAlias
	if err := decodeStrictHostMonitorJSON(data, &decoded); err != nil {
		return err
	}
	*s = HostMonitorStatus(decoded)
	return nil
}

func WriteHostMonitorRequest(stateDir string, request HostMonitorRequest) error {
	layout, err := HostMonitorPaths(stateDir)
	if err != nil {
		return err
	}
	if err := request.Validate(stateDir); err != nil {
		return err
	}
	data, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return err
	}
	return writeExclusivePrivateFile(layout.RequestPath, append(data, '\n'))
}

func ReadHostMonitorRequest(stateDir string) (HostMonitorRequest, error) {
	layout, err := HostMonitorPaths(stateDir)
	if err != nil {
		return HostMonitorRequest{}, err
	}
	var request HostMonitorRequest
	if err := readStrictPrivateJSON(layout.RequestPath, &request); err != nil {
		return HostMonitorRequest{}, fmt.Errorf("read host monitor request: %w", err)
	}
	if err := request.Validate(stateDir); err != nil {
		return HostMonitorRequest{}, err
	}
	return request, nil
}

func ReadHostMonitorStatus(stateDir string) (HostMonitorStatus, error) {
	layout, err := HostMonitorPaths(stateDir)
	if err != nil {
		return HostMonitorStatus{}, err
	}
	var status HostMonitorStatus
	if err := readStrictPrivateJSON(layout.StatusPath, &status); err != nil {
		return HostMonitorStatus{}, fmt.Errorf("read host monitor status: %w", err)
	}
	if err := status.Validate(); err != nil {
		return HostMonitorStatus{}, err
	}
	request, err := ReadHostMonitorRequest(stateDir)
	if err != nil {
		return HostMonitorStatus{}, err
	}
	if status.SchemaVersion != request.SchemaVersion || status.SessionID != filepath.Base(stateDir) || status.SessionID != request.SessionID || status.MonitorID != request.MonitorID ||
		status.Profile != request.ProfileName || status.ExternalProfileDigest != request.ProfileDigest || status.GuestProfileDigest != request.GuestProfileDigest ||
		status.VolumeID != request.VolumeID {
		return HostMonitorStatus{}, fmt.Errorf("host monitor status is not bound to its immutable request")
	}
	if status.Endpoint != nil && (status.Endpoint.Transport != "unix" || status.Endpoint.Address != layout.RelayPath) {
		return HostMonitorStatus{}, fmt.Errorf("host monitor status endpoint is not the exact host relay")
	}
	expectedGuestProtocol, err := guestProtocolVersionForHostMonitorSchema(request.SchemaVersion)
	if err != nil {
		return HostMonitorStatus{}, err
	}
	expectedEgressPort := request.EgressPort
	if status.Guest != nil && (status.Guest.ProtocolVersion != expectedGuestProtocol || status.Guest.SessionID != request.SessionID ||
		status.Guest.Generation != request.ExpectedGuestGeneration || status.Guest.VolumeID != request.VolumeID ||
		status.Guest.Profile != request.ProfileName || status.Guest.ProfileDigest != request.GuestProfileDigest || status.Guest.Policy != request.GuestPolicy ||
		status.Guest.VSockCID != request.CIDLease.CID || status.Guest.VSockPort != request.GuestControlPort || status.Guest.SupervisorPort != request.GuestSupervisorPort || status.Guest.EgressPort != expectedEgressPort ||
		status.Guest.EgressReady != (request.SchemaVersion == HostMonitorSchemaVersionV3) || request.SchemaVersion == HostMonitorSchemaVersionV3 && status.Guest.NetworkReady ||
		!canonicalHostMonitorUUID(status.Guest.IncarnationID) || !canonicalHostMonitorUUID(status.Guest.GuestBootID)) {
		return HostMonitorStatus{}, fmt.Errorf("host monitor guest status is not bound to the immutable launch identity")
	}
	return status, nil
}

func writeExclusivePrivateFile(path string, data []byte) error {
	if len(data) > HostMonitorMaxFileBytes {
		return fmt.Errorf("protected host monitor file exceeds limit")
	}
	parent := filepath.Dir(path)
	tmp, err := os.CreateTemp(parent, ".host-monitor-request-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	_, writeErr := tmp.Write(data)
	syncErr := tmp.Sync()
	closeErr := tmp.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	// link(2) publishes the complete inode atomically and refuses replacement.
	if err := os.Link(tmpPath, path); err != nil {
		return err
	}
	if err := os.Remove(tmpPath); err != nil {
		removeErr := os.Remove(path)
		return errors.Join(err, removeErr, syncDirectory(parent))
	}
	if err := syncDirectory(parent); err != nil {
		removeErr := os.Remove(path)
		rollbackSyncErr := syncDirectory(parent)
		return errors.Join(err, removeErr, rollbackSyncErr)
	}
	return nil
}

func writeHostMonitorStatus(path string, status HostMonitorStatus) error {
	if err := status.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return fmt.Errorf("encode host monitor status: %w", err)
	}
	if len(data)+1 > HostMonitorMaxFileBytes {
		return fmt.Errorf("encoded host monitor status exceeds limit")
	}
	parent := filepath.Dir(path)
	tmp, err := os.CreateTemp(parent, ".host-monitor-status-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	_, writeErr := tmp.Write(append(data, '\n'))
	syncErr := tmp.Sync()
	closeErr := tmp.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func ReadHostGuestManifestSnapshot(path, workspace, profile, profileDigest string, policies []string) (guestcontrol.Manifest, string, error) {
	data, err := readPrivateHostMonitorFile(path)
	if err != nil {
		return guestcontrol.Manifest{}, "", err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var manifest guestcontrol.Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return guestcontrol.Manifest{}, "", fmt.Errorf("decode host guest manifest: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return guestcontrol.Manifest{}, "", fmt.Errorf("decode host guest manifest: %w", err)
	}
	if err := manifest.Validate(workspace, profile, profileDigest, policies); err != nil {
		return guestcontrol.Manifest{}, "", err
	}
	sum := sha256.Sum256(data)
	return manifest, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func HostMonitorFileSHA256(path string) (string, error) {
	data, err := readPrivateHostMonitorFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func readStrictPrivateJSON(path string, target any) error {
	data, err := readPrivateHostMonitorFile(path)
	if err != nil {
		return err
	}
	return decodeStrictHostMonitorJSON(data, target)
}

func decodeStrictHostMonitorJSON(data []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return requireEOF(decoder)
}

func hostMonitorJSONSchemaVersion(data []byte) int {
	var envelope struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return 0
	}
	return envelope.SchemaVersion
}

func rejectHostMonitorJSONFields(data []byte, forbidden ...string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for name := range fields {
		for _, candidate := range forbidden {
			// encoding/json matches tagged object names without regard to case.
			// Reject every spelling the shared v2-capable Go type would accept.
			if strings.EqualFold(name, candidate) {
				return fmt.Errorf("json: unknown field %q", name)
			}
		}
	}
	return nil
}

func readPrivateHostMonitorFile(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != 0o600 || before.Size() > HostMonitorMaxFileBytes {
		return nil, fmt.Errorf("protected host monitor file has unsafe type, permissions, or size")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("protected host monitor file identity changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, HostMonitorMaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > HostMonitorMaxFileBytes {
		return nil, fmt.Errorf("protected host monitor file exceeds limit")
	}
	return data, nil
}

func canonicalHostMonitorUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && value == parsed.String()
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
