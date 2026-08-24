package externalrunner

import (
	"crypto/sha256"
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
	"github.com/google/uuid"
)

const (
	HostMonitorSchemaVersion   = 1
	HostMonitorRequestName     = "host-monitor-request.json"
	HostMonitorStatusName      = "host-monitor-status.json"
	HostMonitorLockName        = "host-monitor.lock"
	HostMonitorSocketName      = "supervisor.sock"
	HostMonitorGuestSecretName = "guest-secret.json"
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
	StateDir      string
	RuntimeDir    string
	WorkspaceDir  string
	ControlDir    string
	HostDir       string
	LogsDir       string
	RequestPath   string
	StatusPath    string
	LockPath      string
	GuestManifest string
	RelayPath     string
	RunnerLog     string
	GuestSecret   string
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
		RequestPath:   filepath.Join(hostDir, HostMonitorRequestName),
		StatusPath:    filepath.Join(hostDir, HostMonitorStatusName),
		LockPath:      filepath.Join(hostDir, HostMonitorLockName),
		GuestManifest: filepath.Join(controlDir, "request.json"),
		RelayPath:     filepath.Join(hostDir, HostMonitorSocketName),
		RunnerLog:     filepath.Join(runtimeDir, "logs", "runner.log"),
		GuestSecret:   filepath.Join(hostDir, HostMonitorGuestSecretName),
	}
	return layout, nil
}

type HostMonitorRequest struct {
	SchemaVersion           int       `json:"schema_version"`
	MonitorID               string    `json:"monitor_id"`
	SessionID               string    `json:"session_id"`
	StateDir                string    `json:"state_dir"`
	SourceWorkspace         string    `json:"source_workspace"`
	ProfileFile             string    `json:"profile_file"`
	ProfileFileSHA256       string    `json:"profile_file_sha256"`
	ProfileName             string    `json:"profile_name"`
	ProfileDigest           string    `json:"profile_digest"`
	GuestProfileDigest      string    `json:"guest_profile_digest"`
	GuestPolicy             string    `json:"guest_policy"`
	GuestControlPort        uint32    `json:"guest_control_port"`
	GuestSupervisorPort     uint32    `json:"guest_supervisor_port"`
	GuestManifestSHA256     string    `json:"guest_manifest_sha256"`
	ExpectedGuestGeneration uint64    `json:"expected_guest_generation"`
	LaunchNonce             string    `json:"launch_nonce"`
	CIDLeaseRoot            string    `json:"cid_lease_root"`
	CIDLease                CIDLease  `json:"cid_lease"`
	CreatedAt               time.Time `json:"created_at"`
}

func (r HostMonitorRequest) Validate(stateDir string) error {
	if r.SchemaVersion != HostMonitorSchemaVersion || !validHexSecret(r.MonitorID) {
		return fmt.Errorf("host monitor request schema or identity is invalid")
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
		!validPort(r.GuestControlPort) || !validPort(r.GuestSupervisorPort) || r.GuestControlPort == r.GuestSupervisorPort {
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

type HostMonitorGuestSecret struct {
	SchemaVersion int    `json:"schema_version"`
	MonitorID     string `json:"monitor_id"`
	SessionID     string `json:"session_id"`
	Generation    uint64 `json:"generation"`
	IncarnationID string `json:"incarnation_id"`
	EventToken    string `json:"event_token"`
}

func (s HostMonitorGuestSecret) Validate(request HostMonitorRequest) error {
	if s.SchemaVersion != HostMonitorSchemaVersion || s.MonitorID != request.MonitorID || s.SessionID != request.SessionID ||
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
}

func publicHostGuestIdentity(handshake guestcontrol.Handshake) HostGuestIdentity {
	return HostGuestIdentity{
		ProtocolVersion: handshake.ProtocolVersion, SessionID: handshake.SessionID,
		Generation: handshake.Generation, IncarnationID: handshake.IncarnationID,
		GuestBootID: handshake.GuestBootID,
		Profile:     handshake.Profile, ProfileDigest: handshake.ProfileDigest, Policy: handshake.Policy,
		VSockCID: handshake.VSockCID, VSockPort: handshake.VSockPort, SupervisorPort: handshake.SupervisorPort,
		NetworkReady: handshake.NetworkReady,
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
	RelayClosed           bool                      `json:"relay_closed,omitempty"`
	LastError             string                    `json:"last_error,omitempty"`
}

func (s HostMonitorStatus) Validate() error {
	if s.SchemaVersion != HostMonitorSchemaVersion || s.Revision == 0 || !validHexSecret(s.MonitorID) {
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
		if s.Runner == nil {
			if s.RunnerExit != nil || s.RunnerReaped || !s.RelayClosed {
				return fmt.Errorf("host monitor pre-launch failure evidence is inconsistent")
			}
		} else if s.Runner.Validate(true) != nil || (s.RunnerReaped && s.RunnerExit == nil) {
			return fmt.Errorf("host monitor failed state has inconsistent runner evidence")
		}
	default:
		return fmt.Errorf("host monitor state %q is unsupported", s.State)
	}
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
	if status.SessionID != filepath.Base(stateDir) || status.SessionID != request.SessionID || status.MonitorID != request.MonitorID ||
		status.Profile != request.ProfileName || status.ExternalProfileDigest != request.ProfileDigest || status.GuestProfileDigest != request.GuestProfileDigest {
		return HostMonitorStatus{}, fmt.Errorf("host monitor status is not bound to its immutable request")
	}
	if status.Endpoint != nil && (status.Endpoint.Transport != "unix" || status.Endpoint.Address != layout.RelayPath) {
		return HostMonitorStatus{}, fmt.Errorf("host monitor status endpoint is not the exact host relay")
	}
	if status.Guest != nil && (status.Guest.ProtocolVersion != guestcontrol.ProtocolVersion || status.Guest.SessionID != request.SessionID ||
		status.Guest.Generation != request.ExpectedGuestGeneration ||
		status.Guest.Profile != request.ProfileName || status.Guest.ProfileDigest != request.GuestProfileDigest || status.Guest.Policy != request.GuestPolicy ||
		status.Guest.VSockCID != request.CIDLease.CID || status.Guest.VSockPort != request.GuestControlPort || status.Guest.SupervisorPort != request.GuestSupervisorPort ||
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
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return requireEOF(decoder)
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
