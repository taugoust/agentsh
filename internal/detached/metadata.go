package detached

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

const ProtocolVersion = 2

const (
	// EnvNetworkEnforcementRequested carries launcher intent into the detached
	// supervisor after configureSupervisorMVP disables unsupported best-effort
	// features. It is not evidence of readiness.
	EnvNetworkEnforcementRequested = "AGENTSH_DETACHED_NETWORK_ENFORCEMENT_REQUESTED"
	// EnvSupervisorLaunchMode is diagnostic context only. Cgroup readiness is
	// still derived from the runtime cgroup probe rather than this value.
	EnvSupervisorLaunchMode = "AGENTSH_DETACHED_SUPERVISOR_LAUNCH_MODE"
)

var ErrMetadataInvalid = errors.New("invalid detached supervisor metadata")

type WorkspaceRoot struct {
	Name string `json:"name"`
	Real string `json:"real"`
	Work string `json:"work"`
}

type NetworkEnforcementStatus = types.NetworkEnforcementStatus

type NetworkEnforcementRequest = types.NetworkEnforcementRequest

type NetworkEnforcementTier = types.NetworkEnforcementTier

type NetworkPreflightEvidence = types.NetworkPreflightEvidence

type NetworkAttachmentEvidence = types.NetworkAttachmentEvidence

type NetworkEnforcement = types.NetworkEnforcement

const (
	NetworkEnforcementStatusNone     = types.NetworkEnforcementStatusNone
	NetworkEnforcementStatusDegraded = types.NetworkEnforcementStatusDegraded
	NetworkEnforcementStatusReady    = types.NetworkEnforcementStatusReady
	NetworkEnforcementStatusActive   = types.NetworkEnforcementStatusActive
	NetworkEnforcementStatusFailed   = types.NetworkEnforcementStatusFailed

	NetworkEnforcementRequestNone       = types.NetworkEnforcementRequestNone
	NetworkEnforcementRequestBestEffort = types.NetworkEnforcementRequestBestEffort
	NetworkEnforcementRequestStrict     = types.NetworkEnforcementRequestStrict

	NetworkEnforcementTierNone                    = types.NetworkEnforcementTierNone
	NetworkEnforcementTierCgroupDelegated         = types.NetworkEnforcementTierCgroupDelegated
	NetworkEnforcementTierHelperEBPFGate          = types.NetworkEnforcementTierHelperEBPFGate
	NetworkEnforcementTierHelperEBPFProxy         = types.NetworkEnforcementTierHelperEBPFProxy
	NetworkEnforcementTierHelperEBPFProxyRequired = types.NetworkEnforcementTierHelperEBPFProxyRequired
)

type Metadata struct {
	SessionID            string              `json:"session_id"`
	ID                   string              `json:"id,omitempty"`
	CreatedAt            time.Time           `json:"created_at"`
	State                string              `json:"state"`
	Policy               string              `json:"policy"`
	RealWorkspace        string              `json:"real_workspace"`
	WorkspaceMode        string              `json:"workspace_mode"`
	Worktree             string              `json:"worktree"`
	WorkspaceRoots       []WorkspaceRoot     `json:"workspace_roots,omitempty"`
	RuntimeHome          string              `json:"runtime_home,omitempty"`
	RuntimeTmp           string              `json:"runtime_tmp,omitempty"`
	ProcessHome          string              `json:"process_home,omitempty"`
	RuntimeHomeMode      string              `json:"runtime_home_mode,omitempty"`
	EnvBaseMode          string              `json:"env_base_mode,omitempty"`
	EnvInherit           []string            `json:"env_inherit,omitempty"`
	SupervisorSock       string              `json:"supervisor_sock"`
	EventToken           string              `json:"event_token,omitempty"`
	SystemdUnit          string              `json:"systemd_unit,omitempty"`
	OwnerPID             int                 `json:"owner_pid"`
	OwnerStartIdentity   string              `json:"owner_start_identity,omitempty"`
	BootID               string              `json:"boot_id,omitempty"`
	Generation           uint64              `json:"generation,omitempty"`
	IncarnationID        string              `json:"incarnation_id,omitempty"`
	IncarnationStartedAt time.Time           `json:"incarnation_started_at,omitzero"`
	HeartbeatAt          time.Time           `json:"heartbeat_at,omitzero"`
	LastError            string              `json:"last_error,omitempty"`
	NetworkEnforcement   *NetworkEnforcement `json:"network_enforcement,omitempty"`
	ProtocolVersion      int                 `json:"protocol_version"`
}

type DiscoveryOptions struct {
	RequireSocket bool
	CheckPID      bool
	PIDAlive      func(int) bool
}

func MetadataPath(stateDir string) string {
	return filepath.Join(stateDir, "metadata.json")
}

func HeartbeatPath(stateDir string) string {
	return filepath.Join(stateDir, "heartbeat.json")
}

type heartbeatRecord struct {
	ProtocolVersion int       `json:"protocol_version"`
	SessionID       string    `json:"session_id"`
	Generation      uint64    `json:"generation"`
	IncarnationID   string    `json:"incarnation_id"`
	HeartbeatAt     time.Time `json:"heartbeat_at"`
}

func WriteHeartbeat(stateDir string, meta Metadata) error {
	if meta.ProtocolVersion < ProtocolVersion || strings.TrimSpace(meta.SessionID) == "" || meta.Generation == 0 || strings.TrimSpace(meta.IncarnationID) == "" || meta.HeartbeatAt.IsZero() {
		return fmt.Errorf("write heartbeat: incomplete detached incarnation identity")
	}
	record := heartbeatRecord{
		ProtocolVersion: meta.ProtocolVersion,
		SessionID:       meta.SessionID,
		Generation:      meta.Generation,
		IncarnationID:   meta.IncarnationID,
		HeartbeatAt:     meta.HeartbeatAt.UTC(),
	}
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode heartbeat: %w", err)
	}
	// Heartbeat freshness is advisory. Atomic replacement prevents readers from
	// accepting partial content, while deliberately omitting fsync avoids turning
	// every liveness tick into a durable metadata transaction.
	if err := atomicWritePrivateFileWithDurability(HeartbeatPath(stateDir), append(data, '\n'), false); err != nil {
		return fmt.Errorf("write heartbeat: %w", err)
	}
	return nil
}

func RemoveHeartbeat(stateDir string) error {
	err := os.Remove(HeartbeatPath(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func WriteMetadata(stateDir string, meta Metadata) error {
	if meta.NetworkEnforcement != nil {
		network := *meta.NetworkEnforcement
		network.Normalize()
		meta.NetworkEnforcement = &network
	}
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	path := MetadataPath(stateDir)
	if err := atomicWritePrivateFile(path, append(b, '\n')); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	return nil
}

func atomicWritePrivateFile(path string, data []byte) error {
	return atomicWritePrivateFileWithDurability(path, data, true)
}

func atomicWritePrivateFileWithDurability(path string, data []byte, durable bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if durable {
		if err := tmp.Sync(); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	if durable {
		if dirHandle, err := os.Open(dir); err == nil {
			_ = dirHandle.Sync()
			_ = dirHandle.Close()
		}
	}
	return nil
}

func ReadMetadataFromRoot(root string, sessionID string) (Metadata, string, error) {
	if sessionID == "" || sessionID == "." || sessionID == ".." || strings.ContainsAny(sessionID, `/\\`) || filepath.Base(sessionID) != sessionID {
		return Metadata{}, "", fmt.Errorf("%w: invalid detached session path identity", ErrMetadataInvalid)
	}
	stateDir := filepath.Join(root, sessionID)
	path := MetadataPath(stateDir)
	b, err := readProtectedRegularFile(path, 4<<20)
	if err != nil {
		return Metadata{}, stateDir, fmt.Errorf("read detached supervisor metadata for %s at %s: %w", sessionID, path, err)
	}
	var meta Metadata
	if err := json.Unmarshal(b, &meta); err != nil {
		return Metadata{}, stateDir, fmt.Errorf("%w for %s at %s: %v", ErrMetadataInvalid, sessionID, path, err)
	}
	if meta.SessionID == "" {
		return Metadata{}, stateDir, fmt.Errorf("%w for %s at %s: missing session_id", ErrMetadataInvalid, sessionID, path)
	}
	if meta.SessionID != sessionID || (meta.ID != "" && meta.ID != sessionID) {
		return Metadata{}, stateDir, fmt.Errorf("%w for %s at %s: path and metadata identities differ", ErrMetadataInvalid, sessionID, path)
	}
	if meta.NetworkEnforcement != nil {
		meta.NetworkEnforcement.Normalize()
	}
	if heartbeat, err := readHeartbeat(stateDir); err == nil &&
		heartbeat.ProtocolVersion == meta.ProtocolVersion && heartbeat.SessionID == meta.SessionID &&
		heartbeat.Generation == meta.Generation && heartbeat.IncarnationID == meta.IncarnationID &&
		heartbeat.HeartbeatAt.After(meta.HeartbeatAt) {
		meta.HeartbeatAt = heartbeat.HeartbeatAt
	}
	return meta, stateDir, nil
}

func readHeartbeat(stateDir string) (heartbeatRecord, error) {
	data, err := readProtectedRegularFile(HeartbeatPath(stateDir), 16<<10)
	if err != nil {
		return heartbeatRecord{}, err
	}
	var heartbeat heartbeatRecord
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&heartbeat); err != nil {
		return heartbeatRecord{}, err
	}
	if heartbeat.ProtocolVersion < ProtocolVersion || strings.TrimSpace(heartbeat.SessionID) == "" || heartbeat.Generation == 0 || strings.TrimSpace(heartbeat.IncarnationID) == "" || heartbeat.HeartbeatAt.IsZero() {
		return heartbeatRecord{}, fmt.Errorf("invalid detached heartbeat")
	}
	heartbeat.HeartbeatAt = heartbeat.HeartbeatAt.UTC()
	return heartbeat, nil
}

func readProtectedRegularFile(path string, maxBytes int64) ([]byte, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("protected file has unsafe type or permissions")
	}
	if pathInfo.Size() < 0 || pathInfo.Size() > maxBytes {
		return nil, fmt.Errorf("protected file exceeds %d bytes", maxBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return nil, fmt.Errorf("protected file identity changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("protected file exceeds %d bytes", maxBytes)
	}
	return data, nil
}

func ListMetadataFromRoot(root string, opts DiscoveryOptions) ([]Metadata, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("discover detached supervisors under %s: %w", root, err)
	}
	var out []Metadata
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		meta, _, err := ReadMetadataFromRoot(root, ent.Name())
		if err != nil {
			continue
		}
		if opts.RequireSocket && strings.TrimSpace(meta.SupervisorSock) == "" {
			continue
		}
		if opts.RequireSocket {
			if _, err := os.Stat(meta.SupervisorSock); err != nil {
				continue
			}
		}
		if opts.CheckPID && meta.OwnerPID > 0 && opts.PIDAlive != nil && !opts.PIDAlive(meta.OwnerPID) {
			continue
		}
		out = append(out, meta)
	}
	return out, nil
}

// StaleNetworkEnforcementSnapshot returns a startup metadata object that is
// safe to show when the live supervisor API could not be queried. Startup
// evidence is historical: it can explain the last observed tier but can never
// preserve ready/active or network_policy_enforced=true.
func StaleNetworkEnforcementSnapshot(report *NetworkEnforcement) *NetworkEnforcement {
	if report == nil {
		return nil
	}
	snapshot := *report
	snapshot.BlockedTrafficClasses = append([]string(nil), report.BlockedTrafficClasses...)
	if report.Attachment != nil {
		attachment := *report.Attachment
		attachment.ProxyEndpointIDs = append([]string(nil), report.Attachment.ProxyEndpointIDs...)
		attachment.BlockedTrafficClasses = append([]string(nil), report.Attachment.BlockedTrafficClasses...)
		snapshot.Attachment = &attachment
	}
	if report.Preflight != nil {
		preflight := *report.Preflight
		snapshot.Preflight = &preflight
	}
	switch snapshot.Status {
	case NetworkEnforcementStatusFailed:
		snapshot.Readiness = NetworkEnforcementStatusFailed
	case NetworkEnforcementStatusNone:
		snapshot.Readiness = NetworkEnforcementStatusNone
	default:
		snapshot.Status = NetworkEnforcementStatusDegraded
		snapshot.Readiness = NetworkEnforcementStatusDegraded
	}
	snapshot.NetworkPolicyEnforced = false
	snapshot.Warning = "detached metadata is a stale startup snapshot; live supervisor runtime evidence is unavailable"
	snapshot.Normalize()
	return &snapshot
}

func ValidateUsable(meta Metadata, pidAlive func(int) bool) error {
	if meta.ProtocolVersion >= 2 {
		switch meta.State {
		case LifecycleReady, LifecycleDegraded, LifecycleRecovering:
		case LifecycleProvisioning:
			return fmt.Errorf("detached session %s is still provisioning", meta.SessionID)
		case LifecycleFinalizing, LifecycleStopping, LifecycleStopped, LifecycleFinalized:
			return fmt.Errorf("detached session %s is %s", meta.SessionID, meta.State)
		case LifecycleFailed:
			return fmt.Errorf("detached session %s supervisor failed: %s", meta.SessionID, meta.LastError)
		default:
			return fmt.Errorf("stale metadata for detached session %s: unknown lifecycle state %q", meta.SessionID, meta.State)
		}
		if meta.Generation == 0 || strings.TrimSpace(meta.IncarnationID) == "" {
			return fmt.Errorf("stale metadata for detached session %s: incomplete incarnation identity", meta.SessionID)
		}
	}
	if strings.TrimSpace(meta.SupervisorSock) == "" {
		return fmt.Errorf("stale metadata for detached session %s: metadata.json has no supervisor_sock", meta.SessionID)
	}
	socketInfo, socketErr := os.Lstat(meta.SupervisorSock)
	if socketErr != nil {
		if errors.Is(socketErr, os.ErrNotExist) {
			return fmt.Errorf("stale metadata for detached session %s: supervisor.sock is missing at %s; stop/remove the stale session or start a new detached session", meta.SessionID, meta.SupervisorSock)
		}
		return fmt.Errorf("stale metadata for detached session %s: cannot stat supervisor.sock at %s: %w", meta.SessionID, meta.SupervisorSock, socketErr)
	}
	if meta.ProtocolVersion >= 2 && (socketInfo.Mode()&os.ModeSocket == 0 || socketInfo.Mode()&os.ModeSymlink != 0) {
		return fmt.Errorf("stale metadata for detached session %s: supervisor path is not a direct Unix socket", meta.SessionID)
	}
	if meta.OwnerPID > 0 && pidAlive != nil && !pidAlive(meta.OwnerPID) {
		return fmt.Errorf("dead supervisor for detached session %s: owner_pid %d is not running; recover or stop the exact stale session", meta.SessionID, meta.OwnerPID)
	}
	if meta.OwnerPID > 0 && meta.OwnerStartIdentity != "" && meta.BootID != "" && !ProcessIdentityMatches(meta.OwnerPID, meta.OwnerStartIdentity, meta.BootID) {
		return fmt.Errorf("stale supervisor identity for detached session %s: owner_pid %d was reused or belongs to another boot", meta.SessionID, meta.OwnerPID)
	}
	return nil
}
