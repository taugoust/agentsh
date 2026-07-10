package detached

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

const ProtocolVersion = 1

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

	NetworkEnforcementTierNone                   = types.NetworkEnforcementTierNone
	NetworkEnforcementTierCgroupDelegated        = types.NetworkEnforcementTierCgroupDelegated
	NetworkEnforcementTierHelperEBPFGate         = types.NetworkEnforcementTierHelperEBPFGate
	NetworkEnforcementTierHelperEBPFProxy         = types.NetworkEnforcementTierHelperEBPFProxy
	NetworkEnforcementTierHelperEBPFProxyRequired = types.NetworkEnforcementTierHelperEBPFProxyRequired
)

type Metadata struct {
	SessionID          string              `json:"session_id"`
	ID                 string              `json:"id,omitempty"`
	CreatedAt          time.Time           `json:"created_at"`
	State              string              `json:"state"`
	Policy             string              `json:"policy"`
	RealWorkspace      string              `json:"real_workspace"`
	WorkspaceMode      string              `json:"workspace_mode"`
	Worktree           string              `json:"worktree"`
	WorkspaceRoots     []WorkspaceRoot     `json:"workspace_roots,omitempty"`
	RuntimeHome        string              `json:"runtime_home,omitempty"`
	RuntimeTmp         string              `json:"runtime_tmp,omitempty"`
	ProcessHome        string              `json:"process_home,omitempty"`
	RuntimeHomeMode    string              `json:"runtime_home_mode,omitempty"`
	EnvBaseMode        string              `json:"env_base_mode,omitempty"`
	EnvInherit         []string            `json:"env_inherit,omitempty"`
	SupervisorSock     string              `json:"supervisor_sock"`
	EventToken         string              `json:"event_token,omitempty"`
	SystemdUnit        string              `json:"systemd_unit,omitempty"`
	OwnerPID           int                 `json:"owner_pid"`
	NetworkEnforcement *NetworkEnforcement `json:"network_enforcement,omitempty"`
	ProtocolVersion    int                 `json:"protocol_version"`
}

type DiscoveryOptions struct {
	RequireSocket bool
	CheckPID      bool
	PIDAlive      func(int) bool
}

func MetadataPath(stateDir string) string {
	return filepath.Join(stateDir, "metadata.json")
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
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	return nil
}

func ReadMetadataFromRoot(root string, sessionID string) (Metadata, string, error) {
	stateDir := filepath.Join(root, sessionID)
	path := MetadataPath(stateDir)
	b, err := os.ReadFile(path)
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
	if meta.NetworkEnforcement != nil {
		meta.NetworkEnforcement.Normalize()
	}
	return meta, stateDir, nil
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
	if strings.TrimSpace(meta.SupervisorSock) == "" {
		return fmt.Errorf("stale metadata for detached session %s: metadata.json has no supervisor_sock", meta.SessionID)
	}
	if _, err := os.Stat(meta.SupervisorSock); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stale metadata for detached session %s: supervisor.sock is missing at %s; stop/remove the stale session or start a new detached session", meta.SessionID, meta.SupervisorSock)
		}
		return fmt.Errorf("stale metadata for detached session %s: cannot stat supervisor.sock at %s: %w", meta.SessionID, meta.SupervisorSock, err)
	}
	if meta.OwnerPID > 0 && pidAlive != nil && !pidAlive(meta.OwnerPID) {
		return fmt.Errorf("dead supervisor for detached session %s: owner_pid %d is not running; stop/remove the stale session or start a new detached session", meta.SessionID, meta.OwnerPID)
	}
	return nil
}
