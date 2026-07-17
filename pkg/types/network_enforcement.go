package types

import (
	"encoding/json"
	"strings"
	"time"
)

// NetworkEnforcementStatus separates configured intent from session readiness
// and per-command attachment evidence.
type NetworkEnforcementStatus string

const (
	NetworkEnforcementStatusNone     NetworkEnforcementStatus = "none"
	NetworkEnforcementStatusDegraded NetworkEnforcementStatus = "degraded"
	NetworkEnforcementStatusReady    NetworkEnforcementStatus = "ready"
	NetworkEnforcementStatusActive   NetworkEnforcementStatus = "active"
	NetworkEnforcementStatusFailed   NetworkEnforcementStatus = "failed"
)

// NetworkEnforcementRequest records the policy's requested runtime guarantee.
type NetworkEnforcementRequest string

const (
	NetworkEnforcementRequestNone       NetworkEnforcementRequest = "none"
	NetworkEnforcementRequestBestEffort NetworkEnforcementRequest = "best-effort"
	NetworkEnforcementRequestStrict     NetworkEnforcementRequest = "strict"
)

// NetworkEnforcementTier names an installed runtime mechanism. The
// proxy-required tier permits only the exact AgentSH proxy endpoint; it does not
// claim transparent redirect compatibility.
type NetworkEnforcementTier string

const (
	NetworkEnforcementTierNone                    NetworkEnforcementTier = "none"
	NetworkEnforcementTierCgroupDelegated         NetworkEnforcementTier = "cgroup-delegated"
	NetworkEnforcementTierHelperEBPFGate          NetworkEnforcementTier = "helper-ebpf-gate"
	NetworkEnforcementTierHelperEBPFProxy         NetworkEnforcementTier = "helper-ebpf-proxy" // legacy degraded label
	NetworkEnforcementTierHelperEBPFProxyRequired NetworkEnforcementTier = "helper-ebpf-proxy-required"
)

// NetworkPreflightEvidence records session-start checks. A ready preflight must
// come from disposable runtime operations; configuration and socket existence
// alone cannot set these fields.
type NetworkPreflightEvidence struct {
	Status                     NetworkEnforcementStatus `json:"status"`
	CommandID                  string                   `json:"command_id,omitempty"`
	CgroupPath                 string                   `json:"cgroup_path,omitempty"`
	CgroupID                   uint64                   `json:"cgroup_id,omitempty"`
	RegistrationID             string                   `json:"registration_id,omitempty"`
	CgroupPlacementProven      bool                     `json:"cgroup_placement_proven"`
	HelperAuthenticated        bool                     `json:"helper_authenticated"`
	HelperAttachProven         bool                     `json:"helper_attach_proven"`
	DefaultDenyMapProven       bool                     `json:"default_deny_map_proven"`
	InitialPolicyLocked        bool                     `json:"initial_policy_locked"`
	PolicyUpdateFailClosed     bool                     `json:"policy_update_fail_closed"`
	HelperCleanupProven        bool                     `json:"helper_cleanup_proven"`
	Pinned                     bool                     `json:"pinned"`
	Reloaded                   bool                     `json:"reloaded"`
	ProxyListenerProven        bool                     `json:"proxy_listener_proven"`
	ProxyConnectProven         bool                     `json:"proxy_connect_proven"`
	ProxyEndpointID            string                   `json:"proxy_endpoint_id,omitempty"`
	ToolBoundaryProven         bool                     `json:"tool_boundary_proven"`
	PrivateProcProven          bool                     `json:"private_proc_proven"`
	CgroupFSHidden             bool                     `json:"cgroupfs_hidden"`
	HelperSocketHidden         bool                     `json:"helper_socket_hidden"`
	CredentialSourceHidden     bool                     `json:"credential_source_hidden"`
	ControlPathsHidden         bool                     `json:"control_paths_hidden"`
	ReservedEnvScrubbed        bool                     `json:"reserved_env_scrubbed"`
	InheritedDescriptorsClosed bool                     `json:"inherited_descriptors_closed"`
	NoNewPrivileges            bool                     `json:"no_new_privs"`
	CapabilitiesDropped        bool                     `json:"capabilities_dropped"`
	DirectBypassProven         bool                     `json:"direct_bypass_proven"`
	LocalDirectTCPBlocked      bool                     `json:"local_direct_tcp_blocked"`
	UDPBlocked                 bool                     `json:"udp_blocked"`
	RawSocketsBlocked          bool                     `json:"raw_sockets_blocked"`
	UnsupportedTrafficProven   bool                     `json:"unsupported_traffic_proven"`
	FailClosedBarrierProven    bool                     `json:"fail_closed_barrier_proven"`
	ChildStoppedDuringSetup    bool                     `json:"child_stopped_during_setup"`
	RefusalLeftChildStopped    bool                     `json:"refusal_left_child_stopped"`
	CheckedAt                  time.Time                `json:"checked_at"`
	Detail                     string                   `json:"detail,omitempty"`
}

// Proven reports whether the session-start preflight established every
// prerequisite for the proxy-required tier.
func (p NetworkPreflightEvidence) Proven() bool {
	return p.Status == NetworkEnforcementStatusReady &&
		!p.CheckedAt.IsZero() &&
		strings.TrimSpace(p.CommandID) != "" &&
		strings.TrimSpace(p.CgroupPath) != "" &&
		p.CgroupID != 0 &&
		strings.TrimSpace(p.RegistrationID) != "" &&
		p.CgroupPlacementProven &&
		p.HelperAuthenticated &&
		p.HelperAttachProven &&
		p.DefaultDenyMapProven &&
		p.InitialPolicyLocked &&
		p.PolicyUpdateFailClosed &&
		p.HelperCleanupProven &&
		p.Pinned &&
		p.ProxyListenerProven &&
		p.ProxyConnectProven &&
		strings.TrimSpace(p.ProxyEndpointID) != "" &&
		p.ToolBoundaryProven &&
		p.PrivateProcProven &&
		p.CgroupFSHidden &&
		p.HelperSocketHidden &&
		p.CredentialSourceHidden &&
		p.ControlPathsHidden &&
		p.ReservedEnvScrubbed &&
		p.InheritedDescriptorsClosed &&
		p.NoNewPrivileges &&
		p.CapabilitiesDropped &&
		p.DirectBypassProven &&
		p.LocalDirectTCPBlocked &&
		p.UDPBlocked &&
		p.RawSocketsBlocked &&
		p.UnsupportedTrafficProven &&
		p.FailClosedBarrierProven &&
		p.ChildStoppedDuringSetup &&
		p.RefusalLeftChildStopped
}

// NetworkAttachmentEvidence describes one command gate after helper
// registration and the default-deny map update have succeeded. It contains no
// helper credential or detached event token.
type NetworkAttachmentEvidence struct {
	Status                    NetworkEnforcementStatus `json:"status"`
	Tier                      NetworkEnforcementTier   `json:"tier"`
	Mode                      string                   `json:"mode,omitempty"`
	CommandID                 string                   `json:"command_id,omitempty"`
	CgroupPath                string                   `json:"cgroup_path,omitempty"`
	CgroupID                  uint64                   `json:"cgroup_id,omitempty"`
	RegistrationID            string                   `json:"registration_id,omitempty"`
	HelperAuthenticated       bool                     `json:"helper_authenticated"`
	ProxyEndpointID           string                   `json:"proxy_endpoint_id,omitempty"`
	ProxyEndpointIDs          []string                 `json:"proxy_endpoint_ids,omitempty"`
	AllowEntries              int                      `json:"allow_entries,omitempty"`
	DenyEntries               int                      `json:"deny_entries,omitempty"`
	DefaultDeny               bool                     `json:"default_deny"`
	InitialPolicyLocked       bool                     `json:"initial_policy_locked"`
	PolicyUpdateFailClosed    bool                     `json:"policy_update_fail_closed"`
	ChildStoppedDuringSetup   bool                     `json:"child_stopped_during_setup"`
	ProxyRequired             bool                     `json:"proxy_required"`
	ExactProxyOnly            bool                     `json:"exact_proxy_endpoint_only"`
	AllowedTransport          string                   `json:"allowed_transport,omitempty"`
	DirectBypassBlocked       bool                     `json:"direct_bypass_blocked"`
	DirectTCPBlocked          bool                     `json:"direct_tcp_blocked"`
	LocalNonProxyTCPBlocked   bool                     `json:"local_non_proxy_tcp_blocked"`
	UDPBlocked                bool                     `json:"udp_blocked"`
	QUICBlocked               bool                     `json:"quic_blocked"`
	CommandDNSRequired        bool                     `json:"command_dns_required"`
	RawSocketBlockConfigured  bool                     `json:"raw_socket_blocking_configured"`
	RawSocketsBlocked         bool                     `json:"raw_sockets_blocked"`
	UnsupportedTrafficAction  string                   `json:"unsupported_traffic_action,omitempty"`
	BlockedTrafficClasses     []string                 `json:"blocked_traffic_classes,omitempty"`
	UnsupportedTrafficBlocked bool                     `json:"unsupported_traffic_blocked"`
	TransparentRedirect       bool                     `json:"transparent_redirect"`
	Pinned                    bool                     `json:"pinned"`
	Reloaded                  bool                     `json:"reloaded"`
	CheckedAt                 time.Time                `json:"checked_at"`
	Detail                    string                   `json:"detail,omitempty"`
}

// Proven reports whether this attachment is evidence for an active,
// crash-persistent, exact-proxy command gate.
func (a NetworkAttachmentEvidence) Proven() bool {
	return a.Status == NetworkEnforcementStatusActive &&
		!a.CheckedAt.IsZero() &&
		a.Tier == NetworkEnforcementTierHelperEBPFProxyRequired &&
		strings.EqualFold(strings.TrimSpace(a.Mode), "cgroup-connect-gate") &&
		strings.TrimSpace(a.CommandID) != "" &&
		strings.TrimSpace(a.CgroupPath) != "" &&
		a.CgroupID != 0 &&
		strings.TrimSpace(a.RegistrationID) != "" &&
		a.HelperAuthenticated &&
		strings.TrimSpace(a.ProxyEndpointID) != "" &&
		a.AllowEntries > 0 &&
		a.DefaultDeny &&
		a.InitialPolicyLocked &&
		a.PolicyUpdateFailClosed &&
		a.ChildStoppedDuringSetup &&
		a.ProxyRequired &&
		a.ExactProxyOnly &&
		strings.EqualFold(strings.TrimSpace(a.AllowedTransport), "tcp") &&
		a.DirectBypassBlocked &&
		a.DirectTCPBlocked &&
		a.LocalNonProxyTCPBlocked &&
		a.UDPBlocked &&
		a.QUICBlocked &&
		!a.CommandDNSRequired &&
		a.RawSocketBlockConfigured &&
		a.RawSocketsBlocked &&
		strings.EqualFold(strings.TrimSpace(a.UnsupportedTrafficAction), "deny") &&
		a.UnsupportedTrafficBlocked &&
		!a.TransparentRedirect &&
		a.Pinned
}

// NethelperLifecycleEvidence is authenticated, non-secret helper health and
// binding identity. Credential values and credential file contents are never
// represented by this schema.
type NethelperRebindRequest struct {
	BootstrapResultPath       string `json:"bootstrap_result_path"`
	SocketPath                string `json:"socket_path"`
	CredentialFile            string `json:"credential_file"`
	ExpectedLeaseID           string `json:"expected_lease_id"`
	ExpectedBindingGeneration uint64 `json:"expected_binding_generation"`
}

type NethelperLifecycleEvidence struct {
	SchemaVersion           int       `json:"schema_version"`
	HelperKind              string    `json:"helper_kind,omitempty"`
	LeaseID                 string    `json:"lease_id,omitempty"`
	UnitName                string    `json:"unit_name,omitempty"`
	ProtocolVersion         int       `json:"protocol_version,omitempty"`
	Capabilities            []string  `json:"capabilities,omitempty"`
	SoftExpiresAt           time.Time `json:"soft_expires_at,omitempty"`
	HardExpiresAt           time.Time `json:"hard_expires_at,omitempty"`
	SoftRemainingSeconds    int64     `json:"soft_remaining_seconds,omitempty"`
	HardRemainingSeconds    int64     `json:"hard_remaining_seconds,omitempty"`
	BindingGeneration       uint64    `json:"binding_generation"`
	RenewalGeneration       uint64    `json:"renewal_generation,omitempty"`
	ActiveRegistrationCount int       `json:"active_registration_count,omitempty"`
	SocketLive              bool      `json:"socket_live"`
	CredentialSourceLive    bool      `json:"credential_source_live"`
	Status                  string    `json:"status"`
	TerminalReason          string    `json:"terminal_reason,omitempty"`
	LastCheckedAt           time.Time `json:"last_checked_at"`
}

// NetworkEnforcement is an evidence report, not a configuration echo.
// Readiness remains session-scoped while Status may temporarily become active
// for a command or failed after a refusal. NetworkPolicyEnforced is defensively
// recomputed while marshaling and can only be true when Proven reports that
// every required prerequisite is present.
type NetworkEnforcement struct {
	Requested                 NetworkEnforcementRequest   `json:"requested"`
	Readiness                 NetworkEnforcementStatus    `json:"readiness"`
	Status                    NetworkEnforcementStatus    `json:"status"`
	Tier                      NetworkEnforcementTier      `json:"tier"`
	NetworkPolicyEnforced     bool                        `json:"network_policy_enforced"`
	CgroupDelegated           bool                        `json:"cgroup_delegated"`
	CgroupMode                string                      `json:"cgroup_mode,omitempty"`
	CgroupRoot                string                      `json:"cgroup_root,omitempty"`
	HelperConfigured          bool                        `json:"helper_configured"`
	HelperAuthenticated       bool                        `json:"helper_authenticated"`
	ToolBoundaryActive        bool                        `json:"tool_boundary_active"`
	ProxyReady                bool                        `json:"proxy_ready"`
	ProxyRequired             bool                        `json:"proxy_required"`
	ExactProxyOnly            bool                        `json:"exact_proxy_endpoint_only"`
	AllowedTransport          string                      `json:"allowed_transport,omitempty"`
	ProxyEndpointID           string                      `json:"proxy_endpoint_id,omitempty"`
	DirectBypassBlocked       bool                        `json:"direct_bypass_blocked"`
	DirectTCPBlocked          bool                        `json:"direct_tcp_blocked"`
	LocalNonProxyTCPBlocked   bool                        `json:"local_non_proxy_tcp_blocked"`
	UDPBlocked                bool                        `json:"udp_blocked"`
	QUICBlocked               bool                        `json:"quic_blocked"`
	CommandDNSRequired        bool                        `json:"command_dns_required"`
	RawSocketBlockConfigured  bool                        `json:"raw_socket_blocking_configured"`
	RawSocketsBlocked         bool                        `json:"raw_sockets_blocked"`
	UnsupportedTrafficAction  string                      `json:"unsupported_traffic_action,omitempty"`
	BlockedTrafficClasses     []string                    `json:"blocked_traffic_classes,omitempty"`
	UnsupportedTrafficBlocked bool                        `json:"unsupported_traffic_blocked"`
	FailClosedSetup           bool                        `json:"fail_closed_setup"`
	TransparentRedirect       bool                        `json:"transparent_redirect"`
	CheckedAt                 time.Time                   `json:"checked_at"`
	Detail                    string                      `json:"detail,omitempty"`
	Warning                   string                      `json:"warning,omitempty"`
	Preflight                 *NetworkPreflightEvidence   `json:"preflight,omitempty"`
	Attachment                *NetworkAttachmentEvidence  `json:"attachment,omitempty"`
	HelperLifecycle           *NethelperLifecycleEvidence `json:"helper_lifecycle,omitempty"`
}

// Proven is the sole condition under which AgentSH may emit
// network_policy_enforced=true.
func (n NetworkEnforcement) Proven() bool {
	if n.CheckedAt.IsZero() || n.Readiness != NetworkEnforcementStatusReady || n.Preflight == nil || !n.Preflight.Proven() {
		return false
	}
	if n.Status != NetworkEnforcementStatusReady {
		if n.Status != NetworkEnforcementStatusActive || n.Attachment == nil || !n.Attachment.Proven() {
			return false
		}
	}
	return n.Tier == NetworkEnforcementTierHelperEBPFProxyRequired &&
		n.CgroupDelegated &&
		strings.TrimSpace(n.CgroupMode) != "" &&
		strings.TrimSpace(n.CgroupRoot) != "" &&
		n.HelperConfigured &&
		n.HelperAuthenticated &&
		n.ToolBoundaryActive &&
		n.ProxyReady &&
		strings.TrimSpace(n.ProxyEndpointID) != "" &&
		strings.TrimSpace(n.Preflight.ProxyEndpointID) == strings.TrimSpace(n.ProxyEndpointID) &&
		n.ProxyRequired &&
		n.ExactProxyOnly &&
		strings.EqualFold(strings.TrimSpace(n.AllowedTransport), "tcp") &&
		n.DirectBypassBlocked &&
		n.DirectTCPBlocked &&
		n.LocalNonProxyTCPBlocked &&
		n.UDPBlocked &&
		n.QUICBlocked &&
		!n.CommandDNSRequired &&
		n.RawSocketBlockConfigured &&
		n.RawSocketsBlocked &&
		strings.EqualFold(strings.TrimSpace(n.UnsupportedTrafficAction), "deny") &&
		n.UnsupportedTrafficBlocked &&
		n.FailClosedSetup &&
		!n.TransparentRedirect
}

// Ready reports whether strict autonomous startup may proceed.
func (n NetworkEnforcement) Ready() bool {
	return n.Status == NetworkEnforcementStatusReady && n.Proven()
}

// Normalize removes unsupported enforcement claims from data loaded from old
// or external metadata.
func (n *NetworkEnforcement) Normalize() {
	if n == nil {
		return
	}
	if n.Requested == "" {
		n.Requested = NetworkEnforcementRequestNone
	}
	if n.Status == "" {
		n.Status = NetworkEnforcementStatusNone
	}
	if n.Readiness == "" {
		switch n.Status {
		case NetworkEnforcementStatusReady:
			n.Readiness = NetworkEnforcementStatusReady
		case NetworkEnforcementStatusFailed:
			n.Readiness = NetworkEnforcementStatusFailed
		case NetworkEnforcementStatusNone:
			n.Readiness = NetworkEnforcementStatusNone
		default:
			n.Readiness = NetworkEnforcementStatusDegraded
		}
	}
	if n.Tier == "" {
		n.Tier = NetworkEnforcementTierNone
	}
	if n.Preflight != nil && n.Preflight.Status == "" {
		n.Preflight.Status = NetworkEnforcementStatusDegraded
	}
	if n.Attachment != nil && n.Attachment.Status == "" {
		n.Attachment.Status = n.Status
	}
	n.NetworkPolicyEnforced = n.Proven()
	if !n.NetworkPolicyEnforced && strings.TrimSpace(n.Warning) == "" && n.Requested != NetworkEnforcementRequestNone {
		n.Warning = "runtime network enforcement is not proven; policy decisions do not imply that traffic was blocked"
	}
}

// MarshalJSON guarantees that stale callers cannot serialize an unproven true
// network_policy_enforced value.
func (n NetworkEnforcement) MarshalJSON() ([]byte, error) {
	n.Normalize()
	type wire NetworkEnforcement
	return json.Marshal(wire(n))
}
