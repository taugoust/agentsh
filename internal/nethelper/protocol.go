// Package nethelper defines the JSON wire types and narrow control plane for
// AgentSH's privileged network-enforcement helper.
//
// The protocol performs strict validation and accepts no file descriptors. The
// Linux helper backend derives all kernel objects from AgentSH's built-in eBPF
// assets. In particular, clients may select only one of the BuiltinMode
// constants below; requests must never carry arbitrary BPF bytecode, BPF object
// paths, program FDs, map FDs, link FDs, or tool-provided file descriptors.
package nethelper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"
	"unicode"
)

const CurrentProtocolVersion = 1

const (
	maxIdentifierBytes  = 96
	maxPolicyMapEntries = 1024
)

// EnforcementTier records the externally visible network-enforcement level for
// a session. These values are intentionally stable JSON strings so detached
// metadata, policy-test output, and the future helper RPC can report the same
// tier without translation.
type EnforcementTier string

const (
	EnforcementTierNone                    EnforcementTier = "none"
	EnforcementTierCgroupDelegated         EnforcementTier = "cgroup-delegated"
	EnforcementTierHelperEBPFGate          EnforcementTier = "helper-ebpf-gate"
	EnforcementTierHelperEBPFProxy         EnforcementTier = "helper-ebpf-proxy" // legacy degraded label
	EnforcementTierHelperEBPFProxyRequired EnforcementTier = "helper-ebpf-proxy-required"
)

// Valid reports whether t is a known tier. The empty value is accepted as an
// omitted/default field and normalizes to EnforcementTierNone.
func (t EnforcementTier) Valid() bool {
	switch t {
	case "", EnforcementTierNone, EnforcementTierCgroupDelegated, EnforcementTierHelperEBPFGate, EnforcementTierHelperEBPFProxy, EnforcementTierHelperEBPFProxyRequired:
		return true
	default:
		return false
	}
}

// Normalized returns the effective tier for omitted/default values.
func (t EnforcementTier) Normalized() EnforcementTier {
	if t == "" {
		return EnforcementTierNone
	}
	return t
}

// BuiltinMode selects one of AgentSH's fixed network-enforcement programs.
//
// Safety invariant: this enum is the only way an unprivileged supervisor may
// request helper behavior. The protocol deliberately has no fields for BPF
// bytecode, BPF object paths, or fd passing from Pi/tools.
type BuiltinMode string

const (
	// BuiltinModeCgroupConnectGate is the fixed cgroup sockaddr BPF gate that
	// updates allow/deny/default-deny maps for a session cgroup.
	BuiltinModeCgroupConnectGate BuiltinMode = "cgroup-connect-gate"

	// BuiltinModeCgroupProxyRedirect is the future fixed cgroup BPF/proxy mode
	// used for approval-capable hostname/SNI policy. It may only target a local
	// AgentSH proxy endpoint supplied by the supervisor. The current embedded BPF
	// object does not implement transparent redirect, so production backends must
	// fail closed for this mode instead of degrading to direct allow.
	BuiltinModeCgroupProxyRedirect BuiltinMode = "cgroup-proxy-redirect"
)

// Valid reports whether m is a known built-in mode. The empty value is accepted
// for backwards-compatible JSON and normalizes to BuiltinModeCgroupConnectGate.
func (m BuiltinMode) Valid() bool {
	switch m {
	case "", BuiltinModeCgroupConnectGate, BuiltinModeCgroupProxyRedirect:
		return true
	default:
		return false
	}
}

// Normalized returns the effective mode for omitted/default values.
func (m BuiltinMode) Normalized() BuiltinMode {
	if m == "" {
		return BuiltinModeCgroupConnectGate
	}
	return m
}

// TransportProtocol is the map-entry protocol selector. Empty and "any" both
// mean any protocol for backwards-compatible omitted JSON fields.
type TransportProtocol string

const (
	TransportProtocolAny TransportProtocol = "any"
	TransportProtocolTCP TransportProtocol = "tcp"
	TransportProtocolUDP TransportProtocol = "udp"
)

// Valid reports whether p is a supported transport selector.
func (p TransportProtocol) Valid() bool {
	switch p {
	case "", TransportProtocolAny, TransportProtocolTCP, TransportProtocolUDP:
		return true
	default:
		return false
	}
}

// Normalized returns the effective protocol for omitted/default values.
func (p TransportProtocol) Normalized() TransportProtocol {
	if p == "" {
		return TransportProtocolAny
	}
	return p
}

// IPFamily optionally pins an endpoint to IPv4 or IPv6. If omitted, validation
// infers the family from IP/CIDR fields.
type IPFamily string

const (
	IPFamilyIPv4 IPFamily = "ipv4"
	IPFamilyIPv6 IPFamily = "ipv6"
)

// Valid reports whether f is empty or one of the supported address families.
func (f IPFamily) Valid() bool {
	switch f {
	case "", IPFamilyIPv4, IPFamilyIPv6:
		return true
	default:
		return false
	}
}

// CleanupReason describes why a session's helper-owned resources should be
// removed. Unknown non-empty values are rejected so cleanup requests remain
// auditable and deterministic.
type CleanupReason string

const (
	CleanupReasonSessionEnded       CleanupReason = "session-ended"
	CleanupReasonSupervisorExit     CleanupReason = "supervisor-exit"
	CleanupReasonRegistrationFailed CleanupReason = "registration-failed"
	CleanupReasonPolicyReset        CleanupReason = "policy-reset"
	CleanupReasonOrphanReaped       CleanupReason = "orphan-reaped"
)

// Valid reports whether r is empty or a known cleanup reason.
func (r CleanupReason) Valid() bool {
	switch r {
	case "", CleanupReasonSessionEnded, CleanupReasonSupervisorExit, CleanupReasonRegistrationFailed, CleanupReasonPolicyReset, CleanupReasonOrphanReaped:
		return true
	default:
		return false
	}
}

// ProxyEndpoint identifies one exact local AgentSH userspace proxy listener.
// Host must be an IP literal: the privileged helper never resolves names and
// never accepts a proxy socket fd from a client.
type ProxyEndpoint struct {
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
}

// AddrPort returns the canonical exact loopback endpoint.
func (p ProxyEndpoint) AddrPort() (netip.AddrPort, error) {
	host := strings.TrimSpace(p.Host)
	if host == "" {
		return netip.AddrPort{}, fmt.Errorf("proxy.host is required")
	}
	if p.Port <= 0 || p.Port > 65535 {
		return netip.AddrPort{}, fmt.Errorf("proxy.port must be between 1 and 65535")
	}
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("proxy.host must be an exact IP address: %w", err)
	}
	if addr.Zone() != "" {
		return netip.AddrPort{}, fmt.Errorf("proxy.host must not contain an IPv6 zone")
	}
	addr = addr.Unmap()
	if !addr.IsLoopback() {
		return netip.AddrPort{}, fmt.Errorf("proxy.host must be loopback")
	}
	return netip.AddrPortFrom(addr, uint16(p.Port)), nil
}

// Validate rejects missing, non-literal, non-loopback, and invalid endpoints.
func (p ProxyEndpoint) Validate() error {
	_, err := p.AddrPort()
	return err
}

// PolicyMapEntry is one exact IP or CIDR entry for the helper-owned allow/deny
// maps. Hostnames are deliberately absent: DNS/SNI/approval semantics belong in
// the supervisor/proxy layer, not in privileged map updates.
type PolicyMapEntry struct {
	IP       string            `json:"ip,omitempty"`
	CIDR     string            `json:"cidr,omitempty"`
	Protocol TransportProtocol `json:"protocol,omitempty"`
	Port     int               `json:"port,omitempty"`
	Family   IPFamily          `json:"family,omitempty"`
}

// Validate rejects ambiguous, malformed, or unsupported map entries.
func (e PolicyMapEntry) Validate() error {
	if !e.Protocol.Valid() {
		return fmt.Errorf("invalid protocol %q", e.Protocol)
	}
	if e.Port < 0 || e.Port > 65535 {
		return fmt.Errorf("port must be between 0 and 65535")
	}
	if !e.Family.Valid() {
		return fmt.Errorf("invalid family %q", e.Family)
	}

	ip := strings.TrimSpace(e.IP)
	cidr := strings.TrimSpace(e.CIDR)
	if (ip == "") == (cidr == "") {
		return fmt.Errorf("exactly one of ip or cidr is required")
	}
	if ip != "" {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return fmt.Errorf("invalid ip %q: %w", ip, err)
		}
		if addr.IsUnspecified() {
			return fmt.Errorf("ip must not be unspecified")
		}
		if err := validateFamilyMatchesAddr(e.Family, addr); err != nil {
			return err
		}
		return nil
	}

	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("invalid cidr %q: %w", cidr, err)
	}
	if err := validateFamilyMatchesAddr(e.Family, prefix.Addr()); err != nil {
		return err
	}
	return nil
}

// RegisterSessionCgroupRequest asks the helper to attach AgentSH's built-in
// network enforcement to one session cgroup. It carries only identifiers and
// mode selectors; the helper must verify peer credentials, nonce/cgroup
// ownership, and subtree containment before acting.
type RegisterSessionCgroupRequest struct {
	ProtocolVersion int    `json:"protocol_version,omitempty"`
	RequestID       string `json:"request_id,omitempty"`
	SessionID       string `json:"session_id"`
	// HelperInstanceCredential authenticates the configured per-user helper
	// instance. It is deliberately unrelated to detached-session event tokens.
	HelperInstanceCredential string `json:"helper_instance_credential,omitempty"`
	// SessionNonce is the legacy wire spelling retained for protocol
	// compatibility. New clients must use HelperInstanceCredential; the helper
	// treats this only as an alias for its instance credential, never as an
	// event-token credential.
	SessionNonce  string `json:"session_nonce,omitempty"`
	SupervisorPID int    `json:"supervisor_pid,omitempty"`
	// SupervisorCgroupPath is the delegated cgroup subtree root for the
	// supervisor. The supervisor process may live directly in this cgroup or in
	// its fixed agentsh.leaf child when cgroup probing had to leaf-move it.
	SupervisorCgroupPath string          `json:"supervisor_cgroup_path,omitempty"`
	CgroupPath           string          `json:"cgroup_path"`
	Tier                 EnforcementTier `json:"tier,omitempty"`
	Mode                 BuiltinMode     `json:"mode,omitempty"`
	Proxy                *ProxyEndpoint  `json:"proxy,omitempty"`
	// PinPath is retained only so version-1 peers receive an explicit rejection
	// instead of an unknown-field error. Pin paths are always helper-selected.
	PinPath string `json:"pin_path,omitempty"`
}

// Validate rejects malformed or unsafe registration requests.
func (r RegisterSessionCgroupRequest) Validate() error {
	if err := validateProtocolVersion(r.ProtocolVersion); err != nil {
		return err
	}
	if err := validateID("session_id", r.SessionID); err != nil {
		return err
	}
	if r.RequestID != "" {
		if err := validateID("request_id", r.RequestID); err != nil {
			return err
		}
	}
	if r.SupervisorPID < 0 {
		return fmt.Errorf("supervisor_pid must not be negative")
	}
	if strings.TrimSpace(r.HelperInstanceCredential) != "" && strings.TrimSpace(r.SessionNonce) != "" {
		return fmt.Errorf("helper_instance_credential and legacy session_nonce must not both be set")
	}
	if err := validateWireCredential("helper_instance_credential", r.HelperInstanceCredential); err != nil {
		return err
	}
	if err := validateWireCredential("session_nonce", r.SessionNonce); err != nil {
		return err
	}
	if err := validateCgroupPath("cgroup_path", r.CgroupPath, true); err != nil {
		return err
	}
	if err := validateCgroupPath("supervisor_cgroup_path", r.SupervisorCgroupPath, false); err != nil {
		return err
	}
	if strings.TrimSpace(r.PinPath) != "" {
		return fmt.Errorf("pin_path is helper-selected and must not be supplied by clients")
	}
	if !r.Tier.Valid() {
		return fmt.Errorf("invalid tier %q", r.Tier)
	}
	if !r.Mode.Valid() {
		return fmt.Errorf("invalid mode %q", r.Mode)
	}
	mode := r.Mode.Normalized()
	if (r.Tier.Normalized() == EnforcementTierHelperEBPFProxy || r.Tier.Normalized() == EnforcementTierHelperEBPFProxyRequired) && r.Proxy == nil {
		return fmt.Errorf("tier %q requires proxy metadata", r.Tier.Normalized())
	}
	if mode == BuiltinModeCgroupProxyRedirect && r.Proxy == nil {
		return fmt.Errorf("proxy is required for mode %q", mode)
	}
	if r.Proxy != nil {
		if err := r.Proxy.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// RegisterSessionCgroupResponse reports the helper's registration result.
type RegisterSessionCgroupResponse struct {
	ProtocolVersion       int             `json:"protocol_version,omitempty"`
	RequestID             string          `json:"request_id,omitempty"`
	SessionID             string          `json:"session_id,omitempty"`
	OK                    bool            `json:"ok"`
	Tier                  EnforcementTier `json:"tier,omitempty"`
	Mode                  BuiltinMode     `json:"mode,omitempty"`
	CgroupID              uint64          `json:"cgroup_id,omitempty"`
	NetworkPolicyEnforced bool            `json:"network_policy_enforced,omitempty"`
	// RegistrationID is an opaque helper-selected handle. The Client carries it
	// into update/cleanup requests automatically for version-1 callers.
	RegistrationID string   `json:"registration_id,omitempty"`
	PinPath        string   `json:"pin_path,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
	Error          string   `json:"error,omitempty"`
}

// UpdatePolicyMapRequest asks the helper to replace the session's allow/deny
// entries. The entries are declarative data only; the helper owns map fds and
// must not accept them from the supervisor or tools.
type UpdatePolicyMapRequest struct {
	ProtocolVersion int              `json:"protocol_version,omitempty"`
	RequestID       string           `json:"request_id,omitempty"`
	SessionID       string           `json:"session_id"`
	RegistrationID  string           `json:"registration_id,omitempty"`
	CgroupID        uint64           `json:"cgroup_id,omitempty"`
	CgroupPath      string           `json:"cgroup_path,omitempty"`
	Mode            BuiltinMode      `json:"mode,omitempty"`
	DefaultDeny     bool             `json:"default_deny"`
	Allow           []PolicyMapEntry `json:"allow,omitempty"`
	Deny            []PolicyMapEntry `json:"deny,omitempty"`
	Proxy           *ProxyEndpoint   `json:"proxy,omitempty"`
}

// Validate rejects malformed or unsafe map-update requests.
func (r UpdatePolicyMapRequest) Validate() error {
	if err := validateProtocolVersion(r.ProtocolVersion); err != nil {
		return err
	}
	if err := validateID("session_id", r.SessionID); err != nil {
		return err
	}
	if r.RequestID != "" {
		if err := validateID("request_id", r.RequestID); err != nil {
			return err
		}
	}
	if r.RegistrationID != "" {
		if err := validateID("registration_id", r.RegistrationID); err != nil {
			return err
		}
	}
	if r.CgroupID == 0 && strings.TrimSpace(r.CgroupPath) == "" {
		return fmt.Errorf("one of cgroup_id or cgroup_path is required")
	}
	if err := validateCgroupPath("cgroup_path", r.CgroupPath, false); err != nil {
		return err
	}
	if !r.Mode.Valid() {
		return fmt.Errorf("invalid mode %q", r.Mode)
	}
	mode := r.Mode.Normalized()
	if mode == BuiltinModeCgroupProxyRedirect && r.Proxy == nil {
		return fmt.Errorf("proxy is required for mode %q", mode)
	}
	if r.Proxy != nil {
		if err := r.Proxy.Validate(); err != nil {
			return err
		}
	}
	if len(r.Allow) > maxPolicyMapEntries {
		return fmt.Errorf("allow contains %d entries, maximum is %d", len(r.Allow), maxPolicyMapEntries)
	}
	if len(r.Deny) > maxPolicyMapEntries {
		return fmt.Errorf("deny contains %d entries, maximum is %d", len(r.Deny), maxPolicyMapEntries)
	}
	for i, entry := range r.Allow {
		if err := entry.Validate(); err != nil {
			return fmt.Errorf("allow[%d]: %w", i, err)
		}
	}
	for i, entry := range r.Deny {
		if err := entry.Validate(); err != nil {
			return fmt.Errorf("deny[%d]: %w", i, err)
		}
	}
	return nil
}

// UpdatePolicyMapResponse reports the helper's map-update result.
type UpdatePolicyMapResponse struct {
	ProtocolVersion int      `json:"protocol_version,omitempty"`
	RequestID       string   `json:"request_id,omitempty"`
	SessionID       string   `json:"session_id,omitempty"`
	OK              bool     `json:"ok"`
	DefaultDeny     bool     `json:"default_deny,omitempty"`
	AllowEntries    int      `json:"allow_entries,omitempty"`
	DenyEntries     int      `json:"deny_entries,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
	Error           string   `json:"error,omitempty"`
}

// CleanupSessionRequest asks the helper to remove helper-owned resources for a
// session. Cleanup names resources by session/cgroup only; it never transfers
// link/map fds back to the caller.
type CleanupSessionRequest struct {
	ProtocolVersion int           `json:"protocol_version,omitempty"`
	RequestID       string        `json:"request_id,omitempty"`
	SessionID       string        `json:"session_id"`
	RegistrationID  string        `json:"registration_id,omitempty"`
	CgroupID        uint64        `json:"cgroup_id,omitempty"`
	CgroupPath      string        `json:"cgroup_path,omitempty"`
	PinPath         string        `json:"pin_path,omitempty"`
	Reason          CleanupReason `json:"reason,omitempty"`
}

// Validate rejects malformed cleanup requests.
func (r CleanupSessionRequest) Validate() error {
	if err := validateProtocolVersion(r.ProtocolVersion); err != nil {
		return err
	}
	if err := validateID("session_id", r.SessionID); err != nil {
		return err
	}
	if r.RequestID != "" {
		if err := validateID("request_id", r.RequestID); err != nil {
			return err
		}
	}
	if r.RegistrationID != "" {
		if err := validateID("registration_id", r.RegistrationID); err != nil {
			return err
		}
	}
	if err := validateCgroupPath("cgroup_path", r.CgroupPath, false); err != nil {
		return err
	}
	if strings.TrimSpace(r.PinPath) != "" {
		return fmt.Errorf("pin_path is helper-selected and must not be supplied by clients")
	}
	if !r.Reason.Valid() {
		return fmt.Errorf("invalid reason %q", r.Reason)
	}
	return nil
}

// CleanupSessionResponse reports the helper's cleanup result.
type CleanupSessionResponse struct {
	ProtocolVersion int      `json:"protocol_version,omitempty"`
	RequestID       string   `json:"request_id,omitempty"`
	SessionID       string   `json:"session_id,omitempty"`
	OK              bool     `json:"ok"`
	RemovedPins     []string `json:"removed_pins,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
	Error           string   `json:"error,omitempty"`
}

// ReleaseInstanceRequest asks an ephemeral helper to stop after all registered
// command cgroups have been cleaned. It is a fixed lifecycle operation: it
// cannot name pins, units, processes, or arbitrary cleanup targets.
type InstanceStatusRequest struct {
	ProtocolVersion          int    `json:"protocol_version,omitempty"`
	RequestID                string `json:"request_id,omitempty"`
	LeaseID                  string `json:"lease_id"`
	HelperInstanceCredential string `json:"helper_instance_credential"`
}

func (r InstanceStatusRequest) Validate() error {
	return validateInstanceLifecycleRequest(r.ProtocolVersion, r.RequestID, r.LeaseID, r.HelperInstanceCredential)
}

type InstanceStatusResponse struct {
	ProtocolVersion         int       `json:"protocol_version,omitempty"`
	RequestID               string    `json:"request_id,omitempty"`
	Capabilities            []string  `json:"capabilities,omitempty"`
	HelperKind              string    `json:"helper_kind"`
	LeaseID                 string    `json:"lease_id,omitempty"`
	UnitName                string    `json:"unit_name,omitempty"`
	CreatedAt               time.Time `json:"created_at"`
	SoftExpiresAt           time.Time `json:"soft_expires_at"`
	HardExpiresAt           time.Time `json:"hard_expires_at"`
	ActiveRegistrationCount int       `json:"active_registration_count"`
	Status                  string    `json:"status"`
	Reason                  string    `json:"reason,omitempty"`
	RenewalGeneration       uint64    `json:"renewal_generation"`
	OK                      bool      `json:"ok"`
	Error                   string    `json:"error,omitempty"`
}

type RenewInstanceRequest struct {
	ProtocolVersion          int    `json:"protocol_version,omitempty"`
	RequestID                string `json:"request_id,omitempty"`
	LeaseID                  string `json:"lease_id"`
	HelperInstanceCredential string `json:"helper_instance_credential"`
}

func (r RenewInstanceRequest) Validate() error {
	return validateInstanceLifecycleRequest(r.ProtocolVersion, r.RequestID, r.LeaseID, r.HelperInstanceCredential)
}

type RenewInstanceResponse = InstanceStatusResponse

func validateInstanceLifecycleRequest(protocolVersion int, requestID, leaseID, credential string) error {
	if err := validateProtocolVersion(protocolVersion); err != nil {
		return err
	}
	if requestID != "" {
		if err := validateID("request_id", requestID); err != nil {
			return err
		}
	}
	if err := validateID("lease_id", leaseID); err != nil {
		return err
	}
	if strings.TrimSpace(credential) == "" {
		return fmt.Errorf("helper_instance_credential is required")
	}
	return validateWireCredential("helper_instance_credential", credential)
}

// ReleaseInstanceRequest asks an ephemeral helper to stop after all registered
// command cgroups have been cleaned. It is a fixed lifecycle operation: it
// cannot name pins, units, processes, or arbitrary cleanup targets.
type ReleaseInstanceRequest struct {
	ProtocolVersion          int    `json:"protocol_version,omitempty"`
	RequestID                string `json:"request_id,omitempty"`
	LeaseID                  string `json:"lease_id"`
	HelperInstanceCredential string `json:"helper_instance_credential"`
}

// Validate rejects malformed or unauthenticated release requests.
func (r ReleaseInstanceRequest) Validate() error {
	if err := validateProtocolVersion(r.ProtocolVersion); err != nil {
		return err
	}
	if r.RequestID != "" {
		if err := validateID("request_id", r.RequestID); err != nil {
			return err
		}
	}
	if err := validateID("lease_id", r.LeaseID); err != nil {
		return err
	}
	if strings.TrimSpace(r.HelperInstanceCredential) == "" {
		return fmt.Errorf("helper_instance_credential is required")
	}
	return validateWireCredential("helper_instance_credential", r.HelperInstanceCredential)
}

// ReleaseInstanceResponse confirms that an ephemeral helper accepted release.
// The helper stops only after this response has been written to the caller.
type ReleaseInstanceResponse struct {
	ProtocolVersion int    `json:"protocol_version,omitempty"`
	RequestID       string `json:"request_id,omitempty"`
	LeaseID         string `json:"lease_id,omitempty"`
	OK              bool   `json:"ok"`
	Error           string `json:"error,omitempty"`
}

// DecodeRegisterSessionCgroupRequestJSON decodes a registration request using
// strict JSON field checking, then validates it.
func DecodeRegisterSessionCgroupRequestJSON(data []byte) (RegisterSessionCgroupRequest, error) {
	var req RegisterSessionCgroupRequest
	if err := decodeStrictJSON(data, &req); err != nil {
		return req, err
	}
	return req, req.Validate()
}

// DecodeUpdatePolicyMapRequestJSON decodes a map-update request using strict
// JSON field checking, then validates it.
func DecodeUpdatePolicyMapRequestJSON(data []byte) (UpdatePolicyMapRequest, error) {
	var req UpdatePolicyMapRequest
	if err := decodeStrictJSON(data, &req); err != nil {
		return req, err
	}
	return req, req.Validate()
}

// DecodeCleanupSessionRequestJSON decodes a cleanup request using strict JSON
// field checking, then validates it.
func DecodeCleanupSessionRequestJSON(data []byte) (CleanupSessionRequest, error) {
	var req CleanupSessionRequest
	if err := decodeStrictJSON(data, &req); err != nil {
		return req, err
	}
	return req, req.Validate()
}

// DecodeReleaseInstanceRequestJSON strictly decodes an ephemeral-helper
// release request.
func DecodeInstanceStatusRequestJSON(data []byte) (InstanceStatusRequest, error) {
	var req InstanceStatusRequest
	if err := decodeStrictJSON(data, &req); err != nil {
		return req, err
	}
	return req, req.Validate()
}

func DecodeRenewInstanceRequestJSON(data []byte) (RenewInstanceRequest, error) {
	var req RenewInstanceRequest
	if err := decodeStrictJSON(data, &req); err != nil {
		return req, err
	}
	return req, req.Validate()
}

func DecodeReleaseInstanceRequestJSON(data []byte) (ReleaseInstanceRequest, error) {
	var req ReleaseInstanceRequest
	if err := decodeStrictJSON(data, &req); err != nil {
		return req, err
	}
	return req, req.Validate()
}

func decodeStrictJSON(data []byte, v any) error {
	if err := rejectDuplicateJSONFields(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func rejectDuplicateJSONFields(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var walkValue func() error
	walkValue = func() error {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("JSON object key is not a string")
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("duplicate JSON field %q", key)
				}
				seen[key] = struct{}{}
				if err := walkValue(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if end != json.Delim('}') {
				return fmt.Errorf("malformed JSON object")
			}
		case '[':
			for dec.More() {
				if err := walkValue(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if end != json.Delim(']') {
				return fmt.Errorf("malformed JSON array")
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delim)
		}
		return nil
	}
	if err := walkValue(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func validateWireCredential(field, value string) error {
	if value == "" {
		return nil
	}
	if len(value) > 512 {
		return fmt.Errorf("%s exceeds 512 bytes", field)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must not contain surrounding whitespace", field)
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("%s must not contain whitespace or control characters", field)
		}
	}
	return nil
}

func validateProtocolVersion(version int) error {
	if version < 0 {
		return fmt.Errorf("protocol_version must not be negative")
	}
	if version > CurrentProtocolVersion {
		return fmt.Errorf("unsupported protocol_version %d", version)
	}
	return nil
}

func validateID(field string, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if len(value) > maxIdentifierBytes {
		return fmt.Errorf("%s exceeds %d bytes", field, maxIdentifierBytes)
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.' || r == ':':
		default:
			return fmt.Errorf("%s contains invalid character %q", field, r)
		}
	}
	return nil
}

func validateCgroupPath(field string, value string, required bool) error {
	value = strings.TrimSpace(value)
	if value == "" {
		if required {
			return fmt.Errorf("%s is required", field)
		}
		return nil
	}
	if strings.ContainsRune(value, 0) {
		return fmt.Errorf("%s contains NUL", field)
	}
	if strings.Contains(value, "..") {
		return fmt.Errorf("%s must not contain parent traversal", field)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains control character", field)
		}
	}
	return nil
}

func validateFamilyMatchesAddr(family IPFamily, addr netip.Addr) error {
	if family == "" {
		return nil
	}
	if family == IPFamilyIPv4 && !addr.Is4() {
		return fmt.Errorf("family ipv4 does not match address")
	}
	if family == IPFamilyIPv6 && !addr.Is6() {
		return fmt.Errorf("family ipv6 does not match address")
	}
	return nil
}
