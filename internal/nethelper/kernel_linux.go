//go:build linux

package nethelper

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	ebpftrace "github.com/agentsh/agentsh/internal/netmonitor/ebpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// KernelBackendOptions controls the Linux helper-owned kernel backend. The
// backend always loads AgentSH's embedded BPF object; it never accepts BPF
// bytecode, object paths, program fds, map fds, or link fds from clients.
type KernelBackendOptions struct {
	// PinRoot is an AgentSH-owned bpffs subtree for helper-created maps and
	// bpf_links. Empty disables pinning. The default constructor uses
	// DefaultBPFFSPinRoot so restart-tolerant pins are attempted by default.
	PinRoot string

	// TrustBoundaryComplete should remain false unless deployment guarantees that
	// same-UID tools cannot reach the helper socket/fds and kernel cgroup checks
	// are enabled. When false, Register responses intentionally do not claim
	// NetworkPolicyEnforced even after successful attach.
	TrustBoundaryComplete bool

	// PinOwnerUID is the required owner of the helper pin subtree. Constructors
	// default this to the helper's effective UID (root in production).
	PinOwnerUID uint32

	// TargetUID limits automatic orphan reaping to one per-user helper instance.
	// Production services set EnforceTargetUID; recovery tooling has separate
	// explicit selectors.
	TargetUID        uint32
	EnforceTargetUID bool
}

// DefaultBPFFSPinRoot returns the default bpffs subtree used for helper-owned
// pins. It is a function (not a const) so path construction remains portable.
func DefaultBPFFSPinRoot() string {
	return filepath.Join(string(filepath.Separator), "sys", "fs", "bpf", "agentsh")
}

// KernelBackend is the Linux privileged-helper kernel backend. It owns loaded
// collections, links, maps, pins, and cleanup for registered session cgroups.
type KernelBackend struct {
	opts KernelBackendOptions

	mu       sync.Mutex
	sessions map[string]*kernelSession
	byID     map[uint64]string
	byPath   map[string]string
	reserved map[uint64]bool
}

type kernelSession struct {
	SessionID      string
	CgroupPath     string
	CgroupID       uint64
	Tier           EnforcementTier
	Mode           BuiltinMode
	Proxy          *ProxyEndpoint
	PinPath        string
	CleanupPending bool

	opMu       sync.Mutex
	attachment *ebpftrace.CgroupAttachment
}

func NewKernelBackend() *KernelBackend {
	return NewKernelBackendWithOptions(KernelBackendOptions{PinRoot: DefaultBPFFSPinRoot()})
}

func NewKernelBackendWithOptions(opts KernelBackendOptions) *KernelBackend {
	if opts.PinOwnerUID == 0 && os.Geteuid() != 0 {
		opts.PinOwnerUID = uint32(os.Geteuid())
	}
	return &KernelBackend{
		opts:     opts,
		sessions: make(map[string]*kernelSession),
		byID:     make(map[uint64]string),
		byPath:   make(map[string]string),
		reserved: make(map[uint64]bool),
	}
}

func validateKernelRegistration(req RegisterSessionCgroupRequest) error {
	if req.Mode.Normalized() != BuiltinModeCgroupConnectGate {
		return fmt.Errorf("built-in mode %q is not implemented: transparent redirect is not part of proxy-required enforcement", req.Mode.Normalized())
	}
	switch req.Tier.Normalized() {
	case EnforcementTierHelperEBPFGate:
		if req.Proxy != nil {
			return fmt.Errorf("proxy metadata is only valid for a proxy-required tier")
		}
	case EnforcementTierHelperEBPFProxy, EnforcementTierHelperEBPFProxyRequired:
		if req.Proxy == nil {
			return fmt.Errorf("proxy-required registration requires an exact proxy endpoint")
		}
		if _, err := req.Proxy.AddrPort(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("kernel helper does not implement enforcement tier %q", req.Tier.Normalized())
	}
	return nil
}

func cloneProxyEndpoint(endpoint *ProxyEndpoint) *ProxyEndpoint {
	if endpoint == nil {
		return nil
	}
	copy := *endpoint
	return &copy
}

func validateKernelPolicyUpdate(sess *kernelSession, req UpdatePolicyMapRequest) error {
	if sess == nil {
		return fmt.Errorf("registered kernel session is unavailable")
	}
	proxyRequired := sess.Tier == EnforcementTierHelperEBPFProxy || sess.Tier == EnforcementTierHelperEBPFProxyRequired
	if !proxyRequired {
		if req.Proxy != nil {
			return fmt.Errorf("proxy metadata does not match the registered enforcement tier")
		}
		if !req.DefaultDeny {
			return fmt.Errorf("pinned helper policy updates must remain default-deny")
		}
		return nil
	}
	if !req.DefaultDeny {
		return fmt.Errorf("proxy-required policy updates must remain default-deny")
	}
	if req.Proxy == nil || sess.Proxy == nil {
		return fmt.Errorf("proxy-required policy update is missing its registered proxy endpoint")
	}
	registered, err := sess.Proxy.AddrPort()
	if err != nil {
		return fmt.Errorf("registered proxy endpoint is invalid: %w", err)
	}
	requested, err := req.Proxy.AddrPort()
	if err != nil {
		return err
	}
	if requested != registered {
		return fmt.Errorf("proxy endpoint does not match the registered session cgroup")
	}
	if len(req.Allow) == 0 {
		return fmt.Errorf("proxy-required policy update has no exact proxy endpoints")
	}
	if len(req.Deny) != 0 {
		return fmt.Errorf("proxy-required policy update accepts only exact proxy allow endpoints")
	}
	registeredPresent := false
	seen := make(map[netip.AddrPort]struct{}, len(req.Allow))
	for i, entry := range req.Allow {
		if strings.TrimSpace(entry.CIDR) != "" || strings.TrimSpace(entry.IP) == "" {
			return fmt.Errorf("proxy-required allow[%d] must be an exact IP endpoint", i)
		}
		if entry.Protocol.Normalized() != TransportProtocolTCP || entry.Port <= 0 {
			return fmt.Errorf("proxy-required allow[%d] must be exact TCP address+port", i)
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(entry.IP))
		if err != nil || addr.Zone() != "" {
			return fmt.Errorf("proxy-required allow[%d] has an invalid IP address", i)
		}
		addr = addr.Unmap()
		if !addr.IsLoopback() {
			return fmt.Errorf("proxy-required allow[%d] is not a loopback proxy endpoint", i)
		}
		endpoint := netip.AddrPortFrom(addr, uint16(entry.Port))
		if _, duplicate := seen[endpoint]; duplicate {
			return fmt.Errorf("proxy-required allow[%d] duplicates endpoint %s", i, endpoint)
		}
		seen[endpoint] = struct{}{}
		if endpoint == registered {
			registeredPresent = true
		}
	}
	if !registeredPresent {
		return fmt.Errorf("proxy-required allowlist omits the registered primary proxy endpoint")
	}
	return nil
}

func (b *KernelBackend) RegisterSessionCgroup(ctx context.Context, peer PeerInfo, req RegisterSessionCgroupRequest) (RegisterSessionCgroupResponse, error) {
	if b == nil {
		return RegisterSessionCgroupResponse{OK: false, Error: "nethelper kernel backend is nil"}, fmt.Errorf("nethelper kernel backend is nil")
	}
	if err := req.Validate(); err != nil {
		return RegisterSessionCgroupResponse{OK: false, Error: err.Error()}, err
	}
	if err := validateKernelRegistration(req); err != nil {
		return RegisterSessionCgroupResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}
	select {
	case <-ctx.Done():
		return RegisterSessionCgroupResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: ctx.Err().Error()}, ctx.Err()
	default:
	}

	cgroupPath, err := (kernelCgroupResolver{}).CanonicalCgroupPath(req.CgroupPath)
	if err != nil {
		err = fmt.Errorf("canonicalize target cgroup: %w", err)
		return RegisterSessionCgroupResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}
	key := registrationKey(req.SessionID, cgroupPath)
	cgroupID, err := ebpftrace.CgroupID(cgroupPath)
	if err != nil {
		err = fmt.Errorf("resolve cgroup id: %w", err)
		return RegisterSessionCgroupResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}

	b.mu.Lock()
	if _, exists := b.sessions[key]; exists {
		b.mu.Unlock()
		err := fmt.Errorf("session cgroup is already registered with this helper")
		return RegisterSessionCgroupResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}
	if _, exists := b.byPath[cgroupPath]; exists || b.byID[cgroupID] != "" || b.reserved[cgroupID] {
		b.mu.Unlock()
		err := fmt.Errorf("target cgroup identity is already registered with this helper")
		return RegisterSessionCgroupResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}
	b.reserved[cgroupID] = true
	b.mu.Unlock()
	reserved := true
	defer func() {
		if reserved {
			b.mu.Lock()
			delete(b.reserved, cgroupID)
			b.mu.Unlock()
		}
	}()

	pinPath, err := b.pinPath(peer, req, cgroupID)
	if err != nil {
		return RegisterSessionCgroupResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}
	if pinPath != "" {
		if err := preparePinPath(b.opts.PinRoot, pinPath, b.opts.PinOwnerUID); err != nil {
			err = fmt.Errorf("prepare helper-selected pin path: %w", err)
			return RegisterSessionCgroupResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
		}
	}

	attachment, reloadedPins, err := loadPinnedCgroupAttachment(pinPath, cgroupID, b.opts.PinOwnerUID)
	if err != nil {
		err = fmt.Errorf("reload pinned helper resources: %w", err)
		return RegisterSessionCgroupResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}
	if attachment == nil {
		attachOpts := ebpftrace.CgroupAttachOptions{
			PinPath:                pinPath,
			FailClosedBeforeAttach: true,
		}
		attachment, err = ebpftrace.AttachConnectToCgroupWithOptions(cgroupPath, attachOpts)
		if err != nil {
			_ = removeEmptyPinDirectories(b.opts.PinRoot, pinPath)
			err = fmt.Errorf("attach built-in cgroup connect programs: %w", err)
			return RegisterSessionCgroupResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
		}
	}
	if attachment == nil || attachment.Collection == nil {
		return RegisterSessionCgroupResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: "helper attachment has no eBPF collection"}, fmt.Errorf("helper attachment has no eBPF collection")
	}
	if err := ebpftrace.PopulateAllowlist(attachment.Collection, cgroupID, nil, nil, nil, nil, true); err != nil {
		if reloadedPins {
			closeAttachmentRefs(attachment)
		} else {
			_ = attachment.Close()
			_ = removeEmptyPinDirectories(b.opts.PinRoot, pinPath)
		}
		err = fmt.Errorf("initialize helper gate fail closed: %w", err)
		return RegisterSessionCgroupResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}

	sess := &kernelSession{
		SessionID:  req.SessionID,
		CgroupPath: cgroupPath,
		CgroupID:   cgroupID,
		Tier:       req.Tier.Normalized(),
		Mode:       req.Mode.Normalized(),
		Proxy:      cloneProxyEndpoint(req.Proxy),
		PinPath:    pinPath,
		attachment: attachment,
	}

	b.mu.Lock()
	delete(b.reserved, cgroupID)
	reserved = false
	if _, exists := b.sessions[key]; exists || b.byPath[cgroupPath] != "" || b.byID[cgroupID] != "" {
		b.mu.Unlock()
		if reloadedPins {
			closeAttachmentRefs(attachment)
		} else {
			_ = attachment.Close()
			_ = removeEmptyPinDirectories(b.opts.PinRoot, pinPath)
		}
		err := fmt.Errorf("target cgroup identity is already registered with this helper")
		return RegisterSessionCgroupResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}
	b.sessions[key] = sess
	b.byID[cgroupID] = key
	b.byPath[cgroupPath] = key
	b.mu.Unlock()

	warnings := b.registrationWarnings(req, pinPath, reloadedPins)
	return RegisterSessionCgroupResponse{
		ProtocolVersion:       CurrentProtocolVersion,
		RequestID:             req.RequestID,
		SessionID:             req.SessionID,
		OK:                    true,
		Tier:                  sess.Tier,
		Mode:                  sess.Mode,
		CgroupID:              cgroupID,
		NetworkPolicyEnforced: false,
		PinPath:               pinPath,
		Warnings:              warnings,
	}, nil
}

func (b *KernelBackend) UpdatePolicyMap(ctx context.Context, _ PeerInfo, req UpdatePolicyMapRequest) (UpdatePolicyMapResponse, error) {
	if b == nil {
		return UpdatePolicyMapResponse{OK: false, Error: "nethelper kernel backend is nil"}, fmt.Errorf("nethelper kernel backend is nil")
	}
	if err := req.Validate(); err != nil {
		return UpdatePolicyMapResponse{OK: false, Error: err.Error()}, err
	}
	if req.Mode.Normalized() == BuiltinModeCgroupProxyRedirect {
		err := fmt.Errorf("built-in mode %q is not implemented: transparent redirect is not part of proxy-required enforcement", BuiltinModeCgroupProxyRedirect)
		return UpdatePolicyMapResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}
	select {
	case <-ctx.Done():
		return UpdatePolicyMapResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: ctx.Err().Error()}, ctx.Err()
	default:
	}

	sess, err := b.lookupSession(req.SessionID, req.CgroupPath, req.CgroupID)
	if err != nil {
		return UpdatePolicyMapResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}
	sess.opMu.Lock()
	defer sess.opMu.Unlock()
	b.mu.Lock()
	active := b.sessions[registrationKey(sess.SessionID, sess.CgroupPath)] == sess && !sess.CleanupPending
	b.mu.Unlock()
	if !active {
		err := fmt.Errorf("session cgroup cleanup is in progress")
		return UpdatePolicyMapResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}
	if req.CgroupID == 0 || req.CgroupID != sess.CgroupID {
		err := fmt.Errorf("cgroup_id does not match registered session cgroup")
		return UpdatePolicyMapResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}
	if cleanCgroupPath(req.CgroupPath) != sess.CgroupPath {
		err := fmt.Errorf("cgroup_path does not match registered session cgroup")
		return UpdatePolicyMapResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}
	if req.Mode.Normalized() != sess.Mode {
		err := fmt.Errorf("mode does not match registered session cgroup")
		return UpdatePolicyMapResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}
	if err := validateKernelPolicyUpdate(sess, req); err != nil {
		return UpdatePolicyMapResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}
	currentID, idErr := ebpftrace.CgroupID(sess.CgroupPath)
	if idErr != nil || currentID != sess.CgroupID {
		err := fmt.Errorf("registered cgroup identity changed: got %d: %w", currentID, idErr)
		if idErr == nil {
			err = fmt.Errorf("registered cgroup identity changed: got %d, want %d", currentID, sess.CgroupID)
		}
		return UpdatePolicyMapResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}
	if sess.attachment == nil || sess.attachment.Collection == nil {
		err := fmt.Errorf("registered session has no active eBPF collection")
		return UpdatePolicyMapResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}

	allowExact, allowCIDR, err := policyEntriesToEBPF(req.Allow)
	if err != nil {
		err = fmt.Errorf("allow entries: %w", err)
		return UpdatePolicyMapResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}
	denyExact, denyCIDR, err := policyEntriesToEBPF(req.Deny)
	if err != nil {
		err = fmt.Errorf("deny entries: %w", err)
		return UpdatePolicyMapResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}
	if err := ebpftrace.PopulateAllowlist(sess.attachment.Collection, sess.CgroupID, allowExact, allowCIDR, denyExact, denyCIDR, req.DefaultDeny); err != nil {
		err = fmt.Errorf("populate helper-owned policy maps: %w", err)
		return UpdatePolicyMapResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}

	warnings := updateWarnings(req)
	return UpdatePolicyMapResponse{
		ProtocolVersion: CurrentProtocolVersion,
		RequestID:       req.RequestID,
		SessionID:       req.SessionID,
		OK:              true,
		DefaultDeny:     req.DefaultDeny,
		AllowEntries:    len(req.Allow),
		DenyEntries:     len(req.Deny),
		Warnings:        warnings,
	}, nil
}

func (b *KernelBackend) CleanupSession(ctx context.Context, _ PeerInfo, req CleanupSessionRequest) (CleanupSessionResponse, error) {
	if b == nil {
		return CleanupSessionResponse{OK: false, Error: "nethelper kernel backend is nil"}, fmt.Errorf("nethelper kernel backend is nil")
	}
	if err := req.Validate(); err != nil {
		return CleanupSessionResponse{OK: false, Error: err.Error()}, err
	}
	select {
	case <-ctx.Done():
		return CleanupSessionResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: ctx.Err().Error()}, ctx.Err()
	default:
	}

	if strings.TrimSpace(req.CgroupPath) == "" || req.CgroupID == 0 {
		err := fmt.Errorf("cleanup requires the exact registered cgroup_path and cgroup_id")
		return CleanupSessionResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}
	sess, err := b.beginSessionCleanup(req.SessionID, req.CgroupPath, req.CgroupID)
	if err != nil {
		return CleanupSessionResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}, err
	}
	sess.opMu.Lock()
	defer sess.opMu.Unlock()
	var removed []string
	if sess.attachment != nil {
		removed = append([]string(nil), sess.attachment.PinnedPaths...)
	}
	// CgroupAttachment.Close detaches links before unpinning/closing maps. Do
	// not clear default-deny first: that would create an allow-all interval for
	// any process still present in the cgroup during cleanup.
	if sess.attachment != nil {
		if err := sess.attachment.Close(); err != nil {
			b.finishSessionCleanup(sess, false)
			err = fmt.Errorf("close helper-owned eBPF resources: %w", err)
			return CleanupSessionResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, RemovedPins: removed, Error: err.Error()}, err
		}
	}
	if sess.PinPath != "" {
		if err := removeEmptyPinDirectories(b.opts.PinRoot, sess.PinPath); err != nil {
			b.finishSessionCleanup(sess, false)
			return CleanupSessionResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, RemovedPins: removed, Error: err.Error()}, err
		}
	}
	b.finishSessionCleanup(sess, true)
	return CleanupSessionResponse{
		ProtocolVersion: CurrentProtocolVersion,
		RequestID:       req.RequestID,
		SessionID:       req.SessionID,
		OK:              true,
		RemovedPins:     removed,
	}, nil
}

func (b *KernelBackend) lookupSession(sessionID, cgroupPath string, cgroupID uint64) (*kernelSession, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var sess *kernelSession
	if strings.TrimSpace(cgroupPath) != "" {
		sess = b.sessions[registrationKey(sessionID, cgroupPath)]
	} else if cgroupID != 0 {
		sess = b.sessions[b.byID[cgroupID]]
	}
	if sess == nil || sess.SessionID != strings.TrimSpace(sessionID) || sess.CleanupPending {
		return nil, fmt.Errorf("session cgroup is not registered with this helper")
	}
	if strings.TrimSpace(cgroupPath) != "" && cleanCgroupPath(cgroupPath) != sess.CgroupPath {
		return nil, fmt.Errorf("cgroup_path does not match registered session cgroup")
	}
	if cgroupID != 0 && cgroupID != sess.CgroupID {
		return nil, fmt.Errorf("cgroup_id does not match registered session cgroup")
	}
	return sess, nil
}

func (b *KernelBackend) beginSessionCleanup(sessionID, cgroupPath string, cgroupID uint64) (*kernelSession, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := registrationKey(sessionID, cgroupPath)
	sess := b.sessions[key]
	if sess == nil || sess.CleanupPending || sess.SessionID != strings.TrimSpace(sessionID) || sess.CgroupPath != cleanCgroupPath(cgroupPath) || sess.CgroupID != cgroupID {
		return nil, fmt.Errorf("cleanup identity does not match a registered session cgroup")
	}
	sess.CleanupPending = true
	return sess, nil
}

func (b *KernelBackend) finishSessionCleanup(sess *kernelSession, succeeded bool) {
	if b == nil || sess == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	key := registrationKey(sess.SessionID, sess.CgroupPath)
	if b.sessions[key] != sess {
		return
	}
	if !succeeded {
		sess.CleanupPending = false
		return
	}
	delete(b.sessions, key)
	delete(b.byID, sess.CgroupID)
	delete(b.byPath, sess.CgroupPath)
}

func (b *KernelBackend) pinPath(peer PeerInfo, req RegisterSessionCgroupRequest, cgroupID uint64) (string, error) {
	root := strings.TrimSpace(b.opts.PinRoot)
	if root == "" {
		return "", nil
	}
	if peer.PID <= 0 || peer.ProcessStartTime == 0 {
		return "", fmt.Errorf("stable peer process identity is required to select a pin path")
	}
	if req.SupervisorPID != peer.PID {
		return "", fmt.Errorf("supervisor pid does not match pin owner identity")
	}
	pinPath := filepath.Join(
		root,
		pinSchemaComponent,
		fmt.Sprintf("uid-%d", peer.UID),
		fmt.Sprintf("supervisor-%d-%x", peer.PID, peer.ProcessStartTime),
		"sessions",
		"session-"+hex.EncodeToString([]byte(strings.TrimSpace(req.SessionID))),
		fmt.Sprintf("cgroup-%x", cgroupID),
	)
	if err := validatePinPath(root, pinPath); err != nil {
		return "", err
	}
	return filepath.Clean(pinPath), nil
}

func (b *KernelBackend) registrationWarnings(req RegisterSessionCgroupRequest, pinPath string, reloadedPins bool) []string {
	var warnings []string
	if !b.opts.TrustBoundaryComplete {
		warnings = append(warnings, "helper attached the built-in cgroup eBPF gate, but network_policy_enforced is not claimed until same-UID socket/fd isolation and proxy bypass controls are proven")
	}
	if pinPath == "" {
		warnings = append(warnings, "helper resources are not pinned in bpffs; enforcement is helper-process-lifetime only")
	} else if reloadedPins {
		warnings = append(warnings, "reloaded pinned bpffs maps/links for this session cgroup after helper restart")
	}
	if req.Proxy != nil || req.Tier.Normalized() == EnforcementTierHelperEBPFProxy || req.Tier.Normalized() == EnforcementTierHelperEBPFProxyRequired {
		warnings = append(warnings, "transparent cgroup redirect is not implemented; helper supports proxy-required mode only when the supervisor installs a default-deny map for exact proxy endpoints")
	}
	return warnings
}

func updateWarnings(req UpdatePolicyMapRequest) []string {
	var warnings []string
	if req.Proxy != nil && req.DefaultDeny {
		warnings = append(warnings, "proxy-or-block gate active: direct external connects are denied; proxy-aware clients must use the AgentSH proxy approval path")
	}
	if req.Proxy != nil && !req.DefaultDeny {
		warnings = append(warnings, "proxy metadata supplied without default_deny; direct network bypasses may still be possible")
	}
	return warnings
}

func policyEntriesToEBPF(entries []PolicyMapEntry) ([]ebpftrace.AllowKey, []ebpftrace.AllowCIDR, error) {
	var exact []ebpftrace.AllowKey
	var cidrs []ebpftrace.AllowCIDR
	for i, entry := range entries {
		if err := entry.Validate(); err != nil {
			return nil, nil, fmt.Errorf("entry %d: %w", i, err)
		}
		proto := protocolNumber(entry.Protocol.Normalized())
		port := uint16(entry.Port)
		if ip := strings.TrimSpace(entry.IP); ip != "" {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				return nil, nil, fmt.Errorf("entry %d ip: %w", i, err)
			}
			var key ebpftrace.AllowKey
			key.Protocol = proto
			key.Dport = port
			if addr.Is4() {
				key.Family = 2
				a := addr.As4()
				copy(key.Addr[:4], a[:])
			} else {
				key.Family = 10
				a := addr.As16()
				copy(key.Addr[:], a[:])
			}
			exact = append(exact, key)
			continue
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(entry.CIDR))
		if err != nil {
			return nil, nil, fmt.Errorf("entry %d cidr: %w", i, err)
		}
		prefix = prefix.Masked()
		addr := prefix.Addr()
		var cidr ebpftrace.AllowCIDR
		cidr.Protocol = proto
		cidr.PrefixLen = uint32(prefix.Bits())
		cidr.Dport = port
		if addr.Is4() {
			cidr.Family = 2
			a := addr.As4()
			copy(cidr.Addr[:4], a[:])
		} else {
			cidr.Family = 10
			a := addr.As16()
			copy(cidr.Addr[:], a[:])
		}
		cidrs = append(cidrs, cidr)
	}
	return exact, cidrs, nil
}

func protocolNumber(proto TransportProtocol) uint8 {
	switch proto {
	case TransportProtocolTCP:
		return 6
	case TransportProtocolUDP:
		return 17
	default:
		return 0
	}
}

const pinSchemaComponent = "schema-v1"

var expectedLinkRoles = map[string]ebpf.AttachType{
	"handle_connect4": ebpf.AttachCGroupInet4Connect,
	"handle_connect6": ebpf.AttachCGroupInet6Connect,
	"handle_sendmsg4": ebpf.AttachCGroupUDP4Sendmsg,
	"handle_sendmsg6": ebpf.AttachCGroupUDP6Sendmsg,
}

type pinnedProgramSchema struct {
	AttachType ebpf.AttachType
	Tag        string
}

func expectedPinnedProgramSchemas() (map[string]pinnedProgramSchema, error) {
	collection, err := ebpftrace.LoadConnectProgram()
	if err != nil {
		return nil, fmt.Errorf("load built-in programs for pin validation: %w", err)
	}
	defer collection.Close()
	if len(collection.Programs) != len(expectedLinkRoles) {
		return nil, fmt.Errorf("built-in program set has %d entries, want exactly %d", len(collection.Programs), len(expectedLinkRoles))
	}
	expected := make(map[string]pinnedProgramSchema, len(expectedLinkRoles))
	for name, attachType := range expectedLinkRoles {
		program := collection.Programs[name]
		if program == nil {
			return nil, fmt.Errorf("built-in program role %s is missing", name)
		}
		info, err := program.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect built-in program role %s: %w", name, err)
		}
		if info.Type != ebpf.CGroupSockAddr || info.Name != name || strings.TrimSpace(info.Tag) == "" {
			return nil, fmt.Errorf("built-in program role %s has an unexpected kernel identity", name)
		}
		expected[name] = pinnedProgramSchema{AttachType: attachType, Tag: info.Tag}
	}
	return expected, nil
}

type pinnedMapSchema struct {
	Type       ebpf.MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
}

func expectedPinnedMapSchemas() (map[string]pinnedMapSchema, error) {
	expectedNames := map[string]bool{
		"events":       true,
		"allowlist":    true,
		"denylist":     true,
		"default_deny": true,
		"lpm4_allow":   true,
		"lpm6_allow":   true,
		"lpm4_deny":    true,
		"lpm6_deny":    true,
	}
	collection, err := ebpftrace.LoadConnectProgram()
	if err != nil {
		return nil, fmt.Errorf("load built-in maps for pin validation: %w", err)
	}
	defer collection.Close()
	if len(collection.Maps) != len(expectedNames) {
		return nil, fmt.Errorf("built-in map set has %d entries, want exactly %d", len(collection.Maps), len(expectedNames))
	}
	expected := make(map[string]pinnedMapSchema, len(expectedNames))
	for name := range expectedNames {
		builtInMap := collection.Maps[name]
		if builtInMap == nil {
			return nil, fmt.Errorf("built-in map role %s is missing", name)
		}
		info, err := builtInMap.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect built-in map role %s: %w", name, err)
		}
		if info.Name != name || info.MaxEntries == 0 {
			return nil, fmt.Errorf("built-in map role %s has an unexpected kernel schema", name)
		}
		expected[name] = pinnedMapSchema{
			Type:       info.Type,
			KeySize:    info.KeySize,
			ValueSize:  info.ValueSize,
			MaxEntries: info.MaxEntries,
			Flags:      info.Flags,
		}
	}
	return expected, nil
}

func loadPinnedCgroupAttachment(pinPath string, cgroupID uint64, ownerUID uint32) (*ebpftrace.CgroupAttachment, bool, error) {
	pinPath = strings.TrimSpace(pinPath)
	if pinPath == "" {
		return nil, false, nil
	}
	pinInfo, err := os.Lstat(pinPath)
	if err != nil {
		return nil, true, fmt.Errorf("stat pinned registration directory: %w", err)
	}
	if err := validateOwnedPinPath(pinPath, pinInfo, ownerUID, true); err != nil {
		return nil, true, err
	}
	pinEntries, err := os.ReadDir(pinPath)
	if err != nil {
		return nil, true, fmt.Errorf("read pinned registration directory: %w", err)
	}
	if len(pinEntries) == 0 {
		return nil, false, nil
	}
	if len(pinEntries) != 2 || pinEntries[0].Name() != "links" || pinEntries[1].Name() != "maps" || !pinEntries[0].IsDir() || !pinEntries[1].IsDir() {
		return nil, true, fmt.Errorf("pinned registration directory must contain exactly links and maps directories")
	}
	mapsDir := filepath.Join(pinPath, "maps")
	linksDir := filepath.Join(pinPath, "links")
	mapsInfo, mapsErr := os.Lstat(mapsDir)
	linksInfo, linksErr := os.Lstat(linksDir)
	if mapsErr != nil {
		return nil, true, fmt.Errorf("pinned maps dir unavailable: %w", mapsErr)
	}
	if linksErr != nil {
		return nil, true, fmt.Errorf("pinned links dir unavailable: %w", linksErr)
	}
	if !mapsInfo.IsDir() || !linksInfo.IsDir() {
		return nil, true, fmt.Errorf("pinned maps/links paths must be directories")
	}
	if err := validateOwnedPinPath(mapsDir, mapsInfo, ownerUID, true); err != nil {
		return nil, true, err
	}
	if err := validateOwnedPinPath(linksDir, linksInfo, ownerUID, true); err != nil {
		return nil, true, err
	}

	maps, pinnedPaths, err := loadPinnedMaps(mapsDir, ownerUID)
	if err != nil {
		return nil, true, err
	}
	links, linkPins, err := loadPinnedLinks(linksDir, cgroupID, ownerUID, maps)
	if err != nil {
		for _, m := range maps {
			_ = m.Close()
		}
		return nil, true, err
	}
	pinnedPaths = append(pinnedPaths, linkPins...)
	collection := &ebpf.Collection{Maps: maps}
	attachment := &ebpftrace.CgroupAttachment{
		Collection:  collection,
		Links:       links,
		PinnedPaths: pinnedPaths,
		CgroupID:    cgroupID,
	}
	if err := ebpftrace.ValidatePinnedPolicyState(collection, cgroupID); err != nil {
		// Link/program/map identity has already been validated. Best-effort lock
		// the actual attached map before dropping our references so malformed or
		// old default-allow state cannot remain a live bypass.
		lockErr := ebpftrace.LockPolicy(collection, cgroupID)
		closeAttachmentRefs(attachment)
		if lockErr != nil {
			return nil, true, errors.Join(err, fmt.Errorf("lock rejected pinned policy: %w", lockErr))
		}
		return nil, true, err
	}
	return attachment, true, nil
}

func closeAttachmentRefs(att *ebpftrace.CgroupAttachment) {
	if att == nil {
		return
	}
	for _, l := range att.Links {
		if l != nil {
			_ = l.Close()
		}
	}
	att.Links = nil
	if att.Collection != nil {
		att.Collection.Close()
		att.Collection = nil
	}
	att.PinnedPaths = nil
	att.CgroupID = 0
}

func loadPinnedMaps(mapsDir string, ownerUID uint32) (map[string]*ebpf.Map, []string, error) {
	expected, err := expectedPinnedMapSchemas()
	if err != nil {
		return nil, nil, err
	}
	entries, err := os.ReadDir(mapsDir)
	if err != nil {
		return nil, nil, fmt.Errorf("read pinned maps: %w", err)
	}
	if len(entries) != len(expected) {
		return nil, nil, fmt.Errorf("pinned map set has %d entries, want exactly %d", len(entries), len(expected))
	}
	maps := make(map[string]*ebpf.Map, len(expected))
	var pinned []string
	cleanup := func() {
		for _, m := range maps {
			_ = m.Close()
		}
	}
	for _, ent := range entries {
		schema, ok := expected[ent.Name()]
		if !ok || ent.IsDir() || ent.Type()&os.ModeSymlink != 0 {
			cleanup()
			return nil, nil, fmt.Errorf("unexpected pinned map entry %q", ent.Name())
		}
		path := filepath.Join(mapsDir, ent.Name())
		info, err := os.Lstat(path)
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("stat pinned map %s: %w", path, err)
		}
		if err := validateOwnedPinPath(path, info, ownerUID, false); err != nil {
			cleanup()
			return nil, nil, err
		}
		m, err := ebpf.LoadPinnedMap(path, nil)
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("load pinned map %s: %w", path, err)
		}
		mapInfo, err := m.Info()
		if err != nil {
			_ = m.Close()
			cleanup()
			return nil, nil, fmt.Errorf("inspect pinned map %s: %w", path, err)
		}
		if mapInfo.Type != schema.Type || mapInfo.KeySize != schema.KeySize || mapInfo.ValueSize != schema.ValueSize || mapInfo.MaxEntries != schema.MaxEntries || mapInfo.Flags != schema.Flags || mapInfo.Name != ent.Name() {
			_ = m.Close()
			cleanup()
			return nil, nil, fmt.Errorf("pinned map %s does not match built-in schema %s", path, pinSchemaComponent)
		}
		maps[ent.Name()] = m
		pinned = append(pinned, path)
	}
	return maps, pinned, nil
}

func loadPinnedLinks(linksDir string, cgroupID uint64, ownerUID uint32, maps map[string]*ebpf.Map) ([]link.Link, []string, error) {
	expectedPrograms, err := expectedPinnedProgramSchemas()
	if err != nil {
		return nil, nil, err
	}
	expectedMapIDs, err := pinnedMapIDSet(maps)
	if err != nil {
		return nil, nil, err
	}
	entries, err := os.ReadDir(linksDir)
	if err != nil {
		return nil, nil, fmt.Errorf("read pinned links: %w", err)
	}
	if len(entries) != len(expectedPrograms) {
		return nil, nil, fmt.Errorf("pinned link set has %d entries, want exactly %d", len(entries), len(expectedPrograms))
	}
	var links []link.Link
	var pinned []string
	seenPrograms := make(map[ebpf.ProgramID]bool)
	cleanup := func() {
		for _, loaded := range links {
			_ = loaded.Close()
		}
	}
	for _, ent := range entries {
		expected, ok := expectedPrograms[ent.Name()]
		if !ok || ent.IsDir() || ent.Type()&os.ModeSymlink != 0 {
			cleanup()
			return nil, nil, fmt.Errorf("unexpected pinned link entry %q", ent.Name())
		}
		path := filepath.Join(linksDir, ent.Name())
		pathInfo, err := os.Lstat(path)
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("stat pinned link %s: %w", path, err)
		}
		if err := validateOwnedPinPath(path, pathInfo, ownerUID, false); err != nil {
			cleanup()
			return nil, nil, err
		}
		loaded, err := link.LoadPinnedLink(path, nil)
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("load pinned link %s: %w", path, err)
		}
		linkInfo, err := loaded.Info()
		if err != nil {
			_ = loaded.Close()
			cleanup()
			return nil, nil, fmt.Errorf("inspect pinned link %s: %w", path, err)
		}
		cgroupInfo := linkInfo.Cgroup()
		if linkInfo.Type != link.CgroupType || cgroupInfo == nil || cgroupInfo.CgroupId != cgroupID || uint32(cgroupInfo.AttachType) != uint32(expected.AttachType) {
			_ = loaded.Close()
			cleanup()
			return nil, nil, fmt.Errorf("pinned link %s does not match cgroup %d role %s", path, cgroupID, ent.Name())
		}
		program, err := ebpf.NewProgramFromID(linkInfo.Program)
		if err != nil {
			_ = loaded.Close()
			cleanup()
			return nil, nil, fmt.Errorf("open pinned link program for %s: %w", path, err)
		}
		programInfo, infoErr := program.Info()
		_ = program.Close()
		if infoErr != nil {
			_ = loaded.Close()
			cleanup()
			return nil, nil, fmt.Errorf("inspect pinned link program for %s: %w", path, infoErr)
		}
		programMapIDs, available := programInfo.MapIDs()
		if programInfo.Type != ebpf.CGroupSockAddr || programInfo.Name != ent.Name() || programInfo.Tag != expected.Tag || seenPrograms[linkInfo.Program] || !available || !sameMapIDSet(programMapIDs, expectedMapIDs) {
			_ = loaded.Close()
			cleanup()
			return nil, nil, fmt.Errorf("pinned link %s program does not match built-in role %s and helper-owned maps", path, ent.Name())
		}
		seenPrograms[linkInfo.Program] = true
		links = append(links, loaded)
		pinned = append(pinned, path)
	}
	return links, pinned, nil
}

func pinnedMapIDSet(maps map[string]*ebpf.Map) (map[ebpf.MapID]bool, error) {
	ids := make(map[ebpf.MapID]bool, len(maps))
	for name, pinnedMap := range maps {
		if pinnedMap == nil {
			return nil, fmt.Errorf("pinned map %s is unavailable", name)
		}
		info, err := pinnedMap.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect pinned map id for %s: %w", name, err)
		}
		id, available := info.ID()
		if !available || id == 0 || ids[id] {
			return nil, fmt.Errorf("pinned map %s has an unavailable or duplicate kernel id", name)
		}
		ids[id] = true
	}
	return ids, nil
}

func sameMapIDSet(got []ebpf.MapID, expected map[ebpf.MapID]bool) bool {
	if len(got) != len(expected) {
		return false
	}
	seen := make(map[ebpf.MapID]bool, len(got))
	for _, id := range got {
		if !expected[id] || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func validatePinPath(root, pinPath string) error {
	root = strings.TrimSpace(root)
	pinPath = strings.TrimSpace(pinPath)
	if root == "" {
		return fmt.Errorf("pin root is required when pin_path is set")
	}
	if err := validatePinRoot(root); err != nil {
		return err
	}
	if pinPath == "" {
		return nil
	}
	if !filepath.IsAbs(pinPath) {
		return fmt.Errorf("pin paths must be absolute bpffs paths")
	}
	root = filepath.Clean(root)
	pinPath = filepath.Clean(pinPath)
	if !pathInSubtree(root, pinPath, false) {
		return fmt.Errorf("pin_path must be inside helper pin root %s", root)
	}
	rel, err := filepath.Rel(root, pinPath)
	if err != nil || strings.Split(rel, string(filepath.Separator))[0] != pinSchemaComponent {
		return fmt.Errorf("pin_path must use helper schema %s", pinSchemaComponent)
	}
	return nil
}

func validatePinRoot(root string) error {
	root = strings.TrimSpace(root)
	if root == "" || !filepath.IsAbs(root) {
		return fmt.Errorf("pin root must be an absolute bpffs path")
	}
	root = filepath.Clean(root)
	bpffsRoot := filepath.Join(string(filepath.Separator), "sys", "fs", "bpf")
	if !pathInSubtree(bpffsRoot, root, false) {
		return fmt.Errorf("pin root must be a dedicated subtree below %s", bpffsRoot)
	}
	return nil
}

func validateResolvedPinRoot(root string) error {
	resolved, err := filepath.EvalSymlinks(filepath.Clean(root))
	if err != nil {
		return fmt.Errorf("resolve pin root: %w", err)
	}
	if filepath.Clean(resolved) != filepath.Clean(root) {
		return fmt.Errorf("pin root must not contain symlink components")
	}
	return nil
}

func preparePinPath(root, pinPath string, ownerUID uint32) error {
	if err := validatePinPath(root, pinPath); err != nil {
		return err
	}
	root = filepath.Clean(root)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if err := validateResolvedPinRoot(root); err != nil {
		return err
	}
	if err := validateBPFFSMount(root); err != nil {
		return err
	}
	if err := validateOwnedPinPath(root, rootInfo, ownerUID, true); err != nil {
		return err
	}
	if err := os.MkdirAll(pinPath, 0o700); err != nil {
		return err
	}
	current := filepath.Clean(pinPath)
	for {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if err := validateOwnedPinPath(current, info, ownerUID, true); err != nil {
			return err
		}
		if current == root {
			break
		}
		parent := filepath.Dir(current)
		if !pathInSubtree(root, parent, true) {
			return fmt.Errorf("pin path escaped configured root")
		}
		current = parent
	}
	return nil
}

func validateBPFFSMount(path string) error {
	var statfs unix.Statfs_t
	if err := unix.Statfs(path, &statfs); err != nil {
		return fmt.Errorf("inspect pin root filesystem: %w", err)
	}
	if uint64(statfs.Type) != uint64(unix.BPF_FS_MAGIC) {
		return fmt.Errorf("pin root %s is not on bpffs", path)
	}
	return nil
}

func validateOwnedPinPath(path string, info os.FileInfo, ownerUID uint32, directory bool) error {
	if info == nil {
		return fmt.Errorf("pin path %s has no file information", path)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("pin path %s must not be a symlink", path)
	}
	if directory != info.IsDir() {
		return fmt.Errorf("pin path %s has the wrong file type", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("pin path %s must not be group/world accessible", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return fmt.Errorf("pin path %s ownership is unavailable", path)
	}
	if stat.Uid != ownerUID {
		return fmt.Errorf("pin path %s must be owned by uid %d, got %d", path, ownerUID, stat.Uid)
	}
	return nil
}

func removeEmptyPinDirectories(root, pinPath string) error {
	if strings.TrimSpace(pinPath) == "" {
		return nil
	}
	if err := validatePinPath(root, pinPath); err != nil {
		return err
	}
	for _, child := range []string{"links", "maps"} {
		if err := os.Remove(filepath.Join(pinPath, child)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove pin directory: %w", err)
		}
	}
	root = filepath.Clean(root)
	for current := filepath.Clean(pinPath); current != root && pathInSubtree(root, current, false); current = filepath.Dir(current) {
		if err := os.Remove(current); err != nil {
			if os.IsNotExist(err) || errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, syscall.EEXIST) {
				break
			}
			return fmt.Errorf("remove pin directory %s: %w", current, err)
		}
	}
	return nil
}

type pinnedRegistrationPath struct {
	Path                string
	UID                 uint32
	SupervisorPID       int
	SupervisorStartTime uint64
	SessionID           string
	CgroupID            uint64
}

func CleanupPinnedResources(opts PinCleanupOptions) (PinCleanupResult, error) {
	root := strings.TrimSpace(opts.PinRoot)
	if root == "" {
		root = DefaultBPFFSPinRoot()
	}
	root = filepath.Clean(root)
	if err := validatePinRoot(root); err != nil {
		return PinCleanupResult{}, err
	}
	if sessionID := strings.TrimSpace(opts.SessionID); sessionID != "" {
		if err := validateID("session_id", sessionID); err != nil {
			return PinCleanupResult{}, err
		}
	}
	if info, err := os.Lstat(root); err != nil {
		if os.IsNotExist(err) {
			return PinCleanupResult{Warnings: []string{"pin cleanup root does not exist"}}, nil
		}
		return PinCleanupResult{}, fmt.Errorf("stat pin cleanup root: %w", err)
	} else if err := validateOwnedPinPath(root, info, opts.OwnerUID, true); err != nil {
		return PinCleanupResult{}, err
	}
	if err := validateResolvedPinRoot(root); err != nil {
		return PinCleanupResult{}, err
	}
	if err := validateBPFFSMount(root); err != nil {
		return PinCleanupResult{}, err
	}

	registrations, warnings, err := discoverPinnedRegistrations(root, opts)
	if err != nil {
		return PinCleanupResult{}, err
	}
	result := PinCleanupResult{Warnings: warnings}
	for _, reg := range registrations {
		attachment, _, validateErr := loadPinnedCgroupAttachment(reg.Path, reg.CgroupID, opts.OwnerUID)
		if attachment != nil {
			closeAttachmentRefs(attachment)
		}
		if validateErr != nil && !opts.Force {
			result.Warnings = append(result.Warnings, fmt.Sprintf("skip malformed pin tree %s: %v (use --force for explicit recovery)", reg.Path, validateErr))
			continue
		}
		if !opts.Force {
			reapable, reason, reapErr := pinnedRegistrationReapable(reg)
			if reapErr != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("skip pin tree %s: %v", reg.Path, reapErr))
				continue
			}
			if !reapable {
				result.Warnings = append(result.Warnings, fmt.Sprintf("skip active pin tree %s: %s", reg.Path, reason))
				continue
			}
		}
		removed, err := removePinTree(reg.Path, opts.DryRun)
		result.Removed = append(result.Removed, removed...)
		if err != nil {
			return result, err
		}
		if !opts.DryRun {
			if err := removeEmptyPinDirectories(root, reg.Path); err != nil {
				return result, err
			}
		}
	}
	return result, nil
}

func discoverPinnedRegistrations(root string, opts PinCleanupOptions) ([]pinnedRegistrationPath, []string, error) {
	schemaRoot := filepath.Join(root, pinSchemaComponent)
	schemaInfo, err := os.Lstat(schemaRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, []string{"no current-schema pin trees found"}, nil
		}
		return nil, nil, err
	}
	if err := validateOwnedPinPath(schemaRoot, schemaInfo, opts.OwnerUID, true); err != nil {
		return nil, nil, err
	}
	var registrations []pinnedRegistrationPath
	var warnings []string
	err = filepath.WalkDir(schemaRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			warnings = append(warnings, "skip symlink in pin root: "+path)
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if err := validateOwnedPinPath(path, info, opts.OwnerUID, true); err != nil {
				warnings = append(warnings, fmt.Sprintf("skip unprotected pin directory %s: %v", path, err))
				return filepath.SkipDir
			}
		}
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "cgroup-") {
			return nil
		}
		reg, err := parsePinnedRegistrationPath(root, path)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skip unrecognized pin tree %s: %v", path, err))
			return filepath.SkipDir
		}
		if opts.EnforceTargetUID && reg.UID != opts.TargetUID {
			return filepath.SkipDir
		}
		if sessionID := strings.TrimSpace(opts.SessionID); sessionID != "" && reg.SessionID != sessionID {
			return filepath.SkipDir
		}
		registrations = append(registrations, reg)
		return filepath.SkipDir
	})
	if err != nil {
		return nil, warnings, fmt.Errorf("walk helper pin root: %w", err)
	}
	sort.Slice(registrations, func(i, j int) bool { return registrations[i].Path < registrations[j].Path })
	return registrations, warnings, nil
}

func parsePinnedRegistrationPath(root, path string) (pinnedRegistrationPath, error) {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil {
		return pinnedRegistrationPath{}, err
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) != 6 || parts[0] != pinSchemaComponent || parts[3] != "sessions" {
		return pinnedRegistrationPath{}, fmt.Errorf("unexpected schema path")
	}
	uidValue, err := strconv.ParseUint(strings.TrimPrefix(parts[1], "uid-"), 10, 32)
	if err != nil || !strings.HasPrefix(parts[1], "uid-") {
		return pinnedRegistrationPath{}, fmt.Errorf("invalid uid component")
	}
	supervisorParts := strings.Split(strings.TrimPrefix(parts[2], "supervisor-"), "-")
	if len(supervisorParts) != 2 || !strings.HasPrefix(parts[2], "supervisor-") {
		return pinnedRegistrationPath{}, fmt.Errorf("invalid supervisor component")
	}
	pid, err := strconv.Atoi(supervisorParts[0])
	if err != nil || pid <= 0 {
		return pinnedRegistrationPath{}, fmt.Errorf("invalid supervisor pid")
	}
	startTime, err := strconv.ParseUint(supervisorParts[1], 16, 64)
	if err != nil || startTime == 0 {
		return pinnedRegistrationPath{}, fmt.Errorf("invalid supervisor start time")
	}
	sessionBytes, err := hex.DecodeString(strings.TrimPrefix(parts[4], "session-"))
	if err != nil || !strings.HasPrefix(parts[4], "session-") {
		return pinnedRegistrationPath{}, fmt.Errorf("invalid session component")
	}
	sessionID := string(sessionBytes)
	if err := validateID("session_id", sessionID); err != nil {
		return pinnedRegistrationPath{}, err
	}
	cgroupID, err := strconv.ParseUint(strings.TrimPrefix(parts[5], "cgroup-"), 16, 64)
	if err != nil || cgroupID == 0 || !strings.HasPrefix(parts[5], "cgroup-") {
		return pinnedRegistrationPath{}, fmt.Errorf("invalid cgroup component")
	}
	return pinnedRegistrationPath{
		Path:                filepath.Clean(path),
		UID:                 uint32(uidValue),
		SupervisorPID:       pid,
		SupervisorStartTime: startTime,
		SessionID:           sessionID,
		CgroupID:            cgroupID,
	}, nil
}

func pinnedSupervisorDead(reg pinnedRegistrationPath) (bool, error) {
	currentStart, startErr := procStartTime(reg.SupervisorPID)
	switch {
	case startErr == nil && currentStart == reg.SupervisorStartTime:
		return false, nil
	case startErr == nil && currentStart != reg.SupervisorStartTime:
		return true, nil
	case errors.Is(startErr, os.ErrNotExist), errors.Is(startErr, syscall.ESRCH):
		return true, nil
	default:
		return false, fmt.Errorf("cannot prove supervisor identity dead: %w", startErr)
	}
}

func pinnedRegistrationReapable(reg pinnedRegistrationPath) (bool, string, error) {
	cgroupPath, found, err := findCgroupPathByID(reg.CgroupID)
	if err != nil {
		return false, "", err
	}
	if !found {
		return true, "command cgroup is gone", nil
	}
	populated, err := (kernelCgroupResolver{}).CgroupPopulated(cgroupPath)
	if err != nil {
		return false, "", err
	}
	supervisorDead, identityErr := pinnedSupervisorDead(reg)
	if !populated {
		if identityErr == nil && supervisorDead {
			return true, "command cgroup is unpopulated and supervisor identity is dead", nil
		}
		return false, "unpopulated cgroup is retained for its live supervisor", nil
	}
	if identityErr == nil && supervisorDead {
		return false, "command cgroup remains populated after supervisor exit", nil
	}
	return false, "command cgroup remains populated", nil
}

// ReapOrphanedResources removes validated pin trees which aren't owned by an
// in-memory registration and whose command cgroup is gone or unpopulated. A
// populated command cgroup is retained even after supervisor death. The backend
// mutex excludes a racing re-registration while links are validated and unpinned.
func (b *KernelBackend) ReapOrphanedResources(ctx context.Context) error {
	if b == nil || !b.opts.EnforceTargetUID || strings.TrimSpace(b.opts.PinRoot) == "" {
		return nil
	}
	opts := PinCleanupOptions{
		PinRoot:          b.opts.PinRoot,
		TargetUID:        b.opts.TargetUID,
		EnforceTargetUID: true,
		OwnerUID:         b.opts.PinOwnerUID,
	}
	root := filepath.Clean(strings.TrimSpace(opts.PinRoot))
	if err := validatePinRoot(root); err != nil {
		return err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat orphan pin root: %w", err)
	}
	if err := validateOwnedPinPath(root, rootInfo, opts.OwnerUID, true); err != nil {
		return err
	}
	if err := validateResolvedPinRoot(root); err != nil {
		return err
	}
	if err := validateBPFFSMount(root); err != nil {
		return err
	}
	registrations, _, err := discoverPinnedRegistrations(root, opts)
	if err != nil {
		return err
	}
	for _, reg := range registrations {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		reapable, _, err := pinnedRegistrationReapable(reg)
		if err != nil || !reapable {
			continue
		}

		b.mu.Lock()
		if b.byID[reg.CgroupID] != "" || b.reserved[reg.CgroupID] {
			b.mu.Unlock()
			continue
		}
		reapable, _, err = pinnedRegistrationReapable(reg)
		if err != nil || !reapable {
			b.mu.Unlock()
			continue
		}
		attachment, _, validateErr := loadPinnedCgroupAttachment(reg.Path, reg.CgroupID, opts.OwnerUID)
		if attachment != nil {
			closeAttachmentRefs(attachment)
		}
		if validateErr != nil {
			b.mu.Unlock()
			continue
		}
		_, removeErr := removePinTree(reg.Path, false)
		if removeErr == nil {
			removeErr = removeEmptyPinDirectories(root, reg.Path)
		}
		b.mu.Unlock()
		if removeErr != nil {
			return removeErr
		}
	}
	return nil
}

func findCgroupPathByID(cgroupID uint64) (string, bool, error) {
	root := cgroupV2Root()
	var found string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsPermission(walkErr) {
				return filepath.SkipDir
			}
			return walkErr
		}
		if !entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if ok && stat != nil && stat.Ino == cgroupID {
			found = path
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		return "", false, fmt.Errorf("scan cgroup hierarchy for id %d: %w", cgroupID, err)
	}
	return found, found != "", nil
}

func removePinTree(root string, dryRun bool) ([]string, error) {
	var files []string
	var dirs []string
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if entry.IsDir() {
			dirs = append(dirs, path)
		} else {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("walk pin tree %s: %w", root, err)
	}
	sort.SliceStable(files, func(i, j int) bool {
		leftLink := filepath.Base(filepath.Dir(files[i])) == "links"
		rightLink := filepath.Base(filepath.Dir(files[j])) == "links"
		if leftLink != rightLink {
			return leftLink
		}
		return files[i] < files[j]
	})
	sort.Sort(sort.Reverse(sort.StringSlice(dirs)))
	paths := append(append([]string{}, files...), dirs...)
	paths = append(paths, root)
	for _, path := range paths {
		if dryRun {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return paths, fmt.Errorf("remove pinned resource %s: %w", path, err)
		}
	}
	return paths, nil
}
