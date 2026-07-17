package nethelper

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// CgroupResolver performs kernel-backed cgroup identity checks for the helper
// authorizer. The Linux implementation reads /proc/<pid>/cgroup, resolves
// cgroupfs paths, and compares cgroup directories with os.SameFile.
type CgroupResolver interface {
	CgroupPathForPID(pid int) (string, error)
	CanonicalCgroupPath(path string) (string, error)
	SameCgroupPath(a, b string) (bool, error)
	CgroupPathContains(parent, child string) (bool, error)
}

type cgroupPopulationResolver interface {
	CgroupPopulated(path string) (bool, error)
}

type cgroupIdentityResolver interface {
	CgroupID(path string) (uint64, error)
}

// SupervisorAuthorizerOptions configures the supervisor authorizer used by
// privileged-helper deployments. A non-empty HelperInstanceCredential is
// required before registration can succeed.
type SupervisorAuthorizerOptions struct {
	HelperInstanceCredential string
	// SessionNonce is the deprecated option spelling. It remains source
	// compatible with version-1 callers but has helper-instance semantics.
	SessionNonce string

	// ExpectedUID/GID are enforced only when the corresponding Enforce flag is
	// true. Production per-user helpers must set ExpectedUID.
	ExpectedUID uint32
	EnforceUID  bool
	ExpectedGID uint32
	EnforceGID  bool

	// RequireKernelCgroupChecks verifies real cgroup identities and containment.
	RequireKernelCgroupChecks bool
	CgroupResolver            CgroupResolver

	// RequireStableProcessIdentity retains a pidfd where possible and always
	// verifies PID plus /proc start time. Kernel cgroup checks imply this option
	// so production helpers cannot accidentally fall back to PID-only identity.
	RequireStableProcessIdentity bool
}

// SupervisorAuthorizer records exact supervisor/process/cgroup registrations.
// Update and cleanup requests must match the helper-selected registration ID,
// cgroup ID, cgroup path, mode, peer credentials, and process lifetime. Legacy
// version-1 session_nonce peers omit only the opaque registration ID; all stable
// process and cgroup identity checks remain mandatory for them.
type SupervisorAuthorizer struct {
	opts SupervisorAuthorizerOptions

	mu            sync.Mutex
	operations    *OperationGate
	registrations map[string]*supervisorRegistration
	pathOwners    map[string]string
	cgroupOwners  map[uint64]string
}

type supervisorRegistration struct {
	SessionID                 string
	RegistrationID            string
	SupervisorPID             int
	SupervisorUID             uint32
	SupervisorGID             uint32
	SupervisorCgroupPath      string
	SupervisorCgroupID        uint64
	CgroupPath                string
	AuthorizedCgroupID        uint64
	CgroupID                  uint64
	Mode                      BuiltinMode
	LegacyWire                bool
	Identity                  *processIdentity
	Active                    bool
	CleanupPending            bool
	FailedRegistrationCleanup bool
	InFlight                  int
}

// NewSupervisorAuthorizer constructs a fail-closed production authorizer when
// kernel cgroup and stable-process checks are enabled. Lexical/PID-only mode is
// retained solely for controlled tests and compatibility harnesses.
func NewSupervisorAuthorizer(opts SupervisorAuthorizerOptions) *SupervisorAuthorizer {
	return &SupervisorAuthorizer{
		opts:          opts,
		operations:    NewOperationGate(),
		registrations: make(map[string]*supervisorRegistration),
		pathOwners:    make(map[string]string),
		cgroupOwners:  make(map[uint64]string),
	}
}

// AdmitLifecycleOperation shares one admission state machine with instance
// release. Dispatch must hold the returned admission through backend completion.
func (a *SupervisorAuthorizer) AdmitLifecycleOperation() (func(), error) {
	if a == nil {
		return nil, fmt.Errorf("nethelper supervisor authorizer is nil")
	}
	return a.operations.Admit()
}

func (a *SupervisorAuthorizer) OperationGate() *OperationGate {
	if a == nil {
		return nil
	}
	return a.operations
}

func (a *SupervisorAuthorizer) AuthorizeRegister(_ context.Context, peer PeerInfo, req RegisterSessionCgroupRequest) error {
	if a == nil {
		return fmt.Errorf("nethelper supervisor authorizer is nil")
	}
	if err := req.Validate(); err != nil {
		return err
	}
	if err := a.authorizePeer(peer, req.SupervisorPID); err != nil {
		return err
	}
	if strings.TrimSpace(a.opts.HelperInstanceCredential) != "" && strings.TrimSpace(req.HelperInstanceCredential) == "" {
		return fmt.Errorf("helper_instance_credential is required by this helper instance")
	}
	if err := a.authorizeCredential(requestHelperCredential(req)); err != nil {
		return err
	}
	if strings.TrimSpace(req.SupervisorCgroupPath) == "" {
		return fmt.Errorf("supervisor_cgroup_path is required for helper authorization")
	}

	supervisorPath, targetPath, err := a.authorizeCgroupRegistration(peer, req)
	if err != nil {
		return err
	}
	var supervisorCgroupID uint64
	var targetCgroupID uint64
	if a.opts.RequireKernelCgroupChecks {
		identityResolver, ok := a.resolver().(cgroupIdentityResolver)
		if !ok {
			return fmt.Errorf("kernel cgroup identity checks are unavailable")
		}
		supervisorCgroupID, err = identityResolver.CgroupID(supervisorPath)
		if err != nil {
			return fmt.Errorf("capture supervisor cgroup identity: %w", err)
		}
		targetCgroupID, err = identityResolver.CgroupID(targetPath)
		if err != nil {
			return fmt.Errorf("capture target cgroup identity: %w", err)
		}
	}
	identity, err := a.captureStableIdentity(peer)
	if err != nil {
		return err
	}
	registrationID, err := newRegistrationID()
	if err != nil {
		if identity != nil {
			identity.close()
		}
		return err
	}

	reg := &supervisorRegistration{
		SessionID:            strings.TrimSpace(req.SessionID),
		RegistrationID:       registrationID,
		SupervisorPID:        req.SupervisorPID,
		SupervisorUID:        peer.UID,
		SupervisorGID:        peer.GID,
		SupervisorCgroupPath: supervisorPath,
		SupervisorCgroupID:   supervisorCgroupID,
		CgroupPath:           targetPath,
		AuthorizedCgroupID:   targetCgroupID,
		Mode:                 req.Mode.Normalized(),
		LegacyWire:           strings.TrimSpace(req.HelperInstanceCredential) == "" && strings.TrimSpace(req.SessionNonce) != "",
		Identity:             identity,
	}
	key := registrationKey(req.SessionID, targetPath)
	a.mu.Lock()
	if _, exists := a.registrations[key]; exists {
		a.mu.Unlock()
		if identity != nil {
			identity.close()
		}
		return fmt.Errorf("session cgroup is already registered with this helper")
	}
	if owner, exists := a.pathOwners[targetPath]; exists && owner != key {
		a.mu.Unlock()
		if identity != nil {
			identity.close()
		}
		return fmt.Errorf("target cgroup is already registered with this helper")
	}
	a.registrations[key] = reg
	a.pathOwners[targetPath] = key
	a.mu.Unlock()
	return nil
}

func (a *SupervisorAuthorizer) AuthorizeUpdate(_ context.Context, peer PeerInfo, req UpdatePolicyMapRequest) error {
	if a == nil {
		return fmt.Errorf("nethelper supervisor authorizer is nil")
	}
	if err := req.Validate(); err != nil {
		return err
	}
	reg, key, err := a.registeredRequestWithKey(req.SessionID, req.CgroupPath, req.CgroupID, req.RegistrationID)
	if err != nil {
		return err
	}
	a.mu.Lock()
	if a.registrations[key] != reg || reg.CleanupPending {
		a.mu.Unlock()
		return fmt.Errorf("session cgroup is not registered with this helper")
	}
	reg.InFlight++
	a.mu.Unlock()
	if req.Mode.Normalized() != reg.Mode {
		a.CompleteUpdate(req)
		return fmt.Errorf("mode does not match registered session cgroup")
	}
	if err := a.authorizeRegisteredPeer(peer, reg); err != nil {
		a.CompleteUpdate(req)
		return err
	}
	return nil
}

func (a *SupervisorAuthorizer) AuthorizeCleanup(_ context.Context, peer PeerInfo, req CleanupSessionRequest) error {
	if a == nil {
		return fmt.Errorf("nethelper supervisor authorizer is nil")
	}
	if err := req.Validate(); err != nil {
		return err
	}
	reg, key, err := a.registeredRequestWithKey(req.SessionID, req.CgroupPath, req.CgroupID, req.RegistrationID)
	if err != nil {
		return err
	}
	if err := a.authorizeRegisteredPeer(peer, reg); err != nil {
		return err
	}
	a.mu.Lock()
	current, ok := a.registrations[key]
	if !ok || current != reg || current.CleanupPending || current.InFlight != 0 {
		a.mu.Unlock()
		return fmt.Errorf("session cgroup is not registered with this helper (cleanup pending)")
	}
	current.CleanupPending = true
	a.mu.Unlock()
	return nil
}

func (a *SupervisorAuthorizer) authorizePeer(peer PeerInfo, supervisorPID int) error {
	if !peer.Supported {
		return fmt.Errorf("peer credentials are required for helper authorization")
	}
	if peer.PID <= 0 {
		return fmt.Errorf("peer pid is unavailable")
	}
	if supervisorPID <= 0 {
		return fmt.Errorf("supervisor_pid is required for helper authorization")
	}
	if peer.PID != supervisorPID {
		return fmt.Errorf("peer pid does not match supervisor_pid")
	}
	if a.opts.EnforceUID && peer.UID != a.opts.ExpectedUID {
		return fmt.Errorf("peer uid is not authorized")
	}
	if a.opts.EnforceGID && peer.GID != a.opts.ExpectedGID {
		return fmt.Errorf("peer gid is not authorized")
	}
	return nil
}

func (a *SupervisorAuthorizer) authorizeRegisteredPeer(peer PeerInfo, reg *supervisorRegistration) error {
	if reg == nil {
		return fmt.Errorf("session cgroup is not registered with this helper")
	}
	if err := a.authorizePeer(peer, reg.SupervisorPID); err != nil {
		return err
	}
	if peer.UID != reg.SupervisorUID {
		return fmt.Errorf("peer uid does not match registered supervisor")
	}
	if peer.GID != reg.SupervisorGID {
		return fmt.Errorf("peer gid does not match registered supervisor")
	}
	if a.stableProcessIdentityRequired() {
		if reg.Identity == nil {
			return fmt.Errorf("registered supervisor has no stable process identity")
		}
		if err := reg.Identity.validate(); err != nil {
			return err
		}
		if peer.identity == nil || peer.ProcessStartTime == 0 {
			return fmt.Errorf("current peer stable process identity is unavailable")
		}
		if peer.ProcessStartTime != reg.Identity.startTime {
			return fmt.Errorf("peer process lifetime does not match registered supervisor")
		}
	}
	if a.opts.RequireKernelCgroupChecks {
		resolver := a.resolver()
		peerPath, err := resolver.CgroupPathForPID(peer.PID)
		if err != nil {
			return fmt.Errorf("read peer cgroup: %w", err)
		}
		if ok, err := peerInSupervisorCgroup(resolver, peerPath, reg.SupervisorCgroupPath); err != nil {
			return fmt.Errorf("verify peer cgroup: %w", err)
		} else if !ok {
			return fmt.Errorf("peer cgroup does not match registered supervisor cgroup")
		}
		identityResolver, ok := resolver.(cgroupIdentityResolver)
		if !ok {
			return fmt.Errorf("kernel cgroup identity checks are unavailable")
		}
		currentSupervisorID, err := identityResolver.CgroupID(reg.SupervisorCgroupPath)
		if err != nil {
			return fmt.Errorf("revalidate supervisor cgroup id: %w", err)
		}
		if currentSupervisorID != reg.SupervisorCgroupID {
			return fmt.Errorf("supervisor cgroup id changed after registration")
		}
		currentTarget, err := resolver.CanonicalCgroupPath(reg.CgroupPath)
		if err != nil {
			return fmt.Errorf("revalidate target cgroup: %w", err)
		}
		if currentTarget != reg.CgroupPath {
			return fmt.Errorf("target cgroup path changed after registration")
		}
		currentID, err := identityResolver.CgroupID(currentTarget)
		if err != nil {
			return fmt.Errorf("revalidate target cgroup id: %w", err)
		}
		if currentID != reg.CgroupID {
			return fmt.Errorf("target cgroup id changed after registration")
		}
	}
	return nil
}

func (a *SupervisorAuthorizer) authorizeCredential(got string) error {
	expected := strings.TrimSpace(a.opts.HelperInstanceCredential)
	if expected == "" {
		expected = strings.TrimSpace(a.opts.SessionNonce)
	}
	if expected == "" {
		return fmt.Errorf("expected helper instance credential is not configured")
	}
	got = strings.TrimSpace(got)
	if got == "" {
		return fmt.Errorf("helper_instance_credential is required for helper authorization")
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
		return fmt.Errorf("helper instance credential is not authorized")
	}
	return nil
}

func requestHelperCredential(req RegisterSessionCgroupRequest) string {
	if value := strings.TrimSpace(req.HelperInstanceCredential); value != "" {
		return value
	}
	return strings.TrimSpace(req.SessionNonce)
}

// ActiveRegistrationCount reports pending, active, or cleanup-pending command
// registrations. Ephemeral instance release is allowed only when this is zero.
func (a *SupervisorAuthorizer) ActiveRegistrationCount() int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.registrations)
}

func (a *SupervisorAuthorizer) stableProcessIdentityRequired() bool {
	return a != nil && (a.opts.RequireStableProcessIdentity || a.opts.RequireKernelCgroupChecks)
}

func (a *SupervisorAuthorizer) captureStableIdentity(peer PeerInfo) (*processIdentity, error) {
	if !a.stableProcessIdentityRequired() {
		return nil, nil
	}
	if peer.identity == nil || peer.ProcessStartTime == 0 {
		return nil, fmt.Errorf("stable peer process identity is required for helper authorization")
	}
	identity, err := peer.identity.clone()
	if err != nil {
		return nil, fmt.Errorf("retain peer process identity: %w", err)
	}
	if identity.pid != peer.PID || identity.startTime != peer.ProcessStartTime {
		identity.close()
		return nil, fmt.Errorf("peer process identity changed during registration")
	}
	return identity, nil
}

func (a *SupervisorAuthorizer) authorizeCgroupRegistration(peer PeerInfo, req RegisterSessionCgroupRequest) (string, string, error) {
	if a.opts.RequireKernelCgroupChecks {
		resolver := a.resolver()
		peerPath, err := resolver.CgroupPathForPID(peer.PID)
		if err != nil {
			return "", "", fmt.Errorf("read peer cgroup: %w", err)
		}
		supervisorPath, err := resolver.CanonicalCgroupPath(req.SupervisorCgroupPath)
		if err != nil {
			return "", "", fmt.Errorf("verify supervisor cgroup: %w", err)
		}
		targetPath, err := resolver.CanonicalCgroupPath(req.CgroupPath)
		if err != nil {
			return "", "", fmt.Errorf("verify target cgroup: %w", err)
		}
		if ok, err := peerInSupervisorCgroup(resolver, peerPath, supervisorPath); err != nil {
			return "", "", fmt.Errorf("verify peer cgroup: %w", err)
		} else if !ok {
			return "", "", fmt.Errorf("peer cgroup does not match supervisor_cgroup_path")
		}
		inside, err := resolver.CgroupPathContains(supervisorPath, targetPath)
		if err != nil {
			return "", "", fmt.Errorf("verify delegated subtree: %w", err)
		}
		if !inside {
			return "", "", fmt.Errorf("target cgroup is not inside supervisor delegated subtree")
		}
		return supervisorPath, targetPath, nil
	}

	if !cgroupPathContains(req.SupervisorCgroupPath, req.CgroupPath) {
		return "", "", fmt.Errorf("target cgroup is not inside supervisor delegated subtree")
	}
	return cleanCgroupPath(req.SupervisorCgroupPath), cleanCgroupPath(req.CgroupPath), nil
}

func (a *SupervisorAuthorizer) canonicalLookupPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("cgroup_path is required for authorized helper operations")
	}
	if a.opts.RequireKernelCgroupChecks {
		return a.resolver().CanonicalCgroupPath(path)
	}
	return cleanCgroupPath(path), nil
}

func (a *SupervisorAuthorizer) resolver() CgroupResolver {
	if a != nil && a.opts.CgroupResolver != nil {
		return a.opts.CgroupResolver
	}
	return defaultCgroupResolver()
}

// CompleteRegister binds the backend-observed cgroup ID to the pending
// authorization and returns the helper-selected registration handle.
func (a *SupervisorAuthorizer) CompleteRegister(req RegisterSessionCgroupRequest, cgroupID uint64) (string, error) {
	if a == nil || cgroupID == 0 {
		return "", fmt.Errorf("backend returned an invalid cgroup id")
	}
	path, err := a.canonicalLookupPath(req.CgroupPath)
	if err != nil {
		return "", err
	}
	supervisorPath := cleanCgroupPath(req.SupervisorCgroupPath)
	if a.opts.RequireKernelCgroupChecks {
		supervisorPath, err = a.resolver().CanonicalCgroupPath(req.SupervisorCgroupPath)
		if err != nil {
			return "", fmt.Errorf("revalidate supervisor cgroup: %w", err)
		}
		identityResolver, ok := a.resolver().(cgroupIdentityResolver)
		if !ok {
			return "", fmt.Errorf("kernel cgroup identity checks are unavailable")
		}
		currentID, err := identityResolver.CgroupID(path)
		if err != nil {
			return "", fmt.Errorf("revalidate registered cgroup id: %w", err)
		}
		if currentID != cgroupID {
			return "", fmt.Errorf("backend cgroup id does not match authorized target cgroup")
		}
	}

	key := registrationKey(req.SessionID, path)
	a.mu.Lock()
	defer a.mu.Unlock()
	reg, ok := a.registrations[key]
	if !ok || reg.Active || reg.CleanupPending {
		return "", fmt.Errorf("pending session cgroup registration was not found")
	}
	if reg.SessionID != strings.TrimSpace(req.SessionID) || reg.SupervisorPID != req.SupervisorPID || reg.SupervisorCgroupPath != supervisorPath || reg.CgroupPath != path || reg.Mode != req.Mode.Normalized() {
		return "", fmt.Errorf("pending registration identity changed before backend completion")
	}
	if a.opts.RequireKernelCgroupChecks {
		identityResolver := a.resolver().(cgroupIdentityResolver)
		currentSupervisorID, err := identityResolver.CgroupID(supervisorPath)
		if err != nil {
			return "", fmt.Errorf("revalidate supervisor cgroup id: %w", err)
		}
		if currentSupervisorID != reg.SupervisorCgroupID || cgroupID != reg.AuthorizedCgroupID {
			return "", fmt.Errorf("authorized cgroup identity changed before backend completion")
		}
	}
	if a.stableProcessIdentityRequired() {
		if reg.Identity == nil {
			return "", fmt.Errorf("pending registration has no stable process identity")
		}
		if err := reg.Identity.validate(); err != nil {
			return "", err
		}
	}
	if owner, exists := a.cgroupOwners[cgroupID]; exists && owner != key {
		return "", fmt.Errorf("cgroup id is already registered with this helper")
	}
	reg.CgroupID = cgroupID
	reg.Active = true
	a.cgroupOwners[cgroupID] = key
	return reg.RegistrationID, nil
}

// PreserveFailedRegister records a backend attachment whose registration
// completion failed. Admission must remain dirty until compensation is proven
// successful; otherwise authenticated cleanup and the reaper retain the exact
// registration, process, path, and cgroup identities needed for a later retry.
func (a *SupervisorAuthorizer) PreserveFailedRegister(req RegisterSessionCgroupRequest, cgroupID uint64) (string, error) {
	if a == nil || cgroupID == 0 {
		return "", fmt.Errorf("cannot preserve failed registration without a cgroup id")
	}
	path, err := a.canonicalLookupPath(req.CgroupPath)
	if err != nil {
		return "", err
	}
	key := registrationKey(req.SessionID, path)
	a.mu.Lock()
	defer a.mu.Unlock()
	reg := a.registrations[key]
	if reg == nil || reg.Active || reg.CleanupPending {
		return "", fmt.Errorf("pending failed registration was not found")
	}
	reg.CgroupID = cgroupID
	reg.Active = true
	reg.FailedRegistrationCleanup = true
	// A conflicting backend cgroup id may be the reason completion failed. Do
	// not displace the established owner, but retain this path-keyed tombstone.
	if _, exists := a.cgroupOwners[cgroupID]; !exists {
		a.cgroupOwners[cgroupID] = key
	}
	return reg.RegistrationID, nil
}

// RollbackRegister forgets an authorization whose backend attach failed, or
// whose compensating backend cleanup has been proven successful.
func (a *SupervisorAuthorizer) RollbackRegister(sessionID, cgroupPath string) {
	if a == nil {
		return
	}
	lookupPath, err := a.canonicalLookupPath(cgroupPath)
	if err != nil {
		lookupPath = cleanCgroupPath(cgroupPath)
	}
	a.removeRegistration(registrationKey(sessionID, lookupPath))
}

// CompleteUpdate releases the update reservation established by
// AuthorizeUpdate. Server dispatch invokes it after every backend outcome.
func (a *SupervisorAuthorizer) CompleteUpdate(req UpdatePolicyMapRequest) {
	if a == nil {
		return
	}
	a.mu.Lock()
	reg, _ := a.registrationForCompletionLocked(req.SessionID, req.CgroupPath, req.CgroupID, req.RegistrationID)
	if reg != nil && reg.InFlight > 0 {
		reg.InFlight--
	}
	a.mu.Unlock()
}

// CompleteCleanup commits successful backend cleanup or restores authorization
// after a backend failure so cleanup can be retried.
func (a *SupervisorAuthorizer) CompleteCleanup(req CleanupSessionRequest, succeeded bool) {
	if a == nil {
		return
	}
	a.mu.Lock()
	reg, key := a.registrationForCompletionLocked(req.SessionID, req.CgroupPath, req.CgroupID, req.RegistrationID)
	if reg == nil {
		a.mu.Unlock()
		return
	}
	if !succeeded {
		reg.CleanupPending = false
		a.mu.Unlock()
		return
	}
	delete(a.registrations, key)
	if a.pathOwners[reg.CgroupPath] == key {
		delete(a.pathOwners, reg.CgroupPath)
	}
	if a.cgroupOwners[reg.CgroupID] == key {
		delete(a.cgroupOwners, reg.CgroupID)
	}
	a.mu.Unlock()
	if reg.Identity != nil {
		reg.Identity.close()
	}
}

func (a *SupervisorAuthorizer) registrationForCompletionLocked(sessionID, cgroupPath string, cgroupID uint64, registrationID string) (*supervisorRegistration, string) {
	if cgroupID == 0 {
		return nil, ""
	}
	key := registrationKey(sessionID, cleanCgroupPath(cgroupPath))
	reg := a.registrations[key]
	if reg == nil || reg.SessionID != strings.TrimSpace(sessionID) || reg.CgroupID != cgroupID || reg.CgroupPath != cleanCgroupPath(cgroupPath) {
		return nil, ""
	}
	registrationID = strings.TrimSpace(registrationID)
	if registrationID == "" {
		if !reg.LegacyWire {
			return nil, ""
		}
	} else if subtle.ConstantTimeCompare([]byte(registrationID), []byte(reg.RegistrationID)) != 1 {
		return nil, ""
	}
	return reg, key
}

func (a *SupervisorAuthorizer) registeredRequest(sessionID, cgroupPath string, cgroupID uint64, registrationID string) (*supervisorRegistration, error) {
	reg, _, err := a.registeredRequestWithKey(sessionID, cgroupPath, cgroupID, registrationID)
	return reg, err
}

func (a *SupervisorAuthorizer) registeredRequestWithKey(sessionID, cgroupPath string, cgroupID uint64, registrationID string) (*supervisorRegistration, string, error) {
	path, err := a.canonicalLookupPath(cgroupPath)
	if err != nil {
		return nil, "", err
	}
	key := registrationKey(sessionID, path)
	a.mu.Lock()
	reg, ok := a.registrations[key]
	if !ok || !reg.Active || reg.CleanupPending {
		a.mu.Unlock()
		return nil, "", fmt.Errorf("session cgroup is not registered with this helper")
	}
	if cgroupID == 0 || cgroupID != reg.CgroupID {
		a.mu.Unlock()
		return nil, "", fmt.Errorf("cgroup_id does not match registered session cgroup")
	}
	registrationID = strings.TrimSpace(registrationID)
	if registrationID == "" {
		if !reg.LegacyWire {
			a.mu.Unlock()
			return nil, "", fmt.Errorf("registration_id does not match registered session cgroup")
		}
	} else if subtle.ConstantTimeCompare([]byte(registrationID), []byte(reg.RegistrationID)) != 1 {
		a.mu.Unlock()
		return nil, "", fmt.Errorf("registration_id does not match registered session cgroup")
	}
	a.mu.Unlock()
	return reg, key, nil
}

func (a *SupervisorAuthorizer) removeRegistration(key string) {
	a.mu.Lock()
	reg := a.registrations[key]
	if reg != nil {
		delete(a.registrations, key)
		if a.pathOwners[reg.CgroupPath] == key {
			delete(a.pathOwners, reg.CgroupPath)
		}
		if a.cgroupOwners[reg.CgroupID] == key {
			delete(a.cgroupOwners, reg.CgroupID)
		}
	}
	a.mu.Unlock()
	if reg != nil && reg.Identity != nil {
		reg.Identity.close()
	}
}

// ReapableRegistrations marks registrations whose command cgroup is proven
// gone/unpopulated. A dead supervisor alone is not enough to detach an active
// gate: populated command cgroups remain pinned and fail closed.
func (a *SupervisorAuthorizer) ReapableRegistrations() []CleanupSessionRequest {
	if a == nil || !a.opts.RequireKernelCgroupChecks {
		return nil
	}
	resolver := a.resolver()
	population, ok := resolver.(cgroupPopulationResolver)
	if !ok {
		return nil
	}
	identityResolver, ok := resolver.(cgroupIdentityResolver)
	if !ok {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var requests []CleanupSessionRequest
	for _, reg := range a.registrations {
		if reg == nil || !reg.Active || reg.CleanupPending || reg.InFlight != 0 {
			continue
		}
		if reg.FailedRegistrationCleanup {
			reg.CleanupPending = true
			requests = append(requests, CleanupSessionRequest{
				ProtocolVersion: CurrentProtocolVersion,
				RequestID:       "reap-" + reg.RegistrationID,
				SessionID:       reg.SessionID,
				RegistrationID:  reg.RegistrationID,
				CgroupID:        reg.CgroupID,
				CgroupPath:      reg.CgroupPath,
				Reason:          CleanupReasonRegistrationFailed,
			})
			continue
		}
		currentID, identityErr := identityResolver.CgroupID(reg.CgroupPath)
		populated := false
		if identityErr == nil && currentID == reg.CgroupID {
			var err error
			populated, err = population.CgroupPopulated(reg.CgroupPath)
			if err != nil {
				continue
			}
		} else if identityErr != nil {
			var err error
			populated, err = population.CgroupPopulated(reg.CgroupPath)
			if err != nil {
				continue
			}
		}
		if populated {
			continue
		}
		reason := CleanupReasonSessionEnded
		if reg.Identity != nil && !reg.Identity.alive() {
			reason = CleanupReasonOrphanReaped
		}
		reg.CleanupPending = true
		requests = append(requests, CleanupSessionRequest{
			ProtocolVersion: CurrentProtocolVersion,
			SessionID:       reg.SessionID,
			RegistrationID:  reg.RegistrationID,
			CgroupID:        reg.CgroupID,
			CgroupPath:      reg.CgroupPath,
			Reason:          reason,
		})
	}
	sort.Slice(requests, func(i, j int) bool {
		if requests[i].SessionID != requests[j].SessionID {
			return requests[i].SessionID < requests[j].SessionID
		}
		return requests[i].CgroupPath < requests[j].CgroupPath
	})
	return requests
}

// Close releases retained pidfds. It does not detach backend resources.
func (a *SupervisorAuthorizer) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	regs := a.registrations
	a.registrations = make(map[string]*supervisorRegistration)
	a.pathOwners = make(map[string]string)
	a.cgroupOwners = make(map[uint64]string)
	a.mu.Unlock()
	for _, reg := range regs {
		if reg != nil && reg.Identity != nil {
			reg.Identity.close()
		}
	}
}

func peerInSupervisorCgroup(resolver CgroupResolver, peerPath, supervisorPath string) (bool, error) {
	same, err := resolver.SameCgroupPath(peerPath, supervisorPath)
	if err != nil {
		return false, err
	}
	if same {
		return true, nil
	}
	peerCanonical, err := resolver.CanonicalCgroupPath(peerPath)
	if err != nil {
		return false, err
	}
	supervisorCanonical, err := resolver.CanonicalCgroupPath(supervisorPath)
	if err != nil {
		return false, err
	}
	return filepath.Base(peerCanonical) == "agentsh.leaf" && filepath.Dir(peerCanonical) == supervisorCanonical, nil
}

func registrationKey(sessionID, cgroupPath string) string {
	return strings.TrimSpace(sessionID) + "\x00" + cleanCgroupPath(cgroupPath)
}

func sessionIDFromRegistrationKey(key string) string {
	if index := strings.IndexByte(key, 0); index >= 0 {
		return key[:index]
	}
	return ""
}

func newRegistrationID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate helper registration id: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func cgroupPathContains(parent, child string) bool {
	parent = cleanCgroupPath(parent)
	child = cleanCgroupPath(child)
	return pathInSubtree(parent, child, false)
}

func pathInSubtree(parent, child string, allowEqual bool) bool {
	parent = cleanCgroupPath(parent)
	child = cleanCgroupPath(child)
	if parent == "" || child == "" {
		return false
	}
	if parent == child {
		return allowEqual
	}
	rel, err := filepath.Rel(parent, child)
	if err != nil || rel == "." || rel == ".." {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func cleanCgroupPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	return filepath.Clean(path)
}
