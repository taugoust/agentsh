package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/nethelper"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

const (
	nethelperLifecycleSchemaVersion = 1
	nethelperRecoveryHeader         = "X-AgentSH-Nethelper-Recovery"
)

func readRecoveryTokenFile(path string) (string, string) {
	path = strings.TrimSpace(path)
	if validateWrapperRecoveryTokenPath(path) != nil {
		return "", ""
	}
	file, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, pathInfo) || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o077 != 0 || !helperPathOwnedByCurrentUser(openedInfo) {
		return "", ""
	}
	data, err := io.ReadAll(io.LimitReader(file, 514))
	if err != nil || len(data) > 513 {
		return "", ""
	}
	defer func() {
		for i := range data {
			data[i] = 0
		}
	}()
	token := strings.TrimSpace(string(data))
	if len(token) < 32 || len(token) > 512 || strings.ContainsAny(token, " \t\r\n") {
		return "", ""
	}
	return token, path
}

func validateWrapperRecoveryTokenPath(path string) error {
	if strings.TrimSpace(path) == "" || filepath.Base(path) != nethelper.WrapperRecoveryTokenFilename {
		return fmt.Errorf("recovery token must use the fixed wrapper-owned filename")
	}
	if err := validateOwnedProtectedPath(path, false); err != nil {
		return err
	}
	container := filepath.Dir(path)
	if filepath.Base(container) != nethelper.WrapperControlDirectoryName {
		return fmt.Errorf("recovery token must use the fixed wrapper control container")
	}
	resolved, err := filepath.EvalSymlinks(container)
	if err != nil || filepath.Clean(resolved) != container {
		return fmt.Errorf("recovery token container contains a symlink component")
	}
	info, err := os.Lstat(container)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !helperPathOwnedByCurrentUser(info) {
		return fmt.Errorf("recovery token container must be a private wrapper-owned directory")
	}
	return nil
}

func (a *App) authorizeNethelperRecovery(r *http.Request) bool {
	if a == nil || r == nil || !isUnixSocketRequest(r) || a.nethelperRecoveryToken == "" {
		return false
	}
	provided := strings.TrimSpace(r.Header.Get(nethelperRecoveryHeader))
	return subtle.ConstantTimeCompare([]byte(provided), []byte(a.nethelperRecoveryToken)) == 1
}

type nethelperBinding struct {
	Kind                   string
	LeaseID                string
	UnitName               string
	UID                    uint32
	GID                    uint32
	SocketPath             string
	CredentialFile         string
	BootstrapResultPath    string
	CompositionScratchRoot string
	Credential             string
	ProtocolVersion        int
	BootstrapSchemaVersion int
	Capabilities           []string
	CreatedAt              time.Time
	SoftExpiresAt          time.Time
	HardExpiresAt          time.Time
	SoftLease              time.Duration
	RenewalRequired        bool
	Generation             uint64
	RenewalGeneration      uint64
	ActiveRegistrations    int
	LastStatus             string
	LastReason             string
	LastCheckedAt          time.Time
}

func (b nethelperBinding) clone() nethelperBinding {
	b.Capabilities = append([]string(nil), b.Capabilities...)
	return b
}

type uncertainCandidateCleanup struct {
	SessionID  string
	Binding    nethelperBinding
	Attachment *types.NetworkAttachmentEvidence
	Reason     string
	RecordedAt time.Time
}

type nethelperBindingState struct {
	mu        sync.RWMutex
	binding   nethelperBinding
	uncertain *uncertainCandidateCleanup
}

func newNethelperBindingState(socketPath, credentialFile, bootstrapPath, credential string) *nethelperBindingState {
	binding := nethelperBinding{
		SocketPath: strings.TrimSpace(socketPath), CredentialFile: strings.TrimSpace(credentialFile),
		BootstrapResultPath: strings.TrimSpace(bootstrapPath), Credential: strings.TrimSpace(credential),
		ProtocolVersion: nethelper.CurrentProtocolVersion,
	}
	if binding.BootstrapResultPath == "" && binding.SocketPath != "" {
		binding.BootstrapResultPath = filepath.Join(filepath.Dir(binding.SocketPath), "bootstrap.json")
	}
	if binding.BootstrapResultPath != "" {
		if result, err := readNethelperBootstrapResult(binding.BootstrapResultPath); err == nil &&
			result.Validate(time.Now().UTC()) == nil &&
			result.SocketPath == binding.SocketPath && result.CredentialFile == binding.CredentialFile &&
			result.ResultFile == binding.BootstrapResultPath && bootstrapResultMatchesFixedPaths(result) {
			binding.Kind = "ephemeral"
			binding.UnitName = result.UnitName
			binding.BootstrapSchemaVersion = result.BootstrapSchemaVersion
			binding.UID = result.UID
			binding.GID = result.GID
			binding.CompositionScratchRoot = result.CompositionScratchRoot
			binding.CreatedAt = result.StartedAt
			binding.HardExpiresAt = result.ExpiresAt
			binding.SoftLease = time.Duration(result.SoftLeaseSeconds) * time.Second
			binding.RenewalRequired = result.RenewalRequired
			binding.LeaseID = result.LeaseID
		}
	}
	if binding.SocketPath != "" {
		binding.Generation = 1
	}
	return &nethelperBindingState{binding: binding}
}

func (s *nethelperBindingState) snapshot() nethelperBinding {
	if s == nil {
		return nethelperBinding{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.binding.clone()
}

func (s *nethelperBindingState) replace(binding nethelperBinding) {
	s.mu.Lock()
	s.binding = binding.clone()
	s.mu.Unlock()
}

func (s *nethelperBindingState) recordUncertainCandidate(sessionID string, binding nethelperBinding, attachment *types.NetworkAttachmentEvidence, reason string) {
	if s == nil {
		return
	}
	var evidence *types.NetworkAttachmentEvidence
	if attachment != nil {
		copy := *attachment
		evidence = &copy
	}
	s.mu.Lock()
	s.uncertain = &uncertainCandidateCleanup{SessionID: strings.TrimSpace(sessionID), Binding: binding.clone(), Attachment: evidence, Reason: reason, RecordedAt: time.Now().UTC()}
	s.mu.Unlock()
}

func (s *nethelperBindingState) uncertainCandidate() *uncertainCandidateCleanup {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.uncertain == nil {
		return nil
	}
	copy := *s.uncertain
	copy.Binding = copy.Binding.clone()
	if copy.Attachment != nil {
		a := *copy.Attachment
		copy.Attachment = &a
	}
	return &copy
}

func (s *nethelperBindingState) confirmUncertainCandidateCleanup(pending *uncertainCandidateCleanup) bool {
	if s == nil || pending == nil || pending.Attachment == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.uncertain
	if current == nil || current.Attachment == nil || current.SessionID != pending.SessionID ||
		current.Binding.Generation != pending.Binding.Generation || current.Binding.LeaseID != pending.Binding.LeaseID {
		return false
	}
	got, want := current.Attachment, pending.Attachment
	if got.RegistrationID != want.RegistrationID || got.CgroupID != want.CgroupID || got.CgroupPath != want.CgroupPath {
		return false
	}
	// CleanupSession is intentionally non-idempotent. Commit this progress before
	// status is queried so a transient status failure can never cause a retry of
	// an already completed cleanup.
	current.Attachment = nil
	return true
}

func (s *nethelperBindingState) resolveUncertainCandidate(binding nethelperBinding) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.uncertain != nil && s.uncertain.Binding.Generation == binding.Generation && s.uncertain.Binding.LeaseID == binding.LeaseID {
		s.uncertain = nil
	}
	s.mu.Unlock()
}

func (s *nethelperBindingState) updateHealth(generation uint64, status nethelper.InstanceStatusResponse, checkedAt time.Time, reason string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.binding.Generation != generation {
		return
	}
	s.binding.LastCheckedAt = checkedAt
	s.binding.LastStatus = status.Status
	if s.binding.LastStatus == "" && reason != "" {
		s.binding.LastStatus = "failed"
	}
	s.binding.LastReason = status.Reason
	if s.binding.LastReason == "" {
		s.binding.LastReason = reason
	}
	if status.ProtocolVersion != 0 {
		s.binding.ProtocolVersion = status.ProtocolVersion
	}
	if len(status.Capabilities) > 0 {
		s.binding.Capabilities = append([]string(nil), status.Capabilities...)
	}
	if !status.SoftExpiresAt.IsZero() {
		s.binding.SoftExpiresAt = status.SoftExpiresAt
	}
	if !status.HardExpiresAt.IsZero() {
		s.binding.HardExpiresAt = status.HardExpiresAt
	}
	s.binding.RenewalGeneration = status.RenewalGeneration
	s.binding.ActiveRegistrations = status.ActiveRegistrationCount
}

func (s *nethelperBindingState) clearSecret() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.binding.Credential = ""
	s.mu.Unlock()
}

func readNethelperBootstrapResult(path string) (nethelper.BootstrapResult, error) {
	var result nethelper.BootstrapResult
	data, err := os.ReadFile(path)
	if err != nil {
		return result, err
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&result); err != nil {
		return result, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return result, fmt.Errorf("unexpected trailing bootstrap JSON")
		}
		return result, err
	}
	return result, nil
}

func helperPathFileLive(path string, wantSocket bool) bool {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if wantSocket {
		return info.Mode()&os.ModeSocket != 0
	}
	return info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0
}

func containsCapability(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (a *App) resolveCandidateCleanup(ctx context.Context) error {
	if a == nil || a.nethelperBinding == nil {
		return nil
	}
	pending := a.nethelperBinding.uncertainCandidate()
	if pending == nil {
		return nil
	}
	if pending.Attachment != nil {
		attachment := pending.Attachment
		if pending.SessionID == "" || attachment.RegistrationID == "" || attachment.CgroupID == 0 || strings.TrimSpace(attachment.CgroupPath) == "" {
			return fmt.Errorf("candidate cleanup tombstone lacks exact registration identity")
		}
		cleanupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		request := nethelper.CleanupSessionRequest{
			ProtocolVersion: nethelper.CurrentProtocolVersion,
			RequestID:       "candidate-cleanup-" + uuid.NewString(), SessionID: pending.SessionID,
			RegistrationID: attachment.RegistrationID, CgroupID: attachment.CgroupID, CgroupPath: attachment.CgroupPath,
			Reason: nethelper.CleanupReasonRegistrationFailed,
		}
		var resp nethelper.CleanupSessionResponse
		var cleanupErr error
		if a.nethelperCleanupForTest != nil {
			resp, cleanupErr = a.nethelperCleanupForTest(cleanupCtx, pending.Binding.clone(), request)
		} else {
			resp, cleanupErr = nethelperClientForSocket(pending.Binding.SocketPath).CleanupSession(cleanupCtx, request)
		}
		cancel()
		if cleanupErr != nil {
			return fmt.Errorf("candidate tombstone cleanup was not confirmed: %w", cleanupErr)
		}
		if !resp.OK {
			return fmt.Errorf("candidate tombstone cleanup was not confirmed")
		}
		if !a.nethelperBinding.confirmUncertainCandidateCleanup(pending) {
			return fmt.Errorf("candidate cleanup tombstone changed while cleanup was in flight")
		}
	}
	status, err := a.authenticatedNethelperStatus(ctx, pending.Binding)
	if err != nil || status.Status != "active" || status.ActiveRegistrationCount != 0 {
		if err != nil {
			return fmt.Errorf("candidate cleanup status is uncertain: %w", err)
		}
		return fmt.Errorf("candidate cleanup unresolved: status=%s active_registrations=%d", status.Status, status.ActiveRegistrationCount)
	}
	a.nethelperBinding.resolveUncertainCandidate(pending.Binding)
	return nil
}

func (a *App) nethelperBindingSnapshot() nethelperBinding {
	if a == nil || a.nethelperBinding == nil {
		return nethelperBinding{}
	}
	return a.nethelperBinding.snapshot()
}

func (a *App) authenticatedNethelperStatus(ctx context.Context, binding nethelperBinding) (nethelper.InstanceStatusResponse, error) {
	if a != nil && a.nethelperStatusForTest != nil {
		return a.nethelperStatusForTest(ctx, binding.clone())
	}
	if strings.TrimSpace(binding.SocketPath) == "" || strings.TrimSpace(binding.LeaseID) == "" || strings.TrimSpace(binding.Credential) == "" {
		return nethelper.InstanceStatusResponse{}, fmt.Errorf("ephemeral helper binding lacks socket, lease, or in-memory credential")
	}
	statusCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	client := nethelperClientForSocket(binding.SocketPath)
	return client.InstanceStatus(statusCtx, nethelper.InstanceStatusRequest{
		ProtocolVersion:          nethelper.CurrentProtocolVersion,
		RequestID:                "status-" + uuid.NewString(),
		LeaseID:                  binding.LeaseID,
		HelperInstanceCredential: binding.Credential,
	})
}

func (a *App) nethelperLifecycleEvidence(ctx context.Context) (*types.NethelperLifecycleEvidence, error) {
	binding := a.nethelperBindingSnapshot()
	if binding.SocketPath == "" {
		return nil, nil
	}
	now := time.Now().UTC()
	evidence := &types.NethelperLifecycleEvidence{
		SchemaVersion: nethelperLifecycleSchemaVersion,
		HelperKind:    binding.Kind, LeaseID: binding.LeaseID, UnitName: binding.UnitName,
		ProtocolVersion: binding.ProtocolVersion, Capabilities: append([]string(nil), binding.Capabilities...),
		SoftExpiresAt: binding.SoftExpiresAt, HardExpiresAt: binding.HardExpiresAt,
		BindingGeneration: binding.Generation, RenewalGeneration: binding.RenewalGeneration,
		ActiveRegistrationCount: binding.ActiveRegistrations,
		SocketLive:              helperPathFileLive(binding.SocketPath, true),
		CredentialSourceLive:    helperPathFileLive(binding.CredentialFile, false),
		Status:                  binding.LastStatus, TerminalReason: binding.LastReason, LastCheckedAt: binding.LastCheckedAt,
	}
	if binding.LeaseID == "" {
		evidence.Status = "legacy-unavailable"
		evidence.TerminalReason = "helper does not advertise authenticated instance lifecycle"
		evidence.LastCheckedAt = now
		return evidence, nil
	}
	status, err := a.authenticatedNethelperStatus(ctx, binding)
	evidence.LastCheckedAt = now
	if err != nil {
		a.nethelperBinding.updateHealth(binding.Generation, status, now, boundedLifecycleReason(err))
		evidence.Status = "failed"
		evidence.TerminalReason = boundedLifecycleReason(err)
		if status.Status != "" {
			evidence.Status = status.Status
		}
		if status.Reason != "" {
			evidence.TerminalReason = status.Reason
		}
		return evidence, err
	}
	a.nethelperBinding.updateHealth(binding.Generation, status, now, "")
	evidence.HelperKind = status.HelperKind
	evidence.LeaseID = status.LeaseID
	evidence.UnitName = status.UnitName
	evidence.ProtocolVersion = status.ProtocolVersion
	evidence.Capabilities = append([]string(nil), status.Capabilities...)
	evidence.SoftExpiresAt = status.SoftExpiresAt
	evidence.HardExpiresAt = status.HardExpiresAt
	evidence.RenewalGeneration = status.RenewalGeneration
	evidence.ActiveRegistrationCount = status.ActiveRegistrationCount
	evidence.Status = status.Status
	evidence.TerminalReason = status.Reason
	if remaining := status.SoftExpiresAt.Sub(now); remaining > 0 {
		evidence.SoftRemainingSeconds = int64(remaining / time.Second)
	}
	if remaining := status.HardExpiresAt.Sub(now); remaining > 0 {
		evidence.HardRemainingSeconds = int64(remaining / time.Second)
	}
	return evidence, nil
}

func boundedLifecycleReason(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}

type helperRebindRequest = types.NethelperRebindRequest

func validateOwnedProtectedPath(path string, wantSocket bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("path must be absolute and canonical")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path must not be a symlink")
	}
	if !helperPathOwnedByCurrentUser(info) {
		return fmt.Errorf("path is not owned by the supervisor uid")
	}
	if wantSocket {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("path is not a Unix socket")
		}
	} else if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("path is not a protected regular file")
	}
	return nil
}

func (a *App) loadCandidateNethelperBinding(req helperRebindRequest, generation uint64) (nethelperBinding, error) {
	if runtime.GOOS != "linux" {
		return nethelperBinding{}, fmt.Errorf("ephemeral helper rebinding is supported only on Linux")
	}
	for name, path := range map[string]string{"bootstrap_result_path": req.BootstrapResultPath, "socket_path": req.SocketPath, "credential_file": req.CredentialFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nethelperBinding{}, fmt.Errorf("%s must be absolute and canonical", name)
		}
	}
	if err := validateOwnedProtectedPath(req.BootstrapResultPath, false); err != nil {
		return nethelperBinding{}, fmt.Errorf("validate bootstrap result: %w", err)
	}
	result, err := readNethelperBootstrapResult(req.BootstrapResultPath)
	if err != nil {
		return nethelperBinding{}, fmt.Errorf("read bootstrap result: %w", err)
	}
	if err := result.Validate(time.Now().UTC()); err != nil {
		return nethelperBinding{}, err
	}
	currentUID, currentGID, identitySupported := helperCurrentUIDGID()
	if !identitySupported || result.UID != currentUID || result.GID != currentGID {
		return nethelperBinding{}, fmt.Errorf("bootstrap uid/gid does not match the supervisor")
	}
	if result.ResultFile != req.BootstrapResultPath || result.SocketPath != req.SocketPath || result.CredentialFile != req.CredentialFile {
		return nethelperBinding{}, fmt.Errorf("candidate paths do not match protected bootstrap metadata")
	}
	runtimeDir := filepath.Dir(result.SocketPath)
	if filepath.Dir(result.CredentialFile) != runtimeDir || filepath.Dir(result.ResultFile) != runtimeDir {
		return nethelperBinding{}, fmt.Errorf("candidate metadata paths do not share one protected runtime directory")
	}
	resolvedRuntimeDir, err := filepath.EvalSymlinks(runtimeDir)
	if err != nil || filepath.Clean(resolvedRuntimeDir) != runtimeDir {
		return nethelperBinding{}, fmt.Errorf("candidate runtime directory contains a symlink component")
	}
	runtimeInfo, err := os.Lstat(runtimeDir)
	if err != nil || !runtimeInfo.IsDir() || runtimeInfo.Mode()&os.ModeSymlink != 0 || runtimeInfo.Mode().Perm()&0o022 != 0 || !helperPathOwnedByUID(runtimeInfo, 0) {
		return nethelperBinding{}, fmt.Errorf("candidate runtime directory has unsafe type, mode, or ownership")
	}
	if strings.TrimSpace(req.ExpectedLeaseID) != result.LeaseID {
		return nethelperBinding{}, fmt.Errorf("candidate lease does not match expected_lease_id")
	}
	expected, err := nethelper.EphemeralPathsForUID(result.UID, result.LeaseID)
	if err != nil || expected.UnitName != result.UnitName || expected.SocketPath != result.SocketPath || expected.CredentialFile != result.CredentialFile || expected.ResultFile != result.ResultFile || expected.PinRoot != result.PinRoot || expected.CompositionScratchRoot != result.CompositionScratchRoot {
		return nethelperBinding{}, fmt.Errorf("bootstrap metadata does not match fixed helper-selected paths")
	}
	if err := validateLeaseCompositionScratchRoot(result.CompositionScratchRoot, expected.RuntimeDir); err != nil {
		return nethelperBinding{}, fmt.Errorf("validate candidate composition runtime: %w", err)
	}
	if err := validateOwnedProtectedPath(req.SocketPath, true); err != nil {
		return nethelperBinding{}, fmt.Errorf("validate candidate socket: %w", err)
	}
	if err := validateOwnedProtectedPath(req.CredentialFile, false); err != nil {
		return nethelperBinding{}, fmt.Errorf("validate candidate credential source: %w", err)
	}
	credential, err := os.ReadFile(req.CredentialFile)
	if err != nil {
		return nethelperBinding{}, fmt.Errorf("read candidate credential: %w", err)
	}
	value := strings.TrimSpace(string(credential))
	for i := range credential {
		credential[i] = 0
	}
	if len(value) < 32 || len(value) > 512 || strings.ContainsAny(value, " \t\r\n") {
		return nethelperBinding{}, fmt.Errorf("candidate credential source contains an invalid credential")
	}
	return nethelperBinding{
		Kind: "ephemeral", LeaseID: result.LeaseID, UnitName: result.UnitName,
		UID: result.UID, GID: result.GID,
		SocketPath: result.SocketPath, CredentialFile: result.CredentialFile,
		BootstrapResultPath: result.ResultFile, CompositionScratchRoot: result.CompositionScratchRoot, Credential: value,
		ProtocolVersion: result.ProtocolVersion, BootstrapSchemaVersion: result.BootstrapSchemaVersion, CreatedAt: result.StartedAt,
		HardExpiresAt: result.ExpiresAt, SoftLease: time.Duration(result.SoftLeaseSeconds) * time.Second,
		RenewalRequired: result.RenewalRequired, Generation: generation,
	}, nil
}

func bootstrapResultMatchesFixedPaths(result nethelper.BootstrapResult) bool {
	expected, err := nethelper.EphemeralPathsForUID(result.UID, result.LeaseID)
	return err == nil && expected.UnitName == result.UnitName && expected.SocketPath == result.SocketPath &&
		expected.CredentialFile == result.CredentialFile && expected.ResultFile == result.ResultFile &&
		expected.PinRoot == result.PinRoot && expected.CompositionScratchRoot == result.CompositionScratchRoot
}

func helperBindingCleanupUncertain(report *types.NetworkEnforcement) bool {
	return report != nil && report.Status == types.NetworkEnforcementStatusFailed && report.Attachment != nil && strings.TrimSpace(report.Attachment.CgroupPath) != ""
}

var errHelperGenerationConflict = errors.New("nethelper binding generation conflict")
