package approvals

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

type Emitter interface {
	AppendEvent(ctx context.Context, ev types.Event) error
	Publish(ev types.Event)
}

type Request struct {
	ID        string         `json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	ExpiresAt time.Time      `json:"expires_at"`
	SessionID string         `json:"session_id"`
	CommandID string         `json:"command_id,omitempty"`
	Kind      string         `json:"kind"` // "command" | "file" | "network"
	Target    string         `json:"target,omitempty"`
	Rule      string         `json:"rule,omitempty"`
	Message   string         `json:"message,omitempty"`
	Fields    map[string]any `json:"fields,omitempty"`
}

type Resolution struct {
	Approved bool      `json:"approved"`
	Reason   string    `json:"reason,omitempty"`
	Scope    string    `json:"scope,omitempty"`
	At       time.Time `json:"at"`

	ScopeKind      string `json:"scope_kind,omitempty"`
	ScopeKey       string `json:"scope_key,omitempty"`
	ScopeLabel     string `json:"scope_label,omitempty"`
	ScopeOperation string `json:"scope_operation,omitempty"`
	ScopePath      string `json:"scope_path,omitempty"`
	ScopeRule      string `json:"scope_rule,omitempty"`
	ScopePrefix    bool   `json:"scope_prefix,omitempty"`
}

type ScopedDecision struct {
	SessionID string     `json:"session_id"`
	Kind      string     `json:"kind"`
	Key       string     `json:"key"`
	Label     string     `json:"label,omitempty"`
	Approved  bool       `json:"approved"`
	Reason    string     `json:"reason,omitempty"`
	Rule      string     `json:"rule,omitempty"`
	Operation string     `json:"operation,omitempty"`
	Path      string     `json:"path,omitempty"`
	Prefix    bool       `json:"prefix,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type Manager struct {
	mode    string
	timeout time.Duration
	emit    Emitter

	// prompt is factored for testability; defaults to promptTTY.
	prompt func(ctx context.Context, req Request) (Resolution, error)

	// totpSecretLookup retrieves the TOTP secret for a session (TOTP mode only)
	totpSecretLookup func(sessionID string) string

	// webauthnApprover handles WebAuthn approval challenges (webauthn mode only)
	webauthnApprover *WebAuthnApprover

	requestObserver  func(context.Context, Request) error
	terminalObserver func(context.Context, Request, Resolution) error

	mu            sync.Mutex
	pending       map[string]*pending
	scoped        map[string]map[string]ScopedDecision            // sessionID -> scopeKey -> decision
	commandScoped map[string]map[string]map[string]ScopedDecision // sessionID -> commandID -> scopeKey -> decision
	// scopedChanged persists session-scoped grants for detached crash recovery.
	// Command-scoped decisions deliberately never survive a command/process loss.
	scopedChanged func(sessionID string, decisions []ScopedDecision)

	promptMu sync.Mutex

	// Rate limiting: track requests per session
	rateMu        sync.Mutex
	sessionCounts map[string]int // session -> active approval count
	maxPerSession int            // max concurrent approvals per session (0 = unlimited)
}

type terminalCause uint8

const (
	terminalCauseDecision terminalCause = iota + 1
	terminalCauseCanceled
	terminalCauseTimedOut
)

type terminalResolution struct {
	resolution Resolution
	cause      terminalCause
}

type pending struct {
	req      Request
	done     chan struct{}
	terminal *terminalResolution
}

// CommandTimeoutExtensionAllowance returns the maximum cumulative runtime
// allowance one command may receive for approval waits. The command timeout
// owner applies this allowance at most once, even if the command encounters
// multiple sequential approvals.
func (m *Manager) CommandTimeoutExtensionAllowance() time.Duration {
	if m == nil {
		return 0
	}
	return m.timeout
}

func New(mode string, timeout time.Duration, emit Emitter) *Manager {
	if mode == "" {
		mode = "local_tty"
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	m := &Manager{
		mode:          mode,
		timeout:       timeout,
		emit:          emit,
		pending:       make(map[string]*pending),
		scoped:        make(map[string]map[string]ScopedDecision),
		commandScoped: make(map[string]map[string]map[string]ScopedDecision),
		sessionCounts: make(map[string]int),
		maxPerSession: 10, // Default: max 10 concurrent approvals per session
	}
	switch mode {
	case "totp":
		m.prompt = m.promptTOTP
	default:
		m.prompt = m.promptTTY
	}
	return m
}

// SetTOTPSecretLookup sets the callback for retrieving TOTP secrets by session ID.
// Required when using TOTP approval mode.
func (m *Manager) SetTOTPSecretLookup(lookup func(sessionID string) string) {
	m.totpSecretLookup = lookup
}

// SetDetachedRequestObserver installs the detached control-plane publication
// seam. The observer owns transport/replay; approval semantics remain here.
func (m *Manager) SetDetachedRequestObserver(observer func(context.Context, Request) error) {
	m.mu.Lock()
	m.requestObserver = observer
	m.mu.Unlock()
}

// SetDetachedTerminalObserver publishes the immutable winning outcome after an
// approval terminalizes, including cancellation and timeout.
func (m *Manager) SetDetachedTerminalObserver(observer func(context.Context, Request, Resolution) error) {
	m.mu.Lock()
	m.terminalObserver = observer
	m.mu.Unlock()
}

func (m *Manager) notifyDetachedRequest(ctx context.Context, request Request) error {
	m.mu.Lock()
	observer := m.requestObserver
	m.mu.Unlock()
	if observer == nil {
		return nil
	}
	return observer(ctx, request)
}

func (m *Manager) notifyDetachedTerminal(request Request, resolution Resolution) error {
	m.mu.Lock()
	observer := m.terminalObserver
	m.mu.Unlock()
	if observer == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return observer(ctx, request, resolution)
}

func (m *Manager) SetScopedPersistenceHook(hook func(sessionID string, decisions []ScopedDecision)) {
	m.mu.Lock()
	m.scopedChanged = hook
	m.mu.Unlock()
}

// SessionScopedDecisions returns an expiry-filtered copy of durable
// session-scoped decisions. Pending and command-scoped approvals are excluded.
func (m *Manager) SessionScopedDecisions(sessionID string) []ScopedDecision {
	if m == nil || sessionID == "" {
		return nil
	}
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	bySession := m.scoped[sessionID]
	out := make([]ScopedDecision, 0, len(bySession))
	for key, decision := range bySession {
		if decision.ExpiresAt != nil && decision.ExpiresAt.Before(now) {
			delete(bySession, key)
			continue
		}
		out = append(out, decision)
	}
	return out
}

// RestoreSessionScopedDecisions reinstates only grants bound to the exact
// session identity. Callers must first verify the recovery policy digest.
func (m *Manager) RestoreSessionScopedDecisions(sessionID string, decisions []ScopedDecision) error {
	if m == nil || sessionID == "" {
		return nil
	}
	now := time.Now().UTC()
	restored := make(map[string]ScopedDecision, len(decisions))
	for _, decision := range decisions {
		scope := Scope{Kind: decision.Kind, Key: decision.Key, Label: decision.Label, Rule: decision.Rule, Operation: decision.Operation, Path: decision.Path, Prefix: decision.Prefix}
		if decision.SessionID != sessionID || !validScope(scope) {
			return fmt.Errorf("invalid scoped approval recovery identity")
		}
		if decision.ExpiresAt != nil && decision.ExpiresAt.Before(now) {
			continue
		}
		restored[decision.Key] = decision
	}
	m.mu.Lock()
	if len(restored) == 0 {
		delete(m.scoped, sessionID)
	} else {
		m.scoped[sessionID] = restored
	}
	m.mu.Unlock()
	return nil
}

func (m *Manager) notifyScopedChanged(sessionID string) {
	if m == nil || sessionID == "" {
		return
	}
	decisions := m.SessionScopedDecisions(sessionID)
	m.mu.Lock()
	hook := m.scopedChanged
	m.mu.Unlock()
	if hook != nil {
		hook(sessionID, decisions)
	}
}

// SetWebAuthnApprover sets the WebAuthn approver (required for webauthn mode).
func (m *Manager) SetWebAuthnApprover(approver *WebAuthnApprover) {
	m.webauthnApprover = approver
}

// GetWebAuthnChallenge returns a WebAuthn challenge for an approval request.
//
// Authorization note: The userID parameter represents the operator making the approval decision.
// Session ownership validation (ensuring the operator is authorized to approve requests for this
// session) is performed at a higher layer (e.g., API authentication middleware). This design
// separates concerns: the approval manager handles approval logic, while access control is
// handled by the transport layer.
func (m *Manager) GetWebAuthnChallenge(ctx context.Context, approvalID, userID string) (*WebAuthnChallenge, error) {
	if m.mode != "webauthn" {
		return nil, fmt.Errorf("webauthn mode not enabled")
	}
	if m.webauthnApprover == nil {
		return nil, fmt.Errorf("webauthn approver not configured")
	}

	m.mu.Lock()
	p, ok := m.pending[approvalID]
	m.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("approval not found: %s", approvalID)
	}

	return m.webauthnApprover.CreateChallenge(ctx, p.req, userID)
}

// ResolveWithWebAuthn resolves an approval using WebAuthn assertion.
//
// Authorization note: The userID parameter represents the operator making the approval decision.
// Session ownership validation (ensuring the operator is authorized to approve requests for this
// session) is performed at a higher layer (e.g., API authentication middleware). This design
// separates concerns: the approval manager handles approval logic, while access control is
// handled by the transport layer.
func (m *Manager) ResolveWithWebAuthn(ctx context.Context, approvalID, userID string, responseJSON []byte) error {
	if m.mode != "webauthn" {
		return fmt.Errorf("webauthn mode not enabled")
	}
	if m.webauthnApprover == nil {
		return fmt.Errorf("webauthn approver not configured")
	}

	// Verify approval exists before attempting verification
	m.mu.Lock()
	_, ok := m.pending[approvalID]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("approval not found: %s", approvalID)
	}

	if err := m.webauthnApprover.VerifyResponse(ctx, userID, responseJSON); err != nil {
		m.Resolve(approvalID, false, "webauthn verification failed: "+err.Error())
		return err
	}

	m.Resolve(approvalID, true, "webauthn verified")
	return nil
}

func (m *Manager) ListPending() []Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.listPendingLocked("")
}

func (m *Manager) ListPendingForSession(sessionID string) []Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.listPendingLocked(sessionID)
}

func (m *Manager) listPendingLocked(sessionID string) []Request {
	out := make([]Request, 0, len(m.pending))
	now := time.Now().UTC()
	for _, p := range m.pending {
		if p.req.ExpiresAt.Before(now) {
			continue
		}
		if sessionID != "" && p.req.SessionID != sessionID {
			continue
		}
		out = append(out, p.req)
	}
	return out
}

func (m *Manager) Resolve(id string, approved bool, reason string) bool {
	return m.ResolveWithScope(id, approved, reason, ScopeOnce)
}

func (m *Manager) ResolveWithScope(id string, approved bool, reason string, scope string) bool {
	return m.resolveForSession("", id, approved, reason, scope, Scope{})
}

func (m *Manager) ResolveWithScopeTarget(id string, approved bool, reason string, scope string, target Scope) bool {
	return m.resolveForSession("", id, approved, reason, scope, target)
}

func (m *Manager) ResolveForSession(sessionID string, id string, approved bool, reason string) bool {
	return m.ResolveForSessionWithScope(sessionID, id, approved, reason, ScopeOnce)
}

func (m *Manager) ResolveForSessionWithScope(sessionID string, id string, approved bool, reason string, scope string) bool {
	if sessionID == "" {
		return false
	}
	return m.resolveForSession(sessionID, id, approved, reason, scope, Scope{})
}

func (m *Manager) ResolveForSessionWithScopeTarget(sessionID string, id string, approved bool, reason string, scope string, target Scope) bool {
	if sessionID == "" {
		return false
	}
	return m.resolveForSession(sessionID, id, approved, reason, scope, target)
}

func (m *Manager) resolveForSession(sessionID string, id string, approved bool, reason string, scope string, target Scope) bool {
	scope, err := NormalizeResolutionScope(scope)
	if err != nil {
		return false
	}
	p, terminal, ok := m.resolveDecisionForSession(sessionID, id, approved, reason, scope, target)
	if !ok {
		return false
	}
	res := terminal.resolution
	if scope == ScopeSession {
		if granted, ok := ScopeFromResolution(res); ok {
			m.resolvePendingCoveredBySessionScope(p.req, granted, res)
		} else if granted, ok := ScopeFromRequest(p.req); ok {
			m.resolvePendingCoveredBySessionScope(p.req, granted, res)
		}
	} else if scope == ScopeOnce && IsCommandRunScope(target) {
		m.resolvePendingCoveredByCommandRun(p.req, target, res)
	}
	return true
}

func (m *Manager) resolveDecisionForSession(sessionID string, id string, approved bool, reason string, scope string, target Scope) (*pending, terminalResolution, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, ok := m.pending[id]
	if !ok || p == nil || sessionID != "" && p.req.SessionID != sessionID {
		return nil, terminalResolution{}, false
	}
	if IsCommandRunScope(target) {
		target = NewCommandRunScope()
	}
	res := Resolution{Approved: approved, Reason: reason, Scope: scope, At: time.Now().UTC()}
	if validScope(target) {
		res.ScopeKind = target.Kind
		res.ScopeKey = target.Key
		res.ScopeLabel = target.Label
		res.ScopeOperation = target.Operation
		res.ScopePath = target.Path
		res.ScopeRule = target.Rule
		res.ScopePrefix = target.Prefix
	}
	// Publish command-wide decisions before waking the current waiter. This
	// closes the interval in which another request from the same command could
	// arrive after operator resolution but before RequestApproval stores its
	// command-scoped result.
	if scope == ScopeOnce && IsCommandRunScope(target) && p.req.SessionID != "" && p.req.CommandID != "" {
		dec := ScopedDecision{
			SessionID: p.req.SessionID,
			Kind:      target.Kind,
			Key:       target.Key,
			Label:     target.Label,
			Approved:  approved,
			Reason:    reason,
			Rule:      p.req.Rule,
			CreatedAt: time.Now().UTC(),
		}
		if m.commandScoped == nil {
			m.commandScoped = make(map[string]map[string]map[string]ScopedDecision)
		}
		if m.commandScoped[p.req.SessionID] == nil {
			m.commandScoped[p.req.SessionID] = make(map[string]map[string]ScopedDecision)
		}
		if m.commandScoped[p.req.SessionID][p.req.CommandID] == nil {
			m.commandScoped[p.req.SessionID][p.req.CommandID] = make(map[string]ScopedDecision)
		}
		m.commandScoped[p.req.SessionID][p.req.CommandID][target.Key] = dec
	}
	terminal := terminalResolution{resolution: res, cause: terminalCauseDecision}
	if !m.terminalizePendingLocked(id, p, terminal) {
		return nil, terminalResolution{}, false
	}
	return p, terminal, true
}

func (m *Manager) terminalizePendingLocked(id string, p *pending, terminal terminalResolution) bool {
	current, ok := m.pending[id]
	if !ok || current != p || p == nil || p.terminal != nil {
		return false
	}
	p.terminal = &terminal
	delete(m.pending, id)
	close(p.done)
	return true
}

func (m *Manager) claimOrObservePending(p *pending, cause terminalCause) terminalResolution {
	m.mu.Lock()
	if p.terminal != nil {
		terminal := *p.terminal
		m.mu.Unlock()
		return terminal
	}
	if current, ok := m.pending[p.req.ID]; !ok || current != p {
		m.mu.Unlock()
		panic("approval pending entry removed without a terminal resolution")
	}

	var reason string
	switch cause {
	case terminalCauseCanceled:
		reason = "context canceled"
	case terminalCauseTimedOut:
		reason = "approval timeout"
	default:
		m.mu.Unlock()
		panic("invalid non-decision approval resolution cause")
	}
	terminal := terminalResolution{
		resolution: Resolution{
			Approved: false,
			Reason:   reason,
			Scope:    ScopeOnce,
			At:       time.Now().UTC(),
		},
		cause: cause,
	}
	if !m.terminalizePendingLocked(p.req.ID, p, terminal) {
		m.mu.Unlock()
		panic("failed to terminalize pending approval")
	}
	m.mu.Unlock()
	return terminal
}

func (m *Manager) observePending(p *pending) terminalResolution {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p == nil || p.terminal == nil {
		panic("approval completed without a terminal resolution")
	}
	return *p.terminal
}

func (m *Manager) waitForPendingResolution(ctx context.Context, p *pending, timeout <-chan time.Time) terminalResolution {
	select {
	case <-p.done:
		return m.observePending(p)
	case <-ctx.Done():
		return m.claimOrObservePending(p, terminalCauseCanceled)
	case <-timeout:
		return m.claimOrObservePending(p, terminalCauseTimedOut)
	}
}

func terminalError(ctx context.Context, cause terminalCause) error {
	switch cause {
	case terminalCauseDecision:
		return nil
	case terminalCauseCanceled:
		return ctx.Err()
	case terminalCauseTimedOut:
		return fmt.Errorf("approval timeout")
	default:
		panic("unknown approval terminal cause")
	}
}

func (m *Manager) RequestApproval(ctx context.Context, req Request) (Resolution, error) {
	if req.SessionID != "" && req.CommandID != "" {
		commandRun := NewCommandRunScope()
		if cached, ok := m.CheckScoped(ctx, req.SessionID, req.CommandID, commandRun); ok {
			return Resolution{
				Approved:       cached.Approved,
				Reason:         cached.Reason,
				Scope:          ScopeOnce,
				At:             time.Now().UTC(),
				ScopeKind:      cached.Kind,
				ScopeKey:       cached.Key,
				ScopeLabel:     cached.Label,
				ScopeOperation: cached.Operation,
				ScopePath:      cached.Path,
				ScopeRule:      cached.Rule,
				ScopePrefix:    cached.Prefix,
			}, nil
		}
		appendCommandRunScopeOption(&req)
	}

	// Rate limiting: check concurrent approval count per session
	if m.maxPerSession > 0 {
		m.rateMu.Lock()
		count := m.sessionCounts[req.SessionID]
		if count >= m.maxPerSession {
			m.rateMu.Unlock()
			return Resolution{Approved: false, Reason: "rate limit exceeded", Scope: ScopeOnce, At: time.Now().UTC()},
				fmt.Errorf("too many pending approvals for session %s (max %d)", req.SessionID, m.maxPerSession)
		}
		m.sessionCounts[req.SessionID] = count + 1
		m.rateMu.Unlock()
	}

	// Decrement rate limit counter when done
	decrementRate := func() {
		if m.maxPerSession > 0 {
			m.rateMu.Lock()
			m.sessionCounts[req.SessionID]--
			if m.sessionCounts[req.SessionID] <= 0 {
				delete(m.sessionCounts, req.SessionID)
			}
			m.rateMu.Unlock()
		}
	}
	defer decrementRate() // Always decrement on exit after incrementing

	now := time.Now().UTC()
	if req.ID == "" {
		req.ID = "approval-" + uuid.NewString()
	}
	req.CreatedAt = now
	req.ExpiresAt = now.Add(m.timeout)

	p := &pending{req: req, done: make(chan struct{})}

	m.mu.Lock()
	if _, exists := m.pending[req.ID]; exists {
		m.mu.Unlock()
		err := fmt.Errorf("approval ID %q is already pending", req.ID)
		return Resolution{Approved: false, Reason: err.Error(), Scope: ScopeOnce, At: now}, err
	}
	m.pending[req.ID] = p
	m.mu.Unlock()

	ExtendCommandTimeoutForApproval(ctx, m.timeout)

	m.emitEvent(ctx, "approval_requested", req, nil)
	if observerErr := m.notifyDetachedRequest(ctx, req); observerErr != nil {
		_ = m.ResolveForSession(req.SessionID, req.ID, false, "detached control transport unavailable: "+observerErr.Error())
	}

	var cancelPrompt context.CancelFunc
	promptCtx := ctx
	if m.mode == "local_tty" {
		promptCtx, cancelPrompt = context.WithCancel(ctx)
		go func() {
			res, err := m.prompt(promptCtx, req)
			if err != nil {
				if promptCtx.Err() != nil {
					return
				}
				_ = m.Resolve(req.ID, false, err.Error())
				return
			}
			_ = m.ResolveWithScope(req.ID, res.Approved, res.Reason, res.Scope)
		}()
	}

	if m.mode == "local_tty" {
		// Fall through to the wait; prompt resolution will close p.done.
	}

	timeout := time.Until(req.ExpiresAt)
	if timeout < 0 {
		timeout = 0
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	terminal := m.waitForPendingResolution(ctx, p, timer.C)
	if cancelPrompt != nil {
		cancelPrompt()
	}
	res := terminal.resolution
	_ = m.notifyDetachedTerminal(req, res)
	m.emitEvent(ctx, "approval_resolved", req, &res)
	if terminal.cause == terminalCauseDecision {
		m.setScopedFromRequest(ctx, req, res)
	}
	return res, terminalError(ctx, terminal.cause)
}

func (m *Manager) CheckScoped(ctx context.Context, sessionID string, commandID string, scope Scope) (ScopedDecision, bool) {
	if sessionID == "" || !validScope(scope) {
		return ScopedDecision{}, false
	}
	now := time.Now().UTC()
	m.mu.Lock()
	if commandID != "" {
		if byCommand := m.commandScoped[sessionID][commandID]; byCommand != nil {
			if dec, ok := byCommand[CommandRunScopeKey]; ok {
				m.mu.Unlock()
				m.emitScopedEvent(ctx, "approval_command_scope_used", commandID, dec)
				return dec, true
			}
			if dec, ok := byCommand[scope.Key]; ok {
				m.mu.Unlock()
				m.emitScopedEvent(ctx, "approval_command_scope_used", commandID, dec)
				return dec, true
			}
			if scope.Kind == "file" {
				if dec, ok := findFileDirScopedDecision(byCommand, scope, now); ok {
					m.mu.Unlock()
					m.emitScopedEvent(ctx, "approval_command_scope_used", commandID, dec)
					return dec, true
				}
				if dec, ok := findFileTreeScopedDecision(byCommand, scope, now); ok {
					m.mu.Unlock()
					m.emitScopedEvent(ctx, "approval_command_scope_used", commandID, dec)
					return dec, true
				}
			}
		}
	}
	if IsCommandRunScope(scope) {
		m.mu.Unlock()
		return ScopedDecision{}, false
	}
	bySession := m.scoped[sessionID]
	dec, ok := bySession[scope.Key]
	if ok && dec.ExpiresAt != nil && dec.ExpiresAt.Before(now) {
		delete(bySession, scope.Key)
		ok = false
	}
	if !ok && scope.Kind == "file" {
		dec, ok = findFileDirScopedDecision(bySession, scope, now)
	}
	if !ok && scope.Kind == "file" {
		dec, ok = findFileTreeScopedDecision(bySession, scope, now)
	}
	m.mu.Unlock()
	if !ok {
		return ScopedDecision{}, false
	}
	m.emitScopedEvent(ctx, "approval_scope_used", commandID, dec)
	return dec, true
}

func findFileDirScopedDecision(decisions map[string]ScopedDecision, requested Scope, now time.Time) (ScopedDecision, bool) {
	return findFileScopedDecision(decisions, requested, now, "file-dir", fileDirContains)
}

func findFileTreeScopedDecision(decisions map[string]ScopedDecision, requested Scope, now time.Time) (ScopedDecision, bool) {
	return findFileScopedDecision(decisions, requested, now, "file-tree", fileTreeContains)
}

func findFileScopedDecision(decisions map[string]ScopedDecision, requested Scope, now time.Time, kind string, contains func(string, string) bool) (ScopedDecision, bool) {
	for key, dec := range decisions {
		if dec.Kind != kind {
			continue
		}
		if dec.ExpiresAt != nil && dec.ExpiresAt.Before(now) {
			delete(decisions, key)
			continue
		}
		if dec.Operation == "" || requested.Operation == "" || dec.Operation != requested.Operation {
			continue
		}
		// Directory approvals are deliberately rule-aware: approving a broad
		// outside-workspace read must not satisfy a more-specific sensitive rule
		// (for example .env/credential access) under the same directory.
		if dec.Rule == "" || requested.Rule == "" || dec.Rule != requested.Rule {
			continue
		}
		if contains(dec.Path, requested.Path) {
			return dec, true
		}
	}
	return ScopedDecision{}, false
}

func fileDirContains(dirPath, filePath string) bool {
	dirPath = strings.TrimSpace(dirPath)
	filePath = strings.TrimSpace(filePath)
	if dirPath == "" || filePath == "" {
		return false
	}
	dirPath = strings.TrimSuffix(dirPath, "/")
	if dirPath == "" {
		dirPath = "/"
	}
	if dirPath == filePath || dirPath == "/" {
		return true
	}
	if !strings.HasPrefix(filePath, dirPath+"/") {
		return false
	}
	rel := strings.TrimPrefix(filePath, dirPath+"/")
	return rel != "" && !strings.Contains(rel, "/")
}

func fileTreeContains(dirPath, filePath string) bool {
	dirPath = strings.TrimSpace(dirPath)
	filePath = strings.TrimSpace(filePath)
	if dirPath == "" || filePath == "" {
		return false
	}
	dirPath = strings.TrimSuffix(dirPath, "/")
	if dirPath == "" {
		dirPath = "/"
	}
	if dirPath == filePath || dirPath == "/" {
		return true
	}
	return strings.HasPrefix(filePath, dirPath+"/")
}

func (m *Manager) SetScoped(ctx context.Context, sessionID string, commandID string, scope Scope, approved bool, reason string, rule string) bool {
	if sessionID == "" || !validScope(scope) || IsCommandRunScope(scope) {
		return false
	}
	dec := ScopedDecision{
		SessionID: sessionID,
		Kind:      scope.Kind,
		Key:       scope.Key,
		Label:     scope.Label,
		Approved:  approved,
		Reason:    reason,
		Rule:      firstNonEmpty(scope.Rule, rule),
		Operation: scope.Operation,
		Path:      scope.Path,
		Prefix:    scope.Prefix,
		CreatedAt: time.Now().UTC(),
	}
	m.mu.Lock()
	if m.scoped == nil {
		m.scoped = make(map[string]map[string]ScopedDecision)
	}
	if m.scoped[sessionID] == nil {
		m.scoped[sessionID] = make(map[string]ScopedDecision)
	}
	m.scoped[sessionID][scope.Key] = dec
	m.mu.Unlock()
	m.notifyScopedChanged(sessionID)
	m.emitScopedEvent(ctx, "approval_scope_granted", commandID, dec)
	return true
}

func (m *Manager) SetCommandScoped(ctx context.Context, sessionID string, commandID string, scope Scope, approved bool, reason string, rule string) bool {
	if sessionID == "" || commandID == "" || !validScope(scope) {
		return false
	}
	dec := ScopedDecision{
		SessionID: sessionID,
		Kind:      scope.Kind,
		Key:       scope.Key,
		Label:     scope.Label,
		Approved:  approved,
		Reason:    reason,
		Rule:      firstNonEmpty(scope.Rule, rule),
		Operation: scope.Operation,
		Path:      scope.Path,
		Prefix:    scope.Prefix,
		CreatedAt: time.Now().UTC(),
	}
	m.mu.Lock()
	if m.commandScoped == nil {
		m.commandScoped = make(map[string]map[string]map[string]ScopedDecision)
	}
	if m.commandScoped[sessionID] == nil {
		m.commandScoped[sessionID] = make(map[string]map[string]ScopedDecision)
	}
	if m.commandScoped[sessionID][commandID] == nil {
		m.commandScoped[sessionID][commandID] = make(map[string]ScopedDecision)
	}
	m.commandScoped[sessionID][commandID][scope.Key] = dec
	m.mu.Unlock()
	m.emitScopedEvent(ctx, "approval_command_scope_granted", commandID, dec)
	return true
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func (m *Manager) ClearSession(ctx context.Context, sessionID string) {
	if sessionID == "" {
		return
	}
	m.mu.Lock()
	decisions := make([]ScopedDecision, 0, len(m.scoped[sessionID]))
	for _, dec := range m.scoped[sessionID] {
		decisions = append(decisions, dec)
	}
	delete(m.scoped, sessionID)
	delete(m.commandScoped, sessionID)
	m.mu.Unlock()
	m.notifyScopedChanged(sessionID)
	for _, dec := range decisions {
		m.emitScopedEvent(ctx, "approval_scope_cleared", "", dec)
	}
}

func (m *Manager) setScopedFromRequest(ctx context.Context, req Request, res Resolution) {
	scope, err := NormalizeResolutionScope(res.Scope)
	if err != nil {
		return
	}
	approvalScope, ok := ScopeFromResolution(res)
	if !ok {
		approvalScope, ok = ScopeFromRequest(req)
	}
	if !ok || IsCommandRunScope(approvalScope) && scope != ScopeOnce {
		return
	}
	switch scope {
	case ScopeSession:
		if m.SetScoped(ctx, req.SessionID, req.CommandID, approvalScope, res.Approved, res.Reason, req.Rule) {
			m.resolvePendingCoveredBySessionScope(req, approvalScope, res)
		}
	case ScopeOnce:
		m.SetCommandScoped(ctx, req.SessionID, req.CommandID, approvalScope, res.Approved, res.Reason, req.Rule)
	}
}

func (m *Manager) resolvePendingCoveredByCommandRun(source Request, granted Scope, sourceRes Resolution) {
	if source.SessionID == "" || source.CommandID == "" || !IsCommandRunScope(granted) {
		return
	}
	m.mu.Lock()
	now := time.Now().UTC()
	for id, p := range m.pending {
		if p == nil || id == source.ID || p.req.SessionID != source.SessionID || p.req.CommandID != source.CommandID {
			continue
		}
		if p.req.ExpiresAt.Before(now) {
			continue
		}
		res := Resolution{
			Approved:   sourceRes.Approved,
			Reason:     sourceRes.Reason,
			Scope:      ScopeOnce,
			At:         now,
			ScopeKind:  granted.Kind,
			ScopeKey:   granted.Key,
			ScopeLabel: granted.Label,
		}
		if strings.TrimSpace(res.Reason) == "" {
			res.Reason = "covered by command invocation approval"
		}
		m.terminalizePendingLocked(id, p, terminalResolution{
			resolution: res,
			cause:      terminalCauseDecision,
		})
	}
	m.mu.Unlock()
}

func (m *Manager) resolvePendingCoveredBySessionScope(source Request, granted Scope, sourceRes Resolution) {
	if source.SessionID == "" || !validScope(granted) {
		return
	}
	m.mu.Lock()
	now := time.Now().UTC()
	for id, p := range m.pending {
		if p == nil || id == source.ID || p.req.SessionID != source.SessionID {
			continue
		}
		if p.req.ExpiresAt.Before(now) {
			continue
		}
		if !RequestCoveredByScope(p.req, granted) {
			continue
		}
		res := Resolution{
			Approved:       sourceRes.Approved,
			Reason:         sourceRes.Reason,
			Scope:          ScopeSession,
			At:             now,
			ScopeKind:      granted.Kind,
			ScopeKey:       granted.Key,
			ScopeLabel:     granted.Label,
			ScopeOperation: granted.Operation,
			ScopePath:      granted.Path,
			ScopeRule:      granted.Rule,
			ScopePrefix:    granted.Prefix,
		}
		if strings.TrimSpace(res.Reason) == "" {
			res.Reason = "covered by session approval"
		}
		m.terminalizePendingLocked(id, p, terminalResolution{
			resolution: res,
			cause:      terminalCauseDecision,
		})
	}
	m.mu.Unlock()
}

func appendCommandRunScopeOption(req *Request) {
	if req == nil || req.CommandID == "" {
		return
	}
	if req.Fields == nil {
		req.Fields = make(map[string]any)
	}
	commandRun := NewCommandRunScope()
	for _, existing := range scopesFromRequest(*req) {
		if IsCommandRunScope(existing) {
			return
		}
	}
	option := ScopeFields(commandRun)
	switch options := req.Fields["scope_options"].(type) {
	case nil:
		req.Fields["scope_options"] = []map[string]any{option}
	case []map[string]any:
		req.Fields["scope_options"] = append(options, option)
	case []any:
		req.Fields["scope_options"] = append(options, option)
	}
}

// RequestCoveredByScope reports whether a pending request asks for a scope that
// is satisfied by the granted session scope. It understands the default scope
// fields and any scope_options advertised to approval UIs.
func RequestCoveredByScope(req Request, granted Scope) bool {
	for _, requested := range scopesFromRequest(req) {
		if scopeCovers(granted, requested) {
			return true
		}
	}
	return false
}

// ScopeFromRequest returns the default scope advertised by an approval request.
func ScopeFromRequest(req Request) (Scope, bool) {
	return scopeFromFields(req.Fields)
}

func scopesFromRequest(req Request) []Scope {
	if req.Fields == nil {
		return nil
	}
	out := make([]Scope, 0, 1)
	seen := make(map[string]bool)
	add := func(fields map[string]any) {
		if scope, ok := scopeFromFields(fields); ok && !seen[scope.Key] {
			seen[scope.Key] = true
			out = append(out, scope)
		}
	}
	add(req.Fields)
	switch options := req.Fields["scope_options"].(type) {
	case []map[string]any:
		for _, fields := range options {
			add(fields)
		}
	case []any:
		for _, option := range options {
			if fields, ok := option.(map[string]any); ok {
				add(fields)
			}
		}
	}
	return out
}

func scopeCovers(granted Scope, requested Scope) bool {
	if !validScope(granted) || !validScope(requested) {
		return false
	}
	if granted.Key == requested.Key {
		return true
	}
	if requested.Kind != "file" {
		return false
	}
	if granted.Operation == "" || requested.Operation == "" || granted.Operation != requested.Operation {
		return false
	}
	if granted.Rule == "" || requested.Rule == "" || granted.Rule != requested.Rule {
		return false
	}
	switch granted.Kind {
	case "file-dir":
		return fileDirContains(granted.Path, requested.Path)
	case "file-tree":
		return fileTreeContains(granted.Path, requested.Path)
	default:
		return false
	}
}

// ScopeFromResolution returns the scope target explicitly selected in an
// approval resolution, when present.
func ScopeFromResolution(res Resolution) (Scope, bool) {
	if strings.TrimSpace(res.ScopeKind) == "" || strings.TrimSpace(res.ScopeKey) == "" {
		return Scope{}, false
	}
	return Scope{
		Kind:      strings.TrimSpace(res.ScopeKind),
		Key:       strings.TrimSpace(res.ScopeKey),
		Label:     strings.TrimSpace(res.ScopeLabel),
		Operation: normalizeFileScopeOperation(res.ScopeOperation),
		Path:      strings.TrimSpace(res.ScopePath),
		Rule:      strings.TrimSpace(res.ScopeRule),
		Prefix:    res.ScopePrefix,
	}, true
}

func (m *Manager) emitScopedEvent(ctx context.Context, evType string, commandID string, dec ScopedDecision) {
	if m.emit == nil {
		return
	}
	fields := map[string]any{
		"kind":        dec.Kind,
		"scope_key":   dec.Key,
		"scope_label": dec.Label,
		"approved":    dec.Approved,
		"rule":        dec.Rule,
		"reason":      dec.Reason,
	}
	if dec.Operation != "" {
		fields["operation"] = dec.Operation
	}
	if dec.Path != "" {
		fields["path"] = dec.Path
	}
	if dec.Prefix {
		fields["prefix"] = true
	}
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      evType,
		SessionID: dec.SessionID,
		CommandID: commandID,
		Fields:    fields,
	}
	_ = m.emit.AppendEvent(ctx, ev)
	m.emit.Publish(ev)
}

func (m *Manager) emitEvent(ctx context.Context, evType string, req Request, res *Resolution) {
	if m.emit == nil {
		return
	}
	fields := map[string]any{
		"approval_id": req.ID,
		"kind":        req.Kind,
		"target":      req.Target,
		"rule":        req.Rule,
		"message":     req.Message,
	}
	for k, v := range req.Fields {
		fields[k] = v
	}
	if res != nil {
		fields["approved"] = res.Approved
		fields["reason"] = res.Reason
		fields["scope"] = res.Scope
		fields["resolved_at"] = res.At.Format(time.RFC3339Nano)
	}
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      evType,
		SessionID: req.SessionID,
		CommandID: req.CommandID,
		Fields:    fields,
	}
	_ = m.emit.AppendEvent(ctx, ev)
	m.emit.Publish(ev)
}

func (m *Manager) promptTTY(ctx context.Context, req Request) (Resolution, error) {
	m.promptMu.Lock()
	defer m.promptMu.Unlock()

	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return Resolution{}, fmt.Errorf("open /dev/tty: %w", err)
	}

	// Use sync.Once to ensure we only close the file once
	var closeOnce sync.Once
	closeFile := func() { closeOnce.Do(func() { _ = f.Close() }) }
	defer closeFile()

	// Close the tty if the context is cancelled to unblock reads.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			closeFile()
		case <-done:
		}
	}()
	defer close(done)

	reader := bufio.NewReader(f)
	readLineCtx := func(prompt string) (string, error) {
		if _, err := fmt.Fprint(f, prompt); err != nil {
			return "", err
		}
		lineCh := make(chan struct {
			line string
			err  error
		}, 1)
		go func() {
			line, err := reader.ReadString('\n')
			lineCh <- struct {
				line string
				err  error
			}{line: line, err: err}
		}()
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case res := <-lineCh:
			if res.err != nil {
				return "", res.err
			}
			return strings.TrimSpace(res.line), nil
		}
	}

	a, b := challenge()
	fmt.Fprintf(f, "\n=== APPROVAL REQUIRED ===\n")
	fmt.Fprintf(f, "ID: %s\nSession: %s\nCommand: %s\nKind: %s\nTarget: %s\nRule: %s\nMessage: %s\n",
		req.ID, req.SessionID, req.CommandID, req.Kind, req.Target, req.Rule, req.Message)

	answer, err := readLineCtx(fmt.Sprintf("To approve, solve: %d + %d = ?\n> ", a, b))
	if err != nil {
		return Resolution{}, err
	}
	if answer != fmt.Sprintf("%d", a+b) {
		return Resolution{Approved: false, Reason: "challenge failed", At: time.Now().UTC()}, nil
	}

	choice, err := readLineCtx("Approve? type 'yes' to approve: ")
	if err != nil {
		return Resolution{}, err
	}
	choice = strings.ToLower(strings.TrimSpace(choice))
	if choice == "yes" || choice == "y" {
		return Resolution{Approved: true, Reason: "local tty", At: time.Now().UTC()}, nil
	}
	return Resolution{Approved: false, Reason: "denied", At: time.Now().UTC()}, nil
}

func (m *Manager) promptTOTP(ctx context.Context, req Request) (Resolution, error) {
	m.promptMu.Lock()
	defer m.promptMu.Unlock()

	// Get the TOTP secret for this session
	if m.totpSecretLookup == nil {
		return Resolution{Approved: false, Reason: "TOTP not configured", At: time.Now().UTC()},
			fmt.Errorf("TOTP secret lookup not configured")
	}
	secret := m.totpSecretLookup(req.SessionID)
	if secret == "" {
		return Resolution{Approved: false, Reason: "no TOTP secret", At: time.Now().UTC()},
			fmt.Errorf("no TOTP secret for session %s", req.SessionID)
	}

	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return Resolution{}, fmt.Errorf("open /dev/tty: %w", err)
	}

	var closeOnce sync.Once
	closeFile := func() { closeOnce.Do(func() { _ = f.Close() }) }
	defer closeFile()

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			closeFile()
		case <-done:
		}
	}()
	defer close(done)

	reader := bufio.NewReader(f)
	readLineCtx := func(prompt string) (string, error) {
		if _, err := fmt.Fprint(f, prompt); err != nil {
			return "", err
		}
		lineCh := make(chan struct {
			line string
			err  error
		}, 1)
		go func() {
			line, err := reader.ReadString('\n')
			lineCh <- struct {
				line string
				err  error
			}{line: line, err: err}
		}()
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case res := <-lineCh:
			if res.err != nil {
				return "", res.err
			}
			return strings.TrimSpace(res.line), nil
		}
	}

	// Display approval request
	fmt.Fprintf(f, "\n=== APPROVAL REQUIRED (TOTP) ===\n")
	fmt.Fprintf(f, "Session: %s\nCommand: %s\nKind: %s\nTarget: %s\nRule: %s\nMessage: %s\n\n",
		req.SessionID, req.CommandID, req.Kind, req.Target, req.Rule, req.Message)

	// Prompt for TOTP code
	code, err := readLineCtx("Enter 6-digit TOTP code: ")
	if err != nil {
		return Resolution{}, err
	}

	// Validate the code
	if ValidateTOTPCode(code, secret) {
		return Resolution{Approved: true, Reason: "totp verified", At: time.Now().UTC()}, nil
	}

	return Resolution{Approved: false, Reason: "invalid code", At: time.Now().UTC()}, nil
}

func challenge() (int, int) {
	var b [8]byte
	_, _ = rand.Read(b[:])
	n := binary.LittleEndian.Uint64(b[:])
	a := int(n%50) + 10
	bb := int((n/50)%50) + 10
	return a, bb
}
