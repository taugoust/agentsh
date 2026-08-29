package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"

	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/session"
)

const (
	childCapabilityHeader = "X-AgentSH-Child-Capability"
	childCapabilityEnv    = "AGENTSH_CHILD_CAPABILITY"
	childCapabilityBytes  = 32
)

var (
	errChildCapabilityInvalid           = errors.New("child execution capability is invalid")
	errChildCapabilityRevoked           = errors.New("child execution capability is revoked")
	errChildCapabilitySupervisorStopped = errors.New("child execution capability revoked because the supervisor stopped")
)

type childCapabilityRecord struct {
	digest     [32]byte
	sessionID  string
	sessionRef *session.Session
	subagentID string

	active  bool
	revoked bool
	pid     int
	pgid    int

	processStartIdentity  string
	bootID                string
	stableProcessIdentity bool

	ready       chan struct{}
	readyClosed bool
	lifecycle   context.Context
	cancel      context.CancelCauseFunc
}

type childCapabilityHandle struct {
	digest [32]byte
	token  string
}

type childCapabilityClaim struct {
	app        *App
	digest     [32]byte
	sessionID  string
	sessionRef *session.Session
	laneID     string
	peerPID    int
	peerBound  bool
	stablePID  bool
	lifecycle  context.Context
}

func (c *childCapabilityClaim) sharedEligible() bool {
	return c != nil && c.peerBound && c.stablePID
}

func (c *childCapabilityClaim) validate() error {
	if c == nil || c.app == nil {
		return errChildCapabilityInvalid
	}
	return c.app.validateChildCapabilityClaim(c)
}

func mintChildCapabilityToken() (string, [32]byte, error) {
	var secret [childCapabilityBytes]byte
	if _, err := io.ReadFull(rand.Reader, secret[:]); err != nil {
		return "", [32]byte{}, fmt.Errorf("generate child execution capability: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(secret[:])
	return token, sha256.Sum256([]byte(token)), nil
}

func parseChildCapabilityToken(token string) ([32]byte, error) {
	token = strings.TrimSpace(token)
	if token == "" || len(token) > 128 {
		return [32]byte{}, errChildCapabilityInvalid
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != childCapabilityBytes {
		return [32]byte{}, errChildCapabilityInvalid
	}
	return sha256.Sum256([]byte(token)), nil
}

func (a *App) mintChildCapability(sessionID, subagentID string) (*childCapabilityHandle, error) {
	if a == nil || a.sessions == nil || strings.TrimSpace(sessionID) == "" || strings.TrimSpace(subagentID) == "" {
		return nil, errChildCapabilityInvalid
	}
	sessionRef, ok := a.sessions.Get(sessionID)
	if !ok || sessionRef == nil {
		return nil, errChildCapabilityInvalid
	}
	token, digest, err := mintChildCapabilityToken()
	if err != nil {
		return nil, err
	}
	lifecycle, cancel := context.WithCancelCause(context.Background())
	record := &childCapabilityRecord{
		digest: digest, sessionID: sessionID, sessionRef: sessionRef, subagentID: subagentID,
		ready: make(chan struct{}), lifecycle: lifecycle, cancel: cancel,
	}
	a.childCapabilityMu.Lock()
	if a.childCapabilities == nil {
		a.childCapabilities = make(map[[32]byte]*childCapabilityRecord)
	}
	if _, exists := a.childCapabilities[digest]; exists {
		a.childCapabilityMu.Unlock()
		cancel(errChildCapabilityInvalid)
		return nil, errors.New("child execution capability collision")
	}
	a.childCapabilities[digest] = record
	a.childCapabilityMu.Unlock()
	return &childCapabilityHandle{digest: digest, token: token}, nil
}

func closeChildCapabilityReady(record *childCapabilityRecord) {
	if record == nil || record.readyClosed {
		return
	}
	close(record.ready)
	record.readyClosed = true
}

// activateChildCapability binds a previously minted bearer to the exact direct
// child PID. Linux and Darwin additionally retain the kernel process-start
// identity so PID reuse cannot revive a credential.
func (a *App) activateChildCapability(handle *childCapabilityHandle, pid, pgid int) error {
	if a == nil || handle == nil || pid <= 0 || pgid <= 0 {
		return errChildCapabilityInvalid
	}
	startIdentity, bootID, identityErr := detached.CurrentProcessIdentity(pid)
	if identityErr != nil {
		return fmt.Errorf("bind child execution capability to process: %w", identityErr)
	}
	stableIdentity := strings.TrimSpace(startIdentity) != "" && strings.TrimSpace(bootID) != ""
	if (strings.TrimSpace(startIdentity) == "") != (strings.TrimSpace(bootID) == "") {
		return errors.New("bind child execution capability to process: incomplete process identity")
	}

	a.childCapabilityMu.Lock()
	defer a.childCapabilityMu.Unlock()
	record, ok := a.childCapabilities[handle.digest]
	if !ok || record == nil {
		return errChildCapabilityInvalid
	}
	if record.revoked {
		return errChildCapabilityRevoked
	}
	if record.active {
		return errors.New("child execution capability is already active")
	}
	record.pid = pid
	record.pgid = pgid
	record.processStartIdentity = startIdentity
	record.bootID = bootID
	record.stableProcessIdentity = stableIdentity
	record.active = true
	closeChildCapabilityReady(record)
	return nil
}

func (a *App) revokeChildCapability(handle *childCapabilityHandle, cause error) {
	if a == nil || handle == nil {
		return
	}
	a.revokeChildCapabilityDigest(handle.digest, cause)
}

func (a *App) revokeChildCapabilityDigest(digest [32]byte, cause error) {
	if a == nil {
		return
	}
	if cause == nil {
		cause = errChildCapabilityRevoked
	}
	a.childCapabilityMu.Lock()
	record := a.childCapabilities[digest]
	if record == nil || record.revoked {
		a.childCapabilityMu.Unlock()
		return
	}
	record.revoked = true
	record.active = false
	closeChildCapabilityReady(record)
	cancel := record.cancel
	a.childCapabilityMu.Unlock()
	cancel(cause)
}

func (a *App) revokeChildCapabilitiesForSession(sessionID string, cause error) {
	if a == nil || sessionID == "" {
		return
	}
	var digests [][32]byte
	a.childCapabilityMu.Lock()
	for digest, record := range a.childCapabilities {
		if record != nil && record.sessionID == sessionID && !record.revoked {
			digests = append(digests, digest)
		}
	}
	a.childCapabilityMu.Unlock()
	for _, digest := range digests {
		a.revokeChildCapabilityDigest(digest, cause)
	}
}

func (a *App) revokeAllChildCapabilities(cause error) {
	if a == nil {
		return
	}
	var digests [][32]byte
	a.childCapabilityMu.Lock()
	for digest, record := range a.childCapabilities {
		if record != nil && !record.revoked {
			digests = append(digests, digest)
		}
	}
	a.childCapabilityMu.Unlock()
	for _, digest := range digests {
		a.revokeChildCapabilityDigest(digest, cause)
	}
}

type unixHTTPPeer struct {
	PID       int
	UID       uint32
	Supported bool
}

const ctxKeyUnixPeer ctxKey = "unix_peer"

// UnixSocketConnContext records kernel peer credentials once per accepted HTTP
// Unix connection. The server wires it through http.Server.ConnContext; tests
// can inject the same private value without weakening production validation.
func UnixSocketConnContext(ctx context.Context, conn net.Conn) context.Context {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok || unixConn == nil {
		return ctx
	}
	creds := getConnPeerCreds(unixConn)
	if creds.PID <= 0 {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyUnixPeer, unixHTTPPeer{PID: creds.PID, UID: creds.UID, Supported: true})
}

func unixHTTPPeerFromRequest(r *http.Request) unixHTTPPeer {
	if r == nil {
		return unixHTTPPeer{}
	}
	peer, _ := r.Context().Value(ctxKeyUnixPeer).(unixHTTPPeer)
	return peer
}

func (a *App) authenticateChildCapability(ctx context.Context, r *http.Request, sessionID string) (*childCapabilityClaim, error) {
	if r == nil {
		return nil, nil
	}
	token := strings.TrimSpace(r.Header.Get(childCapabilityHeader))
	if token == "" {
		return nil, nil
	}
	if !isUnixSocketRequest(r) {
		return nil, errChildCapabilityInvalid
	}
	digest, err := parseChildCapabilityToken(token)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}

	for {
		a.childCapabilityMu.Lock()
		record := a.childCapabilities[digest]
		if record == nil || record.sessionID != sessionID {
			a.childCapabilityMu.Unlock()
			return nil, errChildCapabilityInvalid
		}
		currentSession, sessionExists := a.sessions.Get(sessionID)
		if !sessionExists || currentSession != record.sessionRef {
			a.childCapabilityMu.Unlock()
			a.revokeChildCapabilityDigest(digest, errChildCapabilityRevoked)
			return nil, errChildCapabilityRevoked
		}
		if record.revoked {
			a.childCapabilityMu.Unlock()
			return nil, errChildCapabilityRevoked
		}
		if !record.active {
			ready := record.ready
			a.childCapabilityMu.Unlock()
			select {
			case <-ctx.Done():
				if cause := context.Cause(ctx); cause != nil {
					return nil, cause
				}
				return nil, ctx.Err()
			case <-ready:
				continue
			}
		}
		pid := record.pid
		startIdentity := record.processStartIdentity
		bootID := record.bootID
		stableIdentity := record.stableProcessIdentity
		laneID := record.subagentID
		lifecycle := record.lifecycle
		a.childCapabilityMu.Unlock()

		if stableIdentity && !detached.ProcessIdentityMatches(pid, startIdentity, bootID) {
			a.revokeChildCapabilityDigest(digest, errChildCapabilityRevoked)
			return nil, errChildCapabilityRevoked
		}
		peer := unixHTTPPeerFromRequest(r)
		if peer.Supported && peer.PID != pid {
			return nil, errChildCapabilityInvalid
		}
		return &childCapabilityClaim{
			app: a, digest: digest, sessionID: sessionID, sessionRef: currentSession, laneID: laneID,
			peerPID: peer.PID, peerBound: peer.Supported && peer.PID == pid,
			stablePID: stableIdentity, lifecycle: lifecycle,
		}, nil
	}
}

// authenticateChildCapabilityProcessGroup is reserved for fixed child control
// requests whose HTTP client is a subprocess of the capability owner (for
// example curl invoked by an operator-owned worker). Ordinary tool execution
// retains exact peer-PID binding.
func (a *App) authenticateChildCapabilityProcessGroup(r *http.Request, sessionID string) (*childCapabilityClaim, error) {
	if r == nil || !isUnixSocketRequest(r) {
		return nil, errChildCapabilityInvalid
	}
	token := strings.TrimSpace(r.Header.Get(childCapabilityHeader))
	digest, err := parseChildCapabilityToken(token)
	if err != nil {
		return nil, err
	}
	peer := unixHTTPPeerFromRequest(r)
	if !peer.Supported {
		return nil, errChildCapabilityInvalid
	}
	a.childCapabilityMu.Lock()
	record := a.childCapabilities[digest]
	if record == nil || record.sessionID != sessionID || record.revoked || !record.active {
		a.childCapabilityMu.Unlock()
		return nil, errChildCapabilityInvalid
	}
	currentSession, ok := a.sessions.Get(sessionID)
	if !ok || currentSession != record.sessionRef {
		a.childCapabilityMu.Unlock()
		return nil, errChildCapabilityRevoked
	}
	pid := record.pid
	pgid := record.pgid
	startIdentity := record.processStartIdentity
	bootID := record.bootID
	stableIdentity := record.stableProcessIdentity
	laneID := record.subagentID
	lifecycle := record.lifecycle
	a.childCapabilityMu.Unlock()
	if !stableIdentity || !detached.ProcessIdentityMatches(pid, startIdentity, bootID) || !childPeerInProcessGroup(peer.PID, pgid) {
		return nil, errChildCapabilityInvalid
	}
	return &childCapabilityClaim{
		app: a, digest: digest, sessionID: sessionID, sessionRef: currentSession, laneID: laneID,
		peerPID: peer.PID, peerBound: true, stablePID: true, lifecycle: lifecycle,
	}, nil
}

func (a *App) validateChildCapabilityClaim(claim *childCapabilityClaim) error {
	if a == nil || claim == nil {
		return errChildCapabilityInvalid
	}
	a.childCapabilityMu.Lock()
	record := a.childCapabilities[claim.digest]
	if record == nil || record.sessionID != claim.sessionID || record.sessionRef != claim.sessionRef || record.subagentID != claim.laneID {
		a.childCapabilityMu.Unlock()
		return errChildCapabilityInvalid
	}
	currentSession, sessionExists := a.sessions.Get(claim.sessionID)
	if !sessionExists || currentSession != claim.sessionRef {
		a.childCapabilityMu.Unlock()
		a.revokeChildCapabilityDigest(claim.digest, errChildCapabilityRevoked)
		return errChildCapabilityRevoked
	}
	if record.revoked || !record.active {
		a.childCapabilityMu.Unlock()
		return errChildCapabilityRevoked
	}
	pid := record.pid
	startIdentity := record.processStartIdentity
	bootID := record.bootID
	stableIdentity := record.stableProcessIdentity
	a.childCapabilityMu.Unlock()
	if claim.peerBound && claim.peerPID != pid {
		return errChildCapabilityInvalid
	}
	if stableIdentity && !detached.ProcessIdentityMatches(pid, startIdentity, bootID) {
		a.revokeChildCapabilityDigest(claim.digest, errChildCapabilityRevoked)
		return errChildCapabilityRevoked
	}
	select {
	case <-claim.lifecycle.Done():
		return errChildCapabilityRevoked
	default:
		return nil
	}
}

// childSharedExecutionSupported remains conservative for session-wide FUSE,
// ptrace/ESF, netns, and non-strict transparent interception. Strict Linux explicit-proxy
// execution is safe because each shared command receives its own immutable-ID
// proxy listener and only that exact endpoint is installed in its command
// cgroup. Non-strict session proxies remain serialized.
func (a *App) childSharedExecutionSupported(sess *session.Session, claim *childCapabilityClaim) bool {
	if a == nil || a.cfg == nil || sess == nil || claim == nil || !claim.sharedEligible() {
		return false
	}
	if runtime.GOOS != "linux" || a.cfg.Sessions.Subagents.ExecConcurrency() <= 1 {
		return false
	}
	if a.ptraceTracer != nil || a.cmdResolver != nil || a.sessionTracker != nil || a.cfg.Sandbox.FUSE.Enabled {
		return false
	}
	if sess.NetNSName() != "" {
		return false
	}

	if commandJailRequired(a.cfg) {
		proxyURL := strings.TrimSpace(sess.ProxyURL())
		if proxyURL == "" {
			return false
		}
		if _, err := exactLoopbackProxyAddrPort(proxyURL); err != nil {
			return false
		}
		return true
	}

	if a.cfg.Sandbox.Network.Transparent.Enabled || strings.TrimSpace(sess.ProxyURL()) != "" || a.cfg.Sandbox.Cgroups.Enabled || a.cfg.Sandbox.Network.Enabled {
		return false
	}
	ebpf := a.cfg.Sandbox.Network.EBPF
	return !ebpf.Enabled && !ebpf.Enforce && !ebpf.Required
}

// contextForChildCapability makes revocation an execution cancellation cause.
// A queued request leaves admission immediately; an active command receives the
// same cancellation through the ordinary process-group cleanup path.
func contextForChildCapability(parent context.Context, claim *childCapabilityClaim) (context.Context, func()) {
	if claim == nil || claim.lifecycle == nil {
		return parent, func() {}
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancelCause(parent)
	stop := context.AfterFunc(claim.lifecycle, func() { cancel(errChildCapabilityRevoked) })
	return ctx, func() {
		stop()
		cancel(context.Canceled)
	}
}
