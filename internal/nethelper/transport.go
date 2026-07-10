package nethelper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// EnvSocket is the supervisor-only environment variable that points at the
// privileged network helper's Unix socket. The exec environment builder must
// never pass this variable to Pi/tools: same-UID tools are not trusted, and the
// helper socket is a privileged control plane.
const EnvSocket = "AGENTSH_NETHELPER_SOCKET"

// EnvHelperInstanceCredential carries the per-user helper-instance credential
// to a trusted supervisor. It is not a detached event token and must never be
// written to detached metadata or inherited by tools.
const EnvHelperInstanceCredential = "AGENTSH_NETHELPER_INSTANCE_CREDENTIAL"

// EnvSessionNonce is the deprecated environment spelling retained while
// version-1 supervisors migrate. Helpers interpret it only as an instance
// credential and compare it with their independently provisioned credential.
const EnvSessionNonce = "AGENTSH_NETHELPER_SESSION_NONCE"

// EnvCredentialFile points a detached supervisor at an installed
// helper-instance credential. The supervisor reads it before serving requests,
// removes this path from its environment, and retains only the in-memory value.
// Tool environments must scrub this key and all credential value spellings.
const EnvCredentialFile = "AGENTSH_NETHELPER_CREDENTIAL_FILE"

// Operation names one helper RPC. Requests are intentionally small declarative
// JSON messages. The protocol never accepts BPF bytecode, object paths, or file
// descriptors from clients.
type Operation string

const (
	OperationRegisterSessionCgroup Operation = "register_session_cgroup"
	OperationUpdatePolicyMap       Operation = "update_policy_map"
	OperationCleanupSession        Operation = "cleanup_session"
	OperationReleaseInstance       Operation = "release_instance"
)

func (op Operation) Valid() bool {
	switch op {
	case OperationRegisterSessionCgroup, OperationUpdatePolicyMap, OperationCleanupSession, OperationReleaseInstance:
		return true
	default:
		return false
	}
}

// RequestEnvelope is the framing object sent over the Unix socket. Request is
// a typed JSON object decoded with DisallowUnknownFields after Operation is
// selected.
type RequestEnvelope struct {
	ProtocolVersion int             `json:"protocol_version,omitempty"`
	Operation       Operation       `json:"operation"`
	Request         json.RawMessage `json:"request"`
}

// ErrorResponse is returned when a request cannot be dispatched far enough to
// produce an operation-specific response.
type ErrorResponse struct {
	ProtocolVersion int    `json:"protocol_version,omitempty"`
	OK              bool   `json:"ok"`
	Error           string `json:"error,omitempty"`
}

func (e RequestEnvelope) Validate() error {
	if err := validateProtocolVersion(e.ProtocolVersion); err != nil {
		return err
	}
	if !e.Operation.Valid() {
		return fmt.Errorf("invalid operation %q", e.Operation)
	}
	if len(e.Request) == 0 || strings.TrimSpace(string(e.Request)) == "" {
		return fmt.Errorf("request is required")
	}
	return nil
}

// DecodeRequestEnvelopeJSON strictly decodes a helper request envelope.
func DecodeRequestEnvelopeJSON(data []byte) (RequestEnvelope, error) {
	var env RequestEnvelope
	if err := decodeStrictJSON(data, &env); err != nil {
		return env, err
	}
	return env, env.Validate()
}

// PeerInfo is best-effort information about the Unix socket peer. On Linux it
// is populated from SO_PEERCRED. Same UID is explicitly not authorization: the
// authorizer must also validate nonce/cgroup/subtree constraints before a
// backend performs privileged work.
type PeerInfo struct {
	PID              int    `json:"pid,omitempty"`
	UID              uint32 `json:"uid,omitempty"`
	GID              uint32 `json:"gid,omitempty"`
	ProcessStartTime uint64 `json:"process_start_time,omitempty"`
	Supported        bool   `json:"supported"`

	identity *processIdentity
}

func (p *PeerInfo) closeIdentity() {
	if p != nil && p.identity != nil {
		p.identity.close()
		p.identity = nil
	}
}

// Backend performs helper operations after request validation and
// authorization. Production backends must use only AgentSH's built-in BPF
// assets and helper-owned kernel fds/maps/links.
type Backend interface {
	RegisterSessionCgroup(context.Context, PeerInfo, RegisterSessionCgroupRequest) (RegisterSessionCgroupResponse, error)
	UpdatePolicyMap(context.Context, PeerInfo, UpdatePolicyMapRequest) (UpdatePolicyMapResponse, error)
	CleanupSession(context.Context, PeerInfo, CleanupSessionRequest) (CleanupSessionResponse, error)
}

// Authorizer validates that the peer is an AgentSH supervisor allowed to manage
// the requested cgroup. A production implementation must not rely on UID alone;
// it should combine SO_PEERCRED PID/UID/GID, session nonce, supervisor PID,
// caller/target cgroup checks, and delegated-subtree containment.
type Authorizer interface {
	AuthorizeRegister(context.Context, PeerInfo, RegisterSessionCgroupRequest) error
	AuthorizeUpdate(context.Context, PeerInfo, UpdatePolicyMapRequest) error
	AuthorizeCleanup(context.Context, PeerInfo, CleanupSessionRequest) error
}

// InstanceController owns the fixed lifecycle of one ephemeral helper lease.
// Persistent helpers leave this unset and reject release_instance requests.
type InstanceController interface {
	ReleaseInstance(context.Context, PeerInfo, ReleaseInstanceRequest) (ReleaseInstanceResponse, error)
}

type authorizerLifecycle interface {
	CompleteRegister(RegisterSessionCgroupRequest, uint64) (string, error)
	RollbackRegister(string, string)
	CompleteCleanup(CleanupSessionRequest, bool)
}

type registrationReaper interface {
	ReapableRegistrations() []CleanupSessionRequest
	CompleteCleanup(CleanupSessionRequest, bool)
}

type orphanResourceReaper interface {
	ReapOrphanedResources(context.Context) error
}

type updateLifecycle interface {
	CompleteUpdate(UpdatePolicyMapRequest)
}

type denyAuthorizer struct{}

func (denyAuthorizer) AuthorizeRegister(context.Context, PeerInfo, RegisterSessionCgroupRequest) error {
	return errors.New("nethelper authorizer is not configured; refusing privileged registration")
}
func (denyAuthorizer) AuthorizeUpdate(context.Context, PeerInfo, UpdatePolicyMapRequest) error {
	return errors.New("nethelper authorizer is not configured; refusing privileged map update")
}
func (denyAuthorizer) AuthorizeCleanup(context.Context, PeerInfo, CleanupSessionRequest) error {
	return errors.New("nethelper authorizer is not configured; refusing privileged cleanup")
}

// AllowAuthorizer is intentionally exported for unit tests and controlled
// harnesses. Do not use it for a privileged helper exposed to same-UID tools.
type AllowAuthorizer struct{}

func (AllowAuthorizer) AuthorizeRegister(context.Context, PeerInfo, RegisterSessionCgroupRequest) error {
	return nil
}
func (AllowAuthorizer) AuthorizeUpdate(context.Context, PeerInfo, UpdatePolicyMapRequest) error {
	return nil
}
func (AllowAuthorizer) AuthorizeCleanup(context.Context, PeerInfo, CleanupSessionRequest) error {
	return nil
}

// FailClosedBackend is the safe default backend. It makes the helper transport
// usable in tests and in early deployments without ever claiming enforcement.
type FailClosedBackend struct{}

func (FailClosedBackend) RegisterSessionCgroup(_ context.Context, _ PeerInfo, req RegisterSessionCgroupRequest) (RegisterSessionCgroupResponse, error) {
	return RegisterSessionCgroupResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: "nethelper kernel backend is not configured"}, errors.New("nethelper kernel backend is not configured")
}
func (FailClosedBackend) UpdatePolicyMap(_ context.Context, _ PeerInfo, req UpdatePolicyMapRequest) (UpdatePolicyMapResponse, error) {
	return UpdatePolicyMapResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: "nethelper kernel backend is not configured"}, errors.New("nethelper kernel backend is not configured")
}
func (FailClosedBackend) CleanupSession(_ context.Context, _ PeerInfo, req CleanupSessionRequest) (CleanupSessionResponse, error) {
	return CleanupSessionResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: "nethelper kernel backend is not configured"}, errors.New("nethelper kernel backend is not configured")
}

// Server is a minimal one-request-per-connection Unix-socket helper server.
// Go-created listener and accepted fds are close-on-exec; the protocol never
// receives SCM_RIGHTS messages and never passes helper-owned fds to clients.
type Server struct {
	Backend            Backend
	Authorizer         Authorizer
	InstanceController InstanceController
	// Stop is called after an authorized release_instance response write is
	// attempted. A client disconnect must not strand an already accepted lease
	// release. Ephemeral serve mode uses it to cancel the listener context.
	Stop         func()
	MaxBytes     int64
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	ReapInterval time.Duration
}

type stopAfterResponse struct {
	response any
}

func NewServer(backend Backend, authorizer Authorizer) *Server {
	if backend == nil {
		backend = FailClosedBackend{}
	}
	if authorizer == nil {
		authorizer = denyAuthorizer{}
	}
	return &Server{
		Backend:      backend,
		Authorizer:   authorizer,
		MaxBytes:     1 << 20,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		ReapInterval: 5 * time.Second,
	}
}

// ListenUnix creates a mode-0600 Unix listener. The parent directory must be
// protected by the service manager; chmod here is defense-in-depth, not the
// complete same-UID boundary.
func ListenUnix(socketPath string) (net.Listener, error) {
	if runtime.GOOS == "windows" {
		return nil, fmt.Errorf("unix sockets are not supported on windows")
	}
	if strings.TrimSpace(socketPath) == "" {
		return nil, fmt.Errorf("socket path is required")
	}
	if err := validateListenSocketPath(socketPath); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return nil, fmt.Errorf("create socket dir: %w", err)
	}
	if err := validateSocketParent(filepath.Dir(socketPath)); err != nil {
		return nil, err
	}
	if err := removeExistingSocket(socketPath); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	if err := validateSocketFileSecurity(socketPath); err != nil {
		_ = ln.Close()
		_ = os.Remove(socketPath)
		return nil, err
	}
	return ln, nil
}

func removeExistingSocket(socketPath string) error {
	info, err := os.Lstat(socketPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat existing socket path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to replace helper socket symlink %s", socketPath)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace non-socket helper path %s", socketPath)
	}
	if err := os.Remove(socketPath); err != nil {
		return fmt.Errorf("remove existing helper socket: %w", err)
	}
	return nil
}

func (s *Server) Serve(ctx context.Context, socketPath string) error {
	ln, err := ListenUnix(socketPath)
	if err != nil {
		return err
	}
	defer ln.Close()
	defer os.Remove(socketPath)
	return s.ServeListener(ctx, ln)
}

func (s *Server) ServeListener(ctx context.Context, ln net.Listener) error {
	if s == nil {
		s = NewServer(nil, nil)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	serveCtx, cancel := context.WithCancel(ctx)
	if s.Backend == nil {
		s.Backend = FailClosedBackend{}
	}
	if s.Authorizer == nil {
		s.Authorizer = denyAuthorizer{}
	}
	closer, hasCloser := s.Authorizer.(interface{ Close() })
	errCh := make(chan error, 1)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		<-serveCtx.Done()
		_ = ln.Close()
	}()
	if s.ReapInterval > 0 {
		registrationReaper, hasRegistrationReaper := s.Authorizer.(registrationReaper)
		orphanReaper, hasOrphanReaper := s.Backend.(orphanResourceReaper)
		if hasRegistrationReaper || hasOrphanReaper {
			workers.Add(1)
			go func() {
				defer workers.Done()
				s.serveReaper(serveCtx, registrationReaper, orphanReaper)
			}()
		}
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-serveCtx.Done():
					errCh <- serveCtx.Err()
				default:
					errCh <- err
				}
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				s.ServeConn(serveCtx, conn)
			}()
		}
	}()
	serveErr := <-errCh
	cancel()
	_ = ln.Close()
	workers.Wait()
	if hasCloser {
		closer.Close()
	}
	return serveErr
}

func (s *Server) serveReaper(ctx context.Context, registrations registrationReaper, orphans orphanResourceReaper) {
	ticker := time.NewTicker(s.ReapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if registrations != nil {
				for _, req := range registrations.ReapableRegistrations() {
					resp, err := s.Backend.CleanupSession(ctx, PeerInfo{}, req)
					registrations.CompleteCleanup(req, err == nil && resp.OK)
				}
			}
			if orphans != nil {
				_ = orphans.ReapOrphanedResources(ctx)
			}
		}
	}
}

func (s *Server) ServeConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	if s == nil {
		s = NewServer(nil, nil)
	}
	if s.Backend == nil {
		s.Backend = FailClosedBackend{}
	}
	if s.Authorizer == nil {
		s.Authorizer = denyAuthorizer{}
	}
	if s.MaxBytes <= 0 {
		s.MaxBytes = 1 << 20
	}
	if s.ReadTimeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(s.ReadTimeout))
	}
	data, err := io.ReadAll(io.LimitReader(conn, s.MaxBytes+1))
	if err != nil {
		s.writeGenericError(conn, fmt.Errorf("read request: %w", err))
		return
	}
	if int64(len(data)) > s.MaxBytes {
		s.writeGenericError(conn, fmt.Errorf("request exceeds %d bytes", s.MaxBytes))
		return
	}
	peer := peerInfo(conn)
	defer peer.closeIdentity()
	resp := s.dispatch(ctx, peer, data)
	stop := false
	if wrapped, ok := resp.(stopAfterResponse); ok {
		resp = wrapped.response
		stop = true
	}
	if s.WriteTimeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(s.WriteTimeout))
	}
	_ = json.NewEncoder(conn).Encode(resp)
	if stop && s.Stop != nil {
		s.Stop()
	}
}

func (s *Server) writeGenericError(conn net.Conn, err error) {
	if s.WriteTimeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(s.WriteTimeout))
	}
	_ = json.NewEncoder(conn).Encode(ErrorResponse{ProtocolVersion: CurrentProtocolVersion, OK: false, Error: err.Error()})
}

func (s *Server) dispatch(ctx context.Context, peer PeerInfo, data []byte) any {
	env, err := DecodeRequestEnvelopeJSON(data)
	if err != nil {
		return ErrorResponse{ProtocolVersion: CurrentProtocolVersion, OK: false, Error: err.Error()}
	}
	switch env.Operation {
	case OperationRegisterSessionCgroup:
		req, err := DecodeRegisterSessionCgroupRequestJSON(env.Request)
		if err != nil {
			return RegisterSessionCgroupResponse{ProtocolVersion: CurrentProtocolVersion, OK: false, Error: err.Error()}
		}
		if err := s.Authorizer.AuthorizeRegister(ctx, peer, req); err != nil {
			return RegisterSessionCgroupResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}
		}
		resp, err := s.Backend.RegisterSessionCgroup(ctx, peer, req)
		out := ensureRegisterResponse(req, resp, err)
		lifecycle, managed := s.Authorizer.(authorizerLifecycle)
		if !out.OK {
			if managed {
				lifecycle.RollbackRegister(req.SessionID, req.CgroupPath)
			}
			return out
		}
		if managed {
			registrationID, completeErr := lifecycle.CompleteRegister(req, out.CgroupID)
			if completeErr != nil {
				cleanupReq := CleanupSessionRequest{
					ProtocolVersion: CurrentProtocolVersion,
					RequestID:       req.RequestID,
					SessionID:       req.SessionID,
					CgroupID:        out.CgroupID,
					CgroupPath:      req.CgroupPath,
					Reason:          CleanupReasonRegistrationFailed,
				}
				_, _ = s.Backend.CleanupSession(ctx, peer, cleanupReq)
				lifecycle.RollbackRegister(req.SessionID, req.CgroupPath)
				out.OK = false
				out.NetworkPolicyEnforced = false
				out.Error = completeErr.Error()
				return out
			}
			// Legacy version-1 peers use session_nonce and strictly decode the
			// original response shape. Keep their response compatible; they remain
			// bound to PID/start-time, UID/GID, cgroup path/ID, mode, and session.
			if strings.TrimSpace(req.HelperInstanceCredential) != "" {
				out.RegistrationID = registrationID
			}
		}
		return out
	case OperationUpdatePolicyMap:
		req, err := DecodeUpdatePolicyMapRequestJSON(env.Request)
		if err != nil {
			return UpdatePolicyMapResponse{ProtocolVersion: CurrentProtocolVersion, OK: false, Error: err.Error()}
		}
		if err := s.Authorizer.AuthorizeUpdate(ctx, peer, req); err != nil {
			return UpdatePolicyMapResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}
		}
		resp, err := s.Backend.UpdatePolicyMap(ctx, peer, req)
		out := ensureUpdateResponse(req, resp, err)
		if lifecycle, ok := s.Authorizer.(updateLifecycle); ok {
			lifecycle.CompleteUpdate(req)
		}
		return out
	case OperationCleanupSession:
		req, err := DecodeCleanupSessionRequestJSON(env.Request)
		if err != nil {
			return CleanupSessionResponse{ProtocolVersion: CurrentProtocolVersion, OK: false, Error: err.Error()}
		}
		if err := s.Authorizer.AuthorizeCleanup(ctx, peer, req); err != nil {
			return CleanupSessionResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, SessionID: req.SessionID, OK: false, Error: err.Error()}
		}
		resp, err := s.Backend.CleanupSession(ctx, peer, req)
		out := ensureCleanupResponse(req, resp, err)
		if lifecycle, ok := s.Authorizer.(authorizerLifecycle); ok {
			lifecycle.CompleteCleanup(req, out.OK)
		}
		return out
	case OperationReleaseInstance:
		req, err := DecodeReleaseInstanceRequestJSON(env.Request)
		if err != nil {
			return ReleaseInstanceResponse{ProtocolVersion: CurrentProtocolVersion, OK: false, Error: err.Error()}
		}
		if s.InstanceController == nil {
			return ReleaseInstanceResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, LeaseID: req.LeaseID, OK: false, Error: "nethelper instance release is not configured"}
		}
		resp, err := s.InstanceController.ReleaseInstance(ctx, peer, req)
		out := ensureReleaseResponse(req, resp, err)
		if out.OK {
			return stopAfterResponse{response: out}
		}
		return out
	default:
		return ErrorResponse{ProtocolVersion: CurrentProtocolVersion, OK: false, Error: fmt.Sprintf("invalid operation %q", env.Operation)}
	}
}

func ensureRegisterResponse(req RegisterSessionCgroupRequest, resp RegisterSessionCgroupResponse, err error) RegisterSessionCgroupResponse {
	if resp.ProtocolVersion == 0 {
		resp.ProtocolVersion = CurrentProtocolVersion
	}
	if resp.RequestID == "" {
		resp.RequestID = req.RequestID
	}
	if resp.SessionID == "" {
		resp.SessionID = req.SessionID
	}
	if err != nil {
		resp.OK = false
		if resp.Error == "" {
			resp.Error = err.Error()
		}
	}
	return resp
}

func ensureUpdateResponse(req UpdatePolicyMapRequest, resp UpdatePolicyMapResponse, err error) UpdatePolicyMapResponse {
	if resp.ProtocolVersion == 0 {
		resp.ProtocolVersion = CurrentProtocolVersion
	}
	if resp.RequestID == "" {
		resp.RequestID = req.RequestID
	}
	if resp.SessionID == "" {
		resp.SessionID = req.SessionID
	}
	if err != nil {
		resp.OK = false
		if resp.Error == "" {
			resp.Error = err.Error()
		}
	}
	return resp
}

func ensureCleanupResponse(req CleanupSessionRequest, resp CleanupSessionResponse, err error) CleanupSessionResponse {
	if resp.ProtocolVersion == 0 {
		resp.ProtocolVersion = CurrentProtocolVersion
	}
	if resp.RequestID == "" {
		resp.RequestID = req.RequestID
	}
	if resp.SessionID == "" {
		resp.SessionID = req.SessionID
	}
	if err != nil {
		resp.OK = false
		if resp.Error == "" {
			resp.Error = err.Error()
		}
	}
	return resp
}

func ensureReleaseResponse(req ReleaseInstanceRequest, resp ReleaseInstanceResponse, err error) ReleaseInstanceResponse {
	if resp.ProtocolVersion == 0 {
		resp.ProtocolVersion = CurrentProtocolVersion
	}
	if resp.RequestID == "" {
		resp.RequestID = req.RequestID
	}
	if resp.LeaseID == "" {
		resp.LeaseID = req.LeaseID
	}
	if err != nil {
		resp.OK = false
		if resp.Error == "" {
			resp.Error = err.Error()
		}
	}
	return resp
}

// Client is a small synchronous helper client. Dialed sockets are created by
// Go with CLOEXEC; callers must still ensure EnvSocket, EnvCredentialFile, and
// both helper-instance credential spellings are absent from tool environments.
type Client struct {
	SocketPath string
	Timeout    time.Duration
	MaxBytes   int64
	Dial       func(context.Context, string, string) (net.Conn, error)

	mu            sync.Mutex
	registrations map[string]clientRegistration
}

type clientRegistration struct {
	SessionID      string
	CgroupPath     string
	CgroupID       uint64
	RegistrationID string
}

func NewClient(socketPath string) *Client {
	return &Client{
		SocketPath:    socketPath,
		Timeout:       5 * time.Second,
		MaxBytes:      1 << 20,
		registrations: make(map[string]clientRegistration),
	}
}

func (c *Client) RegisterSessionCgroup(ctx context.Context, req RegisterSessionCgroupRequest) (RegisterSessionCgroupResponse, error) {
	if err := req.Validate(); err != nil {
		return RegisterSessionCgroupResponse{}, err
	}
	var resp RegisterSessionCgroupResponse
	err := c.roundTrip(ctx, OperationRegisterSessionCgroup, req, &resp)
	if err != nil {
		return resp, err
	}
	if !resp.OK && shouldRetryLegacyCredential(req, resp.Error) {
		legacyReq := req
		legacyReq.SessionNonce = req.HelperInstanceCredential
		legacyReq.HelperInstanceCredential = ""
		resp = RegisterSessionCgroupResponse{}
		if err := c.roundTrip(ctx, OperationRegisterSessionCgroup, legacyReq, &resp); err != nil {
			return resp, err
		}
		req = legacyReq
	}
	if err := validateResponseIdentity(resp.ProtocolVersion, resp.RequestID, resp.SessionID, req.RequestID, req.SessionID); err != nil {
		return resp, err
	}
	if !resp.OK {
		return resp, responseError(resp.Error)
	}
	c.rememberRegistration(req, resp)
	return resp, nil
}

func shouldRetryLegacyCredential(req RegisterSessionCgroupRequest, responseMessage string) bool {
	if strings.TrimSpace(req.HelperInstanceCredential) == "" || strings.TrimSpace(req.SessionNonce) != "" {
		return false
	}
	message := strings.ToLower(responseMessage)
	return strings.Contains(message, "unknown field") && strings.Contains(message, "helper_instance_credential")
}

func (c *Client) UpdatePolicyMap(ctx context.Context, req UpdatePolicyMapRequest) (UpdatePolicyMapResponse, error) {
	c.fillUpdateRegistration(&req)
	if err := req.Validate(); err != nil {
		return UpdatePolicyMapResponse{}, err
	}
	var resp UpdatePolicyMapResponse
	err := c.roundTrip(ctx, OperationUpdatePolicyMap, req, &resp)
	if err != nil {
		return resp, err
	}
	if err := validateResponseIdentity(resp.ProtocolVersion, resp.RequestID, resp.SessionID, req.RequestID, req.SessionID); err != nil {
		return resp, err
	}
	if !resp.OK {
		return resp, responseError(resp.Error)
	}
	return resp, nil
}

func (c *Client) CleanupSession(ctx context.Context, req CleanupSessionRequest) (CleanupSessionResponse, error) {
	c.fillCleanupRegistration(&req)
	if err := req.Validate(); err != nil {
		return CleanupSessionResponse{}, err
	}
	var resp CleanupSessionResponse
	err := c.roundTrip(ctx, OperationCleanupSession, req, &resp)
	if err != nil {
		return resp, err
	}
	if err := validateResponseIdentity(resp.ProtocolVersion, resp.RequestID, resp.SessionID, req.RequestID, req.SessionID); err != nil {
		return resp, err
	}
	if !resp.OK {
		return resp, responseError(resp.Error)
	}
	c.forgetRegistration(req.SessionID, req.CgroupPath, req.CgroupID)
	return resp, nil
}

// ReleaseInstance asks an ephemeral helper to stop after all command
// registrations are gone. Persistent helpers reject this operation.
func (c *Client) ReleaseInstance(ctx context.Context, req ReleaseInstanceRequest) (ReleaseInstanceResponse, error) {
	if err := req.Validate(); err != nil {
		return ReleaseInstanceResponse{}, err
	}
	var resp ReleaseInstanceResponse
	if err := c.roundTrip(ctx, OperationReleaseInstance, req, &resp); err != nil {
		return resp, err
	}
	if resp.ProtocolVersion != CurrentProtocolVersion {
		return resp, fmt.Errorf("nethelper response protocol_version=%d, want %d", resp.ProtocolVersion, CurrentProtocolVersion)
	}
	if resp.RequestID != strings.TrimSpace(req.RequestID) {
		return resp, fmt.Errorf("nethelper response request_id does not match request")
	}
	if resp.LeaseID != strings.TrimSpace(req.LeaseID) {
		return resp, fmt.Errorf("nethelper response lease_id does not match request")
	}
	if !resp.OK {
		return resp, responseError(resp.Error)
	}
	return resp, nil
}

func (c *Client) rememberRegistration(req RegisterSessionCgroupRequest, resp RegisterSessionCgroupResponse) {
	if c == nil || strings.TrimSpace(resp.RegistrationID) == "" || resp.CgroupID == 0 {
		return
	}
	reg := clientRegistration{
		SessionID:      req.SessionID,
		CgroupPath:     cleanCgroupPath(req.CgroupPath),
		CgroupID:       resp.CgroupID,
		RegistrationID: resp.RegistrationID,
	}
	c.mu.Lock()
	if c.registrations == nil {
		c.registrations = make(map[string]clientRegistration)
	}
	c.registrations[clientPathKey(reg.SessionID, reg.CgroupPath)] = reg
	c.registrations[clientIDKey(reg.SessionID, reg.CgroupID)] = reg
	c.mu.Unlock()
}

func (c *Client) fillUpdateRegistration(req *UpdatePolicyMapRequest) {
	if req == nil {
		return
	}
	if reg, ok := c.lookupRegistration(req.SessionID, req.CgroupPath, req.CgroupID); ok {
		if strings.TrimSpace(req.RegistrationID) == "" {
			req.RegistrationID = reg.RegistrationID
		}
		if strings.TrimSpace(req.CgroupPath) == "" {
			req.CgroupPath = reg.CgroupPath
		}
		if req.CgroupID == 0 {
			req.CgroupID = reg.CgroupID
		}
	}
}

func (c *Client) fillCleanupRegistration(req *CleanupSessionRequest) {
	if req == nil {
		return
	}
	if reg, ok := c.lookupRegistration(req.SessionID, req.CgroupPath, req.CgroupID); ok {
		if strings.TrimSpace(req.RegistrationID) == "" {
			req.RegistrationID = reg.RegistrationID
		}
		if strings.TrimSpace(req.CgroupPath) == "" {
			req.CgroupPath = reg.CgroupPath
		}
		if req.CgroupID == 0 {
			req.CgroupID = reg.CgroupID
		}
	}
}

func (c *Client) lookupRegistration(sessionID, cgroupPath string, cgroupID uint64) (clientRegistration, bool) {
	if c == nil {
		return clientRegistration{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var reg clientRegistration
	var ok bool
	if strings.TrimSpace(cgroupPath) != "" {
		reg, ok = c.registrations[clientPathKey(sessionID, cgroupPath)]
	}
	if !ok && cgroupID != 0 {
		reg, ok = c.registrations[clientIDKey(sessionID, cgroupID)]
	}
	return reg, ok
}

func (c *Client) forgetRegistration(sessionID, cgroupPath string, cgroupID uint64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if strings.TrimSpace(cgroupPath) != "" {
		if reg, ok := c.registrations[clientPathKey(sessionID, cgroupPath)]; ok {
			delete(c.registrations, clientIDKey(reg.SessionID, reg.CgroupID))
		}
		delete(c.registrations, clientPathKey(sessionID, cgroupPath))
	}
	if cgroupID != 0 {
		if reg, ok := c.registrations[clientIDKey(sessionID, cgroupID)]; ok {
			delete(c.registrations, clientPathKey(reg.SessionID, reg.CgroupPath))
		}
		delete(c.registrations, clientIDKey(sessionID, cgroupID))
	}
}

func clientPathKey(sessionID, cgroupPath string) string {
	return strings.TrimSpace(sessionID) + "\x00path\x00" + cleanCgroupPath(cgroupPath)
}

func clientIDKey(sessionID string, cgroupID uint64) string {
	return fmt.Sprintf("%s\x00id\x00%d", strings.TrimSpace(sessionID), cgroupID)
}

func (c *Client) roundTrip(ctx context.Context, op Operation, req any, resp any) error {
	if c == nil || strings.TrimSpace(c.SocketPath) == "" {
		return fmt.Errorf("nethelper socket path is required")
	}
	if runtime.GOOS == "windows" {
		return fmt.Errorf("nethelper unix socket is not supported on windows")
	}
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return err
	}
	env := RequestEnvelope{ProtocolVersion: CurrentProtocolVersion, Operation: op, Request: payload}
	wire, err := json.Marshal(env)
	if err != nil {
		return err
	}
	dial := c.Dial
	if dial == nil {
		if err := validateClientSocketPath(c.SocketPath); err != nil {
			return err
		}
		d := net.Dialer{}
		dial = d.DialContext
	}
	conn, err := dial(ctx, "unix", c.SocketPath)
	if err != nil {
		return err
	}
	defer conn.Close()
	if c.Timeout > 0 {
		deadline := time.Now().Add(c.Timeout)
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(wire); err != nil {
		return err
	}
	// The server reads until EOF before responding, so close the write side when
	// possible while keeping the read side open.
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	max := c.MaxBytes
	if max <= 0 {
		max = 1 << 20
	}
	data, err := io.ReadAll(io.LimitReader(conn, max+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > max {
		return fmt.Errorf("nethelper response exceeds %d bytes", max)
	}
	if err := decodeStrictJSON(data, resp); err != nil {
		var er ErrorResponse
		if erErr := decodeStrictJSON(data, &er); erErr == nil && er.Error != "" {
			return errors.New(er.Error)
		}
		return err
	}
	return nil
}

func validateResponseIdentity(protocolVersion int, responseRequestID, responseSessionID, requestID, sessionID string) error {
	if protocolVersion != CurrentProtocolVersion {
		return fmt.Errorf("nethelper response protocol_version=%d, want %d", protocolVersion, CurrentProtocolVersion)
	}
	if responseRequestID != strings.TrimSpace(requestID) {
		return fmt.Errorf("nethelper response request_id does not match request")
	}
	if responseSessionID != strings.TrimSpace(sessionID) {
		return fmt.Errorf("nethelper response session_id does not match request")
	}
	return nil
}

func responseError(msg string) error {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		msg = "nethelper request failed"
	}
	return errors.New(msg)
}
