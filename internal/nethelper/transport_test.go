package nethelper

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "agentsh-nethelper-test-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "helper.sock")
}

type recordingBackend struct {
	mu          sync.Mutex
	registers   []RegisterSessionCgroupRequest
	updates     []UpdatePolicyMapRequest
	cleanups    []CleanupSessionRequest
	cleanupFail bool
}

func (b *recordingBackend) RegisterSessionCgroup(_ context.Context, _ PeerInfo, req RegisterSessionCgroupRequest) (RegisterSessionCgroupResponse, error) {
	b.mu.Lock()
	b.registers = append(b.registers, req)
	b.mu.Unlock()
	return RegisterSessionCgroupResponse{OK: true, Tier: req.Tier.Normalized(), Mode: req.Mode.Normalized(), CgroupID: 42, NetworkPolicyEnforced: req.Tier.Normalized() == EnforcementTierHelperEBPFProxy}, nil
}

func (b *recordingBackend) UpdatePolicyMap(_ context.Context, _ PeerInfo, req UpdatePolicyMapRequest) (UpdatePolicyMapResponse, error) {
	b.mu.Lock()
	b.updates = append(b.updates, req)
	b.mu.Unlock()
	return UpdatePolicyMapResponse{OK: true, DefaultDeny: req.DefaultDeny, AllowEntries: len(req.Allow), DenyEntries: len(req.Deny)}, nil
}

func (b *recordingBackend) CleanupSession(_ context.Context, _ PeerInfo, req CleanupSessionRequest) (CleanupSessionResponse, error) {
	b.mu.Lock()
	b.cleanups = append(b.cleanups, req)
	fail := b.cleanupFail
	b.mu.Unlock()
	if fail {
		return CleanupSessionResponse{OK: false, Error: "deterministic cleanup failure"}, fmt.Errorf("deterministic cleanup failure")
	}
	return CleanupSessionResponse{OK: true, RemovedPins: []string{req.SessionID}}, nil
}

func TestClientServerRoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets unsupported on windows")
	}
	backend := &recordingBackend{}
	server := NewServer(backend, AllowAuthorizer{})
	socket := shortSocketPath(t)
	ln, err := ListenUnix(socket)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.ServeListener(ctx, ln) }()

	client := NewClient(socket)
	client.Timeout = 2 * time.Second
	reg, err := client.RegisterSessionCgroup(context.Background(), RegisterSessionCgroupRequest{
		ProtocolVersion: CurrentProtocolVersion,
		RequestID:       "req-1",
		SessionID:       "session-1",
		CgroupPath:      filepath.Join("sys", "fs", "cgroup", "agentsh", "session-1"),
		Tier:            EnforcementTierHelperEBPFProxy,
		Mode:            BuiltinModeCgroupConnectGate,
		Proxy:           &ProxyEndpoint{Host: "127.0.0.1", Port: 18080},
	})
	if err != nil {
		t.Fatalf("RegisterSessionCgroup: %v", err)
	}
	if !reg.OK || reg.CgroupID != 42 || !reg.NetworkPolicyEnforced {
		t.Fatalf("register response = %+v", reg)
	}

	upd, err := client.UpdatePolicyMap(context.Background(), UpdatePolicyMapRequest{
		ProtocolVersion: CurrentProtocolVersion,
		RequestID:       "req-2",
		SessionID:       "session-1",
		CgroupID:        reg.CgroupID,
		DefaultDeny:     true,
		Allow:           []PolicyMapEntry{{CIDR: "127.0.0.1/32", Protocol: TransportProtocolTCP}},
	})
	if err != nil {
		t.Fatalf("UpdatePolicyMap: %v", err)
	}
	if !upd.OK || !upd.DefaultDeny || upd.AllowEntries != 1 {
		t.Fatalf("update response = %+v", upd)
	}

	clean, err := client.CleanupSession(context.Background(), CleanupSessionRequest{SessionID: "session-1", CgroupID: reg.CgroupID, Reason: CleanupReasonSessionEnded})
	if err != nil {
		t.Fatalf("CleanupSession: %v", err)
	}
	if !clean.OK || len(clean.RemovedPins) != 1 {
		t.Fatalf("cleanup response = %+v", clean)
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.registers) != 1 || len(backend.updates) != 1 || len(backend.cleanups) != 1 {
		t.Fatalf("backend calls: registers=%d updates=%d cleanups=%d", len(backend.registers), len(backend.updates), len(backend.cleanups))
	}
}

func TestFailedRegistrationCompensationRetainsAuthenticatedTombstone(t *testing.T) {
	const credential = "0123456789abcdef0123456789abcdef"
	backend := &recordingBackend{cleanupFail: true}
	authorizer := NewSupervisorAuthorizer(SupervisorAuthorizerOptions{HelperInstanceCredential: credential})
	server := NewServer(backend, authorizer)
	peer := PeerInfo{PID: 123, UID: 1000, GID: 100, Supported: true}
	register := func(session, path, request string) RegisterSessionCgroupResponse {
		req := RegisterSessionCgroupRequest{ProtocolVersion: 1, RequestID: request, SessionID: session,
			SupervisorPID: peer.PID, SupervisorCgroupPath: filepath.Join(string(filepath.Separator), "supervisor"),
			CgroupPath: path, HelperInstanceCredential: credential, Tier: EnforcementTierHelperEBPFProxy,
			Mode: BuiltinModeCgroupConnectGate, Proxy: &ProxyEndpoint{Host: "127.0.0.1", Port: 18080}}
		requestJSON, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := json.Marshal(RequestEnvelope{ProtocolVersion: 1, Operation: OperationRegisterSessionCgroup, Request: requestJSON})
		if err != nil {
			t.Fatal(err)
		}
		resp, ok := server.dispatch(context.Background(), peer, wire).(RegisterSessionCgroupResponse)
		if !ok {
			t.Fatalf("response type was not registration response")
		}
		return resp
	}
	first := register("session-1", filepath.Join(string(filepath.Separator), "supervisor", "one"), "register-1")
	if !first.OK {
		t.Fatalf("first registration: %+v", first)
	}
	secondPath := filepath.Join(string(filepath.Separator), "supervisor", "two")
	second := register("session-2", secondPath, "register-2")
	if second.OK || second.RegistrationID == "" || !strings.Contains(second.Error, "registration retained") {
		t.Fatalf("failed compensation response=%+v", second)
	}
	if got := authorizer.ActiveRegistrationCount(); got != 2 {
		t.Fatalf("active registration count=%d, want established registration plus tombstone", got)
	}
	backend.mu.Lock()
	backend.cleanupFail = false
	backend.mu.Unlock()
	cleanupReq := CleanupSessionRequest{ProtocolVersion: 1, RequestID: "cleanup-2", SessionID: "session-2",
		RegistrationID: second.RegistrationID, CgroupID: second.CgroupID, CgroupPath: secondPath, Reason: CleanupReasonRegistrationFailed}
	requestJSON, _ := json.Marshal(cleanupReq)
	wire, _ := json.Marshal(RequestEnvelope{ProtocolVersion: 1, Operation: OperationCleanupSession, Request: requestJSON})
	cleanup, ok := server.dispatch(context.Background(), peer, wire).(CleanupSessionResponse)
	if !ok || !cleanup.OK {
		t.Fatalf("retry cleanup=%+v", cleanup)
	}
	if got := authorizer.ActiveRegistrationCount(); got != 1 {
		t.Fatalf("registration count after confirmed retry=%d, want 1", got)
	}
}

func TestClientServerReleaseCancellationRecoversAdmission(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets unsupported on windows")
	}
	const credential = "0123456789abcdef0123456789abcdef"
	gate := NewOperationGate()
	held, err := gate.Admit()
	if err != nil {
		t.Fatal(err)
	}
	defer held()
	server := NewServer(&recordingBackend{}, AllowAuthorizer{})
	server.InstanceController = NewEphemeralInstanceController(EphemeralInstanceControllerOptions{
		LeaseID: "lease-11111111-1111-4111-8111-111111111111", HelperInstanceCredential: credential,
		ExpectedUID: uint32(os.Getuid()), Operations: gate, ReleaseDrainTimeout: 40 * time.Millisecond,
	})
	socket := shortSocketPath(t)
	ln, err := ListenUnix(socket)
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, stop := context.WithCancel(context.Background())
	defer stop()
	go func() { _ = server.ServeListener(serveCtx, ln) }()
	client := NewClient(socket)
	client.Timeout = time.Second
	requestCtx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()
	_, err = client.ReleaseInstance(requestCtx, ReleaseInstanceRequest{ProtocolVersion: 1, RequestID: "release-cancel",
		LeaseID: "lease-11111111-1111-4111-8111-111111111111", HelperInstanceCredential: credential})
	if err == nil {
		t.Fatal("cancelled transport release unexpectedly succeeded")
	}
	time.Sleep(100 * time.Millisecond)
	cleanup, err := gate.Admit()
	if err != nil {
		t.Fatalf("transport cancellation left admission closed: %v", err)
	}
	cleanup()
}

func TestClientServerReleaseStopsAfterResponse(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets unsupported on windows")
	}
	const credential = "0123456789abcdef0123456789abcdef"
	server := NewServer(&recordingBackend{}, AllowAuthorizer{})
	server.InstanceController = NewEphemeralInstanceController(EphemeralInstanceControllerOptions{
		LeaseID:                  "lease-11111111-1111-4111-8111-111111111111",
		HelperInstanceCredential: credential,
		ExpectedUID:              uint32(os.Getuid()),
		ExpectedGID:              uint32(os.Getgid()),
		EnforceGID:               true,
		Registrations:            fixedRegistrationCount(0),
	})
	socket := shortSocketPath(t)
	ln, err := ListenUnix(socket)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	server.Stop = cancel
	done := make(chan error, 1)
	go func() { done <- server.ServeListener(ctx, ln) }()

	client := NewClient(socket)
	client.Timeout = 2 * time.Second
	resp, err := client.ReleaseInstance(context.Background(), ReleaseInstanceRequest{
		ProtocolVersion:          CurrentProtocolVersion,
		RequestID:                "release-1",
		LeaseID:                  "lease-11111111-1111-4111-8111-111111111111",
		HelperInstanceCredential: credential,
	})
	if err != nil {
		t.Fatalf("ReleaseInstance: %v", err)
	}
	if !resp.OK {
		t.Fatalf("release response: %+v", resp)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop after release response")
	}
}

func TestClientServerAuthenticatedStatusAndRenewal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets unsupported on windows")
	}
	const credential = "0123456789abcdef0123456789abcdef"
	const lease = "lease-11111111-1111-4111-8111-111111111111"
	created := time.Now().UTC().Truncate(time.Second)
	server := NewServer(&recordingBackend{}, AllowAuthorizer{})
	wantAttestation := CompositionRuntimeAttestation{
		Runtime:        CompositionRuntimeInode{Device: 1, Inode: 2, Mode: 0o41733, UID: 0, GID: 0},
		LeaseDirectory: CompositionRuntimeInode{Device: 1, Inode: 1, Mode: 0o40711, UID: 0, GID: 0},
	}
	server.InstanceController = NewEphemeralInstanceController(EphemeralInstanceControllerOptions{
		LeaseID: lease, UnitName: "unit.service", HelperInstanceCredential: credential,
		ExpectedUID: uint32(os.Getuid()), ExpectedGID: uint32(os.Getgid()), EnforceGID: true,
		CreatedAt: created, HardExpiresAt: created.Add(60 * time.Hour), Registrations: fixedRegistrationCount(0),
		AttestCompositionRuntime: func(uint32, string) (CompositionRuntimeAttestation, error) { return wantAttestation, nil },
	})
	socket := shortSocketPath(t)
	ln, err := ListenUnix(socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.ServeListener(ctx, ln) }()
	client := NewClient(socket)
	status, err := client.InstanceStatus(context.Background(), InstanceStatusRequest{ProtocolVersion: 1, RequestID: "status-1", LeaseID: lease, HelperInstanceCredential: credential})
	if err != nil || status.Status != "active" || !containsString(status.Capabilities, "renew_instance") || !containsString(status.Capabilities, "attest_composition_runtime") {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	attested, err := client.AttestCompositionRuntime(context.Background(), AttestCompositionRuntimeRequest{
		ProtocolVersion: CurrentProtocolVersion, RequestID: "attest-1", LeaseID: lease, HelperInstanceCredential: credential,
	})
	if err != nil || !attested.OK || attested.Attestation != wantAttestation {
		t.Fatalf("attested=%+v err=%v", attested, err)
	}
	renewed, err := client.RenewInstance(context.Background(), RenewInstanceRequest{ProtocolVersion: 1, RequestID: "renew-1", LeaseID: lease, HelperInstanceCredential: credential})
	if err != nil || renewed.RenewalGeneration != 1 {
		t.Fatalf("renewed=%+v err=%v", renewed, err)
	}
	wire, err := json.Marshal(renewed)
	if err != nil || strings.Contains(string(wire), credential) {
		t.Fatalf("credential leaked in response: %s err=%v", wire, err)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestServerRejectsUnknownOperationBeforeBackend(t *testing.T) {
	backend := &recordingBackend{}
	server := NewServer(backend, AllowAuthorizer{})
	body := []byte(`{"protocol_version":1,"operation":"load_bpf_object","request":{}}`)
	resp := server.dispatch(context.Background(), PeerInfo{}, body)
	errResp, ok := resp.(ErrorResponse)
	if !ok {
		t.Fatalf("response type = %T, want ErrorResponse", resp)
	}
	if errResp.OK || !strings.Contains(errResp.Error, "invalid operation") {
		t.Fatalf("response = %+v", errResp)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.registers) != 0 || len(backend.updates) != 0 || len(backend.cleanups) != 0 {
		t.Fatal("backend should not be called for unknown operation")
	}
}

func TestServerRejectsUnknownTypedFieldBeforeBackend(t *testing.T) {
	backend := &recordingBackend{}
	server := NewServer(backend, AllowAuthorizer{})
	payload := map[string]any{
		"protocol_version": CurrentProtocolVersion,
		"session_id":       "session-1",
		"cgroup_path":      filepath.Join("sys", "fs", "cgroup", "agentsh", "session-1"),
		"bpf_bytecode":     "AAAA",
	}
	req, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(RequestEnvelope{ProtocolVersion: CurrentProtocolVersion, Operation: OperationRegisterSessionCgroup, Request: req})
	if err != nil {
		t.Fatal(err)
	}
	resp := server.dispatch(context.Background(), PeerInfo{}, env)
	reg, ok := resp.(RegisterSessionCgroupResponse)
	if !ok {
		t.Fatalf("response type = %T, want RegisterSessionCgroupResponse", resp)
	}
	if reg.OK || !strings.Contains(reg.Error, "unknown field") {
		t.Fatalf("response = %+v", reg)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.registers) != 0 {
		t.Fatal("backend should not be called for invalid typed request")
	}
}

func TestServerDefaultAuthorizerFailsClosed(t *testing.T) {
	backend := &recordingBackend{}
	server := NewServer(backend, nil)
	payload, err := json.Marshal(RegisterSessionCgroupRequest{SessionID: "session-1", CgroupPath: filepath.Join("sys", "fs", "cgroup", "agentsh", "session-1")})
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(RequestEnvelope{ProtocolVersion: CurrentProtocolVersion, Operation: OperationRegisterSessionCgroup, Request: payload})
	if err != nil {
		t.Fatal(err)
	}
	resp := server.dispatch(context.Background(), PeerInfo{}, env)
	reg, ok := resp.(RegisterSessionCgroupResponse)
	if !ok {
		t.Fatalf("response type = %T", resp)
	}
	if reg.OK || !strings.Contains(reg.Error, "authorizer is not configured") {
		t.Fatalf("response = %+v", reg)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.registers) != 0 {
		t.Fatal("backend should not be called when authorizer denies")
	}
}

func TestClientRejectsInvalidRequestWithoutDialing(t *testing.T) {
	client := NewClient("/does/not/matter.sock")
	client.Dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("dial should not be called")
	}
	_, err := client.RegisterSessionCgroup(context.Background(), RegisterSessionCgroupRequest{SessionID: "session-1"})
	if err == nil || !strings.Contains(err.Error(), "cgroup_path is required") {
		t.Fatalf("err = %v", err)
	}
}
