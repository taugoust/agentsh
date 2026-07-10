package nethelper

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordingBackend struct {
	mu        sync.Mutex
	registers []RegisterSessionCgroupRequest
	updates   []UpdatePolicyMapRequest
	cleanups  []CleanupSessionRequest
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
	b.mu.Unlock()
	return CleanupSessionResponse{OK: true, RemovedPins: []string{req.SessionID}}, nil
}

func TestClientServerRoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets unsupported on windows")
	}
	backend := &recordingBackend{}
	server := NewServer(backend, AllowAuthorizer{})
	socket := filepath.Join(t.TempDir(), "helper.sock")
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
