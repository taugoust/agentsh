package externalrunner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
)

func TestRemoteHostEgressApprovalUsesBoundUnixSupervisor(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "supervisor.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	binding := &HostEgressApprovalBinding{
		ParentSessionID: "session-11111111-1111-1111-1111-111111111111",
		SupervisorURL:   "unix://" + socketPath,
		Token:           token,
	}
	requestSeen := make(chan remoteHostEgressApprovalRequest, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sessions/"+binding.ParentSessionID+"/tools/request_guest_egress_approval" || r.Header.Get(HostEgressApprovalHeader) != token {
			http.Error(w, "bad binding", http.StatusUnauthorized)
			return
		}
		var request remoteHostEgressApprovalRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		requestSeen <- request
		_ = json.NewEncoder(w).Encode(approvals.Resolution{Approved: true, Reason: "operator", Scope: approvals.ScopeSession, At: time.Now().UTC(), ScopeKind: "network", ScopeKey: "network:test", ScopeLabel: "unknown.example:443"})
	})}
	go server.Serve(listener)
	defer server.Shutdown(context.Background())

	manager, err := newHostEgressApprovalManager(binding, "session-22222222-2222-2222-2222-222222222222", nil)
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := manager.RequestApproval(context.Background(), approvals.Request{Kind: "network", Target: "unknown.example:443", Rule: "unknown-egress"})
	if err != nil || !resolution.Approved || resolution.Scope != approvals.ScopeSession {
		t.Fatalf("resolution = %+v, err = %v", resolution, err)
	}
	select {
	case request := <-requestSeen:
		if request.DraftSessionID != "session-22222222-2222-2222-2222-222222222222" || request.Target != "unknown.example:443" || request.Kind != "network" {
			t.Fatalf("unexpected remote request: %+v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("remote approval request was not observed")
	}
}

func TestHostEgressApprovalEnvironmentFailsClosedWhenPartial(t *testing.T) {
	for _, name := range []string{HostEgressApprovalTokenEnv, HostEgressApprovalCredentialEnv, HostEgressApprovalSessionEnv, HostEgressApprovalSupervisorEnv} {
		t.Setenv(name, "")
	}
	if binding, err := hostEgressApprovalBindingFromEnvironment(); err != nil || binding != nil {
		t.Fatalf("empty binding = %+v, %v", binding, err)
	}
	t.Setenv(HostEgressApprovalTokenEnv, "present-only")
	if _, err := hostEgressApprovalBindingFromEnvironment(); err == nil {
		t.Fatal("partial approval environment was accepted")
	}
}

func TestHostEgressApprovalCredentialFile(t *testing.T) {
	for _, name := range []string{HostEgressApprovalTokenEnv, HostEgressApprovalCredentialEnv, HostEgressApprovalSessionEnv, HostEgressApprovalSupervisorEnv} {
		t.Setenv(name, "")
	}
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	path := filepath.Join(t.TempDir(), "approval.token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(HostEgressApprovalCredentialEnv, path)
	t.Setenv(HostEgressApprovalSessionEnv, "session-11111111-1111-1111-1111-111111111111")
	t.Setenv(HostEgressApprovalSupervisorEnv, "unix://"+filepath.Join(t.TempDir(), "supervisor.sock"))
	binding, err := hostEgressApprovalBindingFromEnvironment()
	if err != nil || binding == nil || binding.Token != token {
		t.Fatalf("credential binding = %+v, %v", binding, err)
	}
}
