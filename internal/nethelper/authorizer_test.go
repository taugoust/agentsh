package nethelper

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestSupervisorAuthorizerRegisterUpdateCleanup(t *testing.T) {
	authz := NewSupervisorAuthorizer(SupervisorAuthorizerOptions{SessionNonce: "nonce-test", ExpectedUID: 1000, EnforceUID: true})
	peer := PeerInfo{PID: 4242, UID: 1000, GID: 1000, Supported: true}
	supervisorCgroup := filepath.Join("sys", "fs", "cgroup", "user.slice", "agentsh-supervisor")
	commandCgroup := filepath.Join(supervisorCgroup, "agentsh-session-command")

	reg := RegisterSessionCgroupRequest{
		SessionID:            "session-1",
		SessionNonce:         "nonce-test",
		SupervisorPID:        4242,
		SupervisorCgroupPath: supervisorCgroup,
		CgroupPath:           commandCgroup,
	}
	if err := authz.AuthorizeRegister(context.Background(), peer, reg); err != nil {
		t.Fatalf("AuthorizeRegister: %v", err)
	}
	registrationID, err := authz.CompleteRegister(reg, 42)
	if err != nil {
		t.Fatalf("CompleteRegister: %v", err)
	}

	upd := UpdatePolicyMapRequest{SessionID: "session-1", RegistrationID: registrationID, CgroupID: 42, CgroupPath: commandCgroup, DefaultDeny: true}
	if err := authz.AuthorizeUpdate(context.Background(), peer, upd); err != nil {
		t.Fatalf("AuthorizeUpdate: %v", err)
	}
	authz.CompleteUpdate(upd)

	cleanup := CleanupSessionRequest{SessionID: "session-1", RegistrationID: registrationID, CgroupID: 42, CgroupPath: commandCgroup, Reason: CleanupReasonSessionEnded}
	if err := authz.AuthorizeCleanup(context.Background(), peer, cleanup); err != nil {
		t.Fatalf("AuthorizeCleanup: %v", err)
	}
	if err := authz.AuthorizeUpdate(context.Background(), peer, upd); err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("AuthorizeUpdate after cleanup err = %v, want not registered", err)
	}
}

func TestSupervisorAuthorizerRejectsUnsafeRegisterRequests(t *testing.T) {
	supervisorCgroup := filepath.Join("sys", "fs", "cgroup", "user.slice", "agentsh-supervisor")
	commandCgroup := filepath.Join(supervisorCgroup, "agentsh-session-command")
	outsideCgroup := filepath.Join("sys", "fs", "cgroup", "other.slice", "agentsh-session-command")

	cases := []struct {
		name string
		auth *SupervisorAuthorizer
		peer PeerInfo
		req  RegisterSessionCgroupRequest
		want string
	}{
		{
			name: "missing expected nonce fails closed",
			auth: NewSupervisorAuthorizer(SupervisorAuthorizerOptions{}),
			peer: PeerInfo{PID: 4242, UID: 1000, Supported: true},
			req: RegisterSessionCgroupRequest{
				SessionID:            "session-1",
				SessionNonce:         "nonce-test",
				SupervisorPID:        4242,
				SupervisorCgroupPath: supervisorCgroup,
				CgroupPath:           commandCgroup,
			},
			want: "expected helper instance credential is not configured",
		},
		{
			name: "peer credentials required",
			auth: NewSupervisorAuthorizer(SupervisorAuthorizerOptions{SessionNonce: "nonce-test"}),
			peer: PeerInfo{},
			req: RegisterSessionCgroupRequest{
				SessionID:            "session-1",
				SessionNonce:         "nonce-test",
				SupervisorPID:        4242,
				SupervisorCgroupPath: supervisorCgroup,
				CgroupPath:           commandCgroup,
			},
			want: "peer credentials",
		},
		{
			name: "pid mismatch",
			auth: NewSupervisorAuthorizer(SupervisorAuthorizerOptions{SessionNonce: "nonce-test"}),
			peer: PeerInfo{PID: 1111, UID: 1000, Supported: true},
			req: RegisterSessionCgroupRequest{
				SessionID:            "session-1",
				SessionNonce:         "nonce-test",
				SupervisorPID:        4242,
				SupervisorCgroupPath: supervisorCgroup,
				CgroupPath:           commandCgroup,
			},
			want: "peer pid does not match",
		},
		{
			name: "bad nonce",
			auth: NewSupervisorAuthorizer(SupervisorAuthorizerOptions{SessionNonce: "nonce-test"}),
			peer: PeerInfo{PID: 4242, UID: 1000, Supported: true},
			req: RegisterSessionCgroupRequest{
				SessionID:            "session-1",
				SessionNonce:         "wrong",
				SupervisorPID:        4242,
				SupervisorCgroupPath: supervisorCgroup,
				CgroupPath:           commandCgroup,
			},
			want: "helper instance credential is not authorized",
		},
		{
			name: "target cgroup outside supervisor subtree",
			auth: NewSupervisorAuthorizer(SupervisorAuthorizerOptions{SessionNonce: "nonce-test"}),
			peer: PeerInfo{PID: 4242, UID: 1000, Supported: true},
			req: RegisterSessionCgroupRequest{
				SessionID:            "session-1",
				SessionNonce:         "nonce-test",
				SupervisorPID:        4242,
				SupervisorCgroupPath: supervisorCgroup,
				CgroupPath:           outsideCgroup,
			},
			want: "not inside supervisor delegated subtree",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.auth.AuthorizeRegister(context.Background(), tc.peer, tc.req)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("AuthorizeRegister err = %v, want contains %q", err, tc.want)
			}
		})
	}
}

func TestSupervisorAuthorizerFailedCleanupDoesNotUnregister(t *testing.T) {
	authz := NewSupervisorAuthorizer(SupervisorAuthorizerOptions{SessionNonce: "nonce-test"})
	peer := PeerInfo{PID: 4242, UID: 1000, Supported: true}
	badPeer := PeerInfo{PID: 9999, UID: 1000, Supported: true}
	supervisorCgroup := filepath.Join("sys", "fs", "cgroup", "user.slice", "agentsh-supervisor")
	commandCgroup := filepath.Join(supervisorCgroup, "agentsh-session-command")
	reg := RegisterSessionCgroupRequest{
		SessionID:            "session-1",
		SessionNonce:         "nonce-test",
		SupervisorPID:        4242,
		SupervisorCgroupPath: supervisorCgroup,
		CgroupPath:           commandCgroup,
	}
	if err := authz.AuthorizeRegister(context.Background(), peer, reg); err != nil {
		t.Fatalf("AuthorizeRegister: %v", err)
	}
	registrationID, err := authz.CompleteRegister(reg, 42)
	if err != nil {
		t.Fatalf("CompleteRegister: %v", err)
	}
	cleanup := CleanupSessionRequest{SessionID: "session-1", RegistrationID: registrationID, CgroupID: 42, CgroupPath: commandCgroup}
	if err := authz.AuthorizeCleanup(context.Background(), badPeer, cleanup); err == nil || !strings.Contains(err.Error(), "peer pid does not match") {
		t.Fatalf("AuthorizeCleanup bad peer err = %v", err)
	}
	upd := UpdatePolicyMapRequest{SessionID: "session-1", RegistrationID: registrationID, CgroupID: 42, CgroupPath: commandCgroup, DefaultDeny: true}
	if err := authz.AuthorizeUpdate(context.Background(), peer, upd); err != nil {
		t.Fatalf("registration was removed after failed cleanup: %v", err)
	}
	authz.CompleteUpdate(upd)
}

func TestSupervisorAuthorizerRejectsMapUpdateWithoutRegisteredPath(t *testing.T) {
	authz := NewSupervisorAuthorizer(SupervisorAuthorizerOptions{SessionNonce: "nonce-test"})
	peer := PeerInfo{PID: 4242, UID: 1000, Supported: true}
	if err := authz.AuthorizeUpdate(context.Background(), peer, UpdatePolicyMapRequest{SessionID: "session-1", CgroupID: 99, DefaultDeny: true}); err == nil || !strings.Contains(err.Error(), "cgroup_path is required") {
		t.Fatalf("AuthorizeUpdate err = %v, want cgroup_path requirement", err)
	}
}
