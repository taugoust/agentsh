package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/nethelper"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
	"google.golang.org/protobuf/types/known/structpb"
)

func provenRebindReport(now time.Time) *types.NetworkEnforcement {
	preflight := &types.NetworkPreflightEvidence{
		Status: types.NetworkEnforcementStatusReady, CommandID: "preflight", CgroupPath: "cgroup", CgroupID: 1,
		RegistrationID: "registration", CgroupPlacementProven: true, HelperAuthenticated: true, HelperAttachProven: true,
		DefaultDenyMapProven: true, InitialPolicyLocked: true, PolicyUpdateFailClosed: true, HelperCleanupProven: true,
		Pinned: true, ProxyListenerProven: true, ProxyConnectProven: true, ProxyEndpointID: "127.0.0.1:1234",
		ToolBoundaryProven: true, PrivateProcProven: true, CgroupFSHidden: true, HelperSocketHidden: true,
		CredentialSourceHidden: true, ControlPathsHidden: true, ReservedEnvScrubbed: true, InheritedDescriptorsClosed: true,
		NoNewPrivileges: true, CapabilitiesDropped: true, DirectBypassProven: true, LocalDirectTCPBlocked: true,
		UDPBlocked: true, RawSocketsBlocked: true, UnsupportedTrafficProven: true, FailClosedBarrierProven: true,
		ChildStoppedDuringSetup: true, RefusalLeftChildStopped: true, CheckedAt: now,
	}
	report := &types.NetworkEnforcement{
		Requested: types.NetworkEnforcementRequestStrict, Readiness: types.NetworkEnforcementStatusReady,
		Status: types.NetworkEnforcementStatusReady, Tier: types.NetworkEnforcementTierHelperEBPFProxyRequired,
		CgroupDelegated: true, CgroupMode: "delegated", CgroupRoot: "cgroup-root",
		HelperConfigured: true, HelperAuthenticated: true, ToolBoundaryActive: true, ProxyReady: true,
		ProxyRequired: true, ExactProxyOnly: true, AllowedTransport: "tcp", ProxyEndpointID: preflight.ProxyEndpointID,
		DirectBypassBlocked: true, DirectTCPBlocked: true, LocalNonProxyTCPBlocked: true, UDPBlocked: true, QUICBlocked: true,
		RawSocketBlockConfigured: true, RawSocketsBlocked: true, UnsupportedTrafficAction: "deny", UnsupportedTrafficBlocked: true,
		FailClosedSetup: true, CheckedAt: now, Preflight: preflight,
	}
	report.Normalize()
	return report
}

func newRebindTestApp(t *testing.T) (*App, *session.Session, nethelperBinding, nethelperBinding) {
	t.Helper()
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(2)
	sess, err := sessions.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}
	app := newTestApp(t, sessions, store)
	app.sessionAbsoluteTimeout = 4 * time.Hour
	now := time.Now().UTC().Truncate(time.Second)
	app.nethelperRecoveryToken = strings.Repeat("r", 32)
	oldBinding := nethelperBinding{Kind: "ephemeral", LeaseID: "lease-11111111-1111-4111-8111-111111111111", UnitName: "old.service", SocketPath: filepath.Join(os.TempDir(), "old.sock"), CredentialFile: filepath.Join(os.TempDir(), "old.credential"), Credential: strings.Repeat("a", 32), Generation: 3, HardExpiresAt: now.Add(100 * time.Hour)}
	candidate := nethelperBinding{Kind: "ephemeral", CreatedAt: now, SoftLease: 49 * time.Hour, RenewalRequired: true, LeaseID: "lease-22222222-2222-4222-8222-222222222222", UnitName: "new.service", SocketPath: filepath.Join(os.TempDir(), "new.sock"), CredentialFile: filepath.Join(os.TempDir(), "new.credential"), Credential: strings.Repeat("b", 32), Generation: 4, HardExpiresAt: now.Add(193 * time.Hour)}
	app.nethelperBinding.replace(oldBinding)
	app.nethelperCandidateForTest = func(req types.NethelperRebindRequest, generation uint64) (nethelperBinding, error) {
		candidate.Generation = generation
		return candidate, nil
	}
	app.nethelperStatusForTest = func(_ context.Context, binding nethelperBinding) (nethelper.InstanceStatusResponse, error) {
		return nethelper.InstanceStatusResponse{ProtocolVersion: 1, RequestID: "status", OK: true, HelperKind: "ephemeral", LeaseID: binding.LeaseID, UnitName: binding.UnitName,
			Capabilities: []string{"instance_status", "renew_instance"}, CreatedAt: now, SoftExpiresAt: now.Add(49 * time.Hour), HardExpiresAt: binding.HardExpiresAt, Status: "active"}, nil
	}
	return app, sess, oldBinding, candidate
}

func authorizedRebindHandler(app *App) http.Handler {
	return MarkUnixSocketRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set(nethelperRecoveryHeader, app.nethelperRecoveryToken)
		app.Router().ServeHTTP(w, r)
	}))
}

func rebindRequestBody(generation uint64) string {
	wire, _ := json.Marshal(types.NethelperRebindRequest{BootstrapResultPath: filepath.Join(os.TempDir(), "new", "bootstrap.json"), SocketPath: filepath.Join(os.TempDir(), "new.sock"), CredentialFile: filepath.Join(os.TempDir(), "new.credential"), ExpectedLeaseID: "lease-22222222-2222-4222-8222-222222222222", ExpectedBindingGeneration: generation})
	return string(wire)
}

func TestHelperDisappearanceAfterReadyPreflightBecomesStickyFailed(t *testing.T) {
	app, sess, _, _ := newRebindTestApp(t)
	sess.SetNetworkEnforcement(provenRebindReport(time.Now().UTC()))
	app.nethelperStatusForTest = func(context.Context, nethelperBinding) (nethelper.InstanceStatusResponse, error) {
		return nethelper.InstanceStatusResponse{}, fmt.Errorf("helper disappeared")
	}
	first := app.refreshNetworkEnforcement(sess.ID)
	second := app.refreshNetworkEnforcement(sess.ID)
	if first.Status != types.NetworkEnforcementStatusFailed || second.Status != types.NetworkEnforcementStatusFailed || first.NetworkPolicyEnforced || second.NetworkPolicyEnforced {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
	wire, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), strings.Repeat("a", 32)) {
		t.Fatal("credential leaked in lifecycle evidence")
	}
	app.cfg.Sandbox.Network.EBPF.Enforce = true
	marker := filepath.Join(t.TempDir(), "must-not-run")
	resp, _, execErr := app.execInSessionCore(context.Background(), sess.ID, types.ExecRequest{Command: "sh", Args: []string{"-c", `touch "$1"`, "sh", marker}, Timeout: "900ms"})
	if execErr != nil || resp == nil || resp.Result.Outcome == nil || resp.Result.Outcome.CommandStarted || resp.Result.Outcome.Code != "E_NETWORK_ENFORCEMENT_NOT_READY" {
		t.Fatalf("exec response=%+v err=%v", resp, execErr)
	}
	if resp.Result.CommandTimeout.RequestedMS == nil || *resp.Result.CommandTimeout.RequestedMS != 900 || resp.Result.CommandTimeout.EffectiveMS != 900 || resp.Result.CommandTimeout.Source != types.CommandTimeoutSourceExplicit {
		t.Fatalf("strict readiness refusal command_timeout=%+v", resp.Result.CommandTimeout)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("marker exists after helper failure: %v", err)
	}
}

func TestCancelledQueuedNethelperRebindNeverRunsLater(t *testing.T) {
	app, sess, oldBinding, _ := newRebindTestApp(t)
	var candidateLoaded atomic.Bool
	baseLoader := app.nethelperCandidateForTest
	app.nethelperCandidateForTest = func(req types.NethelperRebindRequest, generation uint64) (nethelperBinding, error) {
		candidateLoaded.Store(true)
		return baseLoader(req, generation)
	}
	unlock := sess.LockExec()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rr := httptest.NewRecorder()
		authorizedRebindHandler(app).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/network-enforcement/helper/rebind", strings.NewReader(rebindRequestBody(oldBinding.Generation))).WithContext(ctx))
		done <- rr
	}()
	cancel()
	rr := <-done
	unlock()
	if rr.Code != http.StatusRequestTimeout || candidateLoaded.Load() {
		t.Fatalf("status=%d candidate_loaded=%v body=%s", rr.Code, candidateLoaded.Load(), rr.Body.String())
	}
}

func TestNethelperRebindRequiresUnixWrapperRecoveryAuthority(t *testing.T) {
	app, sess, oldBinding, _ := newRebindTestApp(t)
	path := "/api/v1/sessions/" + sess.ID + "/network-enforcement/helper/rebind"
	for _, tc := range []struct {
		name    string
		handler http.Handler
		token   bool
	}{
		{name: "generic API credentials", handler: app.Router()},
		{name: "token over non-Unix transport", handler: app.Router(), token: true},
		{name: "Unix transport without token", handler: MarkUnixSocketRequests(app.Router())},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(rebindRequestBody(oldBinding.Generation)))
			if tc.token {
				req.Header.Set(nethelperRecoveryHeader, app.nethelperRecoveryToken)
			}
			rr := httptest.NewRecorder()
			tc.handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestNethelperRebindFailedCandidateWithProvenCleanupCreatesNoTombstoneOrCleanupRetry(t *testing.T) {
	for _, action := range []string{"rebind", "teardown"} {
		t.Run(action, func(t *testing.T) {
			app, sess, oldBinding, _ := newRebindTestApp(t)
			var preflightCalls, cleanupCalls atomic.Int32
			app.nethelperCleanupForTest = func(context.Context, nethelperBinding, nethelper.CleanupSessionRequest) (nethelper.CleanupSessionResponse, error) {
				cleanupCalls.Add(1)
				return nethelper.CleanupSessionResponse{OK: true}, nil
			}
			app.nethelperRebindPreflightForTest = func(context.Context, string) *types.NetworkEnforcement {
				if preflightCalls.Add(1) > 1 {
					return provenRebindReport(time.Now().UTC())
				}
				return &types.NetworkEnforcement{
					Requested: types.NetworkEnforcementRequestStrict, Status: types.NetworkEnforcementStatusFailed, Readiness: types.NetworkEnforcementStatusFailed,
					Attachment: &types.NetworkAttachmentEvidence{RegistrationID: "already-cleaned", CgroupID: 41, CgroupPath: "candidate-cgroup", Pinned: true},
					Preflight:  &types.NetworkPreflightEvidence{RegistrationID: "already-cleaned", CgroupID: 41, CgroupPath: "candidate-cgroup", Pinned: true, HelperCleanupProven: true},
				}
			}
			path := "/api/v1/sessions/" + sess.ID + "/network-enforcement/helper/rebind"
			rr := httptest.NewRecorder()
			authorizedRebindHandler(app).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, path, strings.NewReader(rebindRequestBody(oldBinding.Generation))))
			if rr.Code != http.StatusBadGateway || app.nethelperBinding.uncertainCandidate() != nil {
				t.Fatalf("failed stage status=%d tombstone=%+v body=%s", rr.Code, app.nethelperBinding.uncertainCandidate(), rr.Body.String())
			}

			switch action {
			case "rebind":
				rr = httptest.NewRecorder()
				authorizedRebindHandler(app).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, path, strings.NewReader(rebindRequestBody(oldBinding.Generation))))
				if rr.Code != http.StatusOK {
					t.Fatalf("retry status=%d body=%s", rr.Code, rr.Body.String())
				}
			case "teardown":
				destroy := httptest.NewRecorder()
				app.Router().ServeHTTP(destroy, httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/"+sess.ID, nil))
				if destroy.Code != http.StatusNoContent {
					t.Fatalf("teardown failed: status=%d body=%s", destroy.Code, destroy.Body.String())
				}
				if _, ok := app.sessions.Get(sess.ID); ok {
					t.Fatal("session remained after teardown")
				}
			}
			if cleanupCalls.Load() != 0 {
				t.Fatalf("already-completed cleanup retried %d times", cleanupCalls.Load())
			}
		})
	}
}

func TestNethelperRebindPostRunFailuresPreserveProvenHelperCleanup(t *testing.T) {
	for _, failure := range []string{"nonzero exit", "malformed probe output"} {
		t.Run(failure, func(t *testing.T) {
			app, sess, _, _ := newRebindTestApp(t)
			preflight := &types.NetworkPreflightEvidence{}
			report := &types.NetworkEnforcement{Requested: types.NetworkEnforcementRequestStrict}
			attachment := &types.NetworkAttachmentEvidence{RegistrationID: "cleaned", CgroupID: 9, CgroupPath: "candidate-cgroup"}
			captureNetworkPreflightRunEvidence(preflight, report, attachment, true)
			if failure == "malformed probe output" {
				var probe networkRuntimeProbeResult
				if err := json.Unmarshal([]byte("{"), &probe); err == nil {
					t.Fatal("malformed probe unexpectedly decoded")
				}
			}
			got := app.finishNetworkEnforcementPreflight(sess.ID, sess, report, preflight, failure, false)
			if got.Preflight == nil || !got.Preflight.HelperCleanupProven {
				t.Fatalf("cleanup proof lost after %s: %+v", failure, got.Preflight)
			}
		})
	}
}

func TestFailedCandidateCleanupProgressSurvivesStatusFailure(t *testing.T) {
	app, sess, _, candidate := newRebindTestApp(t)
	attachment := &types.NetworkAttachmentEvidence{RegistrationID: "candidate-reg", CgroupID: 42, CgroupPath: "candidate-cgroup"}
	app.nethelperBinding.recordUncertainCandidate(sess.ID, candidate, attachment, "test")
	var cleanupCalls, statusCalls atomic.Int32
	app.nethelperCleanupForTest = func(_ context.Context, binding nethelperBinding, req nethelper.CleanupSessionRequest) (nethelper.CleanupSessionResponse, error) {
		cleanupCalls.Add(1)
		if binding.LeaseID != candidate.LeaseID || req.RegistrationID != attachment.RegistrationID || req.CgroupID != attachment.CgroupID || req.CgroupPath != attachment.CgroupPath {
			t.Fatalf("inexact cleanup: binding=%+v request=%+v", binding, req)
		}
		return nethelper.CleanupSessionResponse{OK: true}, nil
	}
	app.nethelperStatusForTest = func(context.Context, nethelperBinding) (nethelper.InstanceStatusResponse, error) {
		if statusCalls.Add(1) == 1 {
			return nethelper.InstanceStatusResponse{}, fmt.Errorf("transient status failure")
		}
		return nethelper.InstanceStatusResponse{OK: true, Status: "active", ActiveRegistrationCount: 0}, nil
	}
	if err := app.resolveCandidateCleanup(context.Background()); err == nil {
		t.Fatal("first resolution unexpectedly ignored status failure")
	}
	pending := app.nethelperBinding.uncertainCandidate()
	if pending == nil || pending.Attachment != nil {
		t.Fatalf("successful cleanup progress was not committed: %+v", pending)
	}
	if err := app.resolveCandidateCleanup(context.Background()); err != nil {
		t.Fatalf("second resolution: %v", err)
	}
	if cleanupCalls.Load() != 1 || statusCalls.Load() != 2 || app.nethelperBinding.uncertainCandidate() != nil {
		t.Fatalf("cleanup_calls=%d status_calls=%d tombstone=%+v", cleanupCalls.Load(), statusCalls.Load(), app.nethelperBinding.uncertainCandidate())
	}
}

func TestFailedCandidateCleanupTombstoneBlocksRebindAndTeardown(t *testing.T) {
	app, sess, oldBinding, candidate := newRebindTestApp(t)
	app.nethelperRebindPreflightForTest = func(context.Context, string) *types.NetworkEnforcement {
		return &types.NetworkEnforcement{Requested: types.NetworkEnforcementRequestStrict, Status: types.NetworkEnforcementStatusFailed,
			Readiness: types.NetworkEnforcementStatusFailed, Preflight: &types.NetworkPreflightEvidence{RegistrationID: "candidate-reg", CgroupID: 42, CgroupPath: "candidate-cgroup", Pinned: true}}
	}
	rr := httptest.NewRecorder()
	authorizedRebindHandler(app).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/network-enforcement/helper/rebind", strings.NewReader(rebindRequestBody(oldBinding.Generation))))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("initial status=%d body=%s", rr.Code, rr.Body.String())
	}
	pending := app.nethelperBinding.uncertainCandidate()
	if pending == nil || pending.Binding.LeaseID != candidate.LeaseID || pending.Attachment == nil || pending.Attachment.RegistrationID != "candidate-reg" || !pending.Attachment.Pinned {
		t.Fatalf("candidate evidence was forgotten: %+v", pending)
	}
	// Even an authenticated-looking zero count cannot erase exact candidate
	// identity without a successful cleanup RPC.
	app.nethelperStatusForTest = func(context.Context, nethelperBinding) (nethelper.InstanceStatusResponse, error) {
		return nethelper.InstanceStatusResponse{OK: true, Status: "active", ActiveRegistrationCount: 0}, nil
	}
	rr = httptest.NewRecorder()
	authorizedRebindHandler(app).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/network-enforcement/helper/rebind", strings.NewReader(rebindRequestBody(oldBinding.Generation))))
	if rr.Code != http.StatusConflict {
		t.Fatalf("second status=%d body=%s", rr.Code, rr.Body.String())
	}
	destroy := httptest.NewRecorder()
	app.Router().ServeHTTP(destroy, httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/"+sess.ID, nil))
	if destroy.Code != http.StatusConflict {
		t.Fatalf("destroy status=%d body=%s", destroy.Code, destroy.Body.String())
	}
	if got := app.ReapExpiredSessions(time.Now().Add(24*time.Hour), time.Hour, 0); len(got) != 0 {
		t.Fatalf("reaped staged session: %+v", got)
	}
	if _, ok := app.sessions.Get(sess.ID); !ok {
		t.Fatal("session destroyed with uncertain candidate cleanup")
	}
}

func TestRebindSerializesGRPCDestroy(t *testing.T) {
	app, sess, oldBinding, _ := newRebindTestApp(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	app.nethelperRebindPreflightForTest = func(context.Context, string) *types.NetworkEnforcement {
		close(entered)
		<-release
		return provenRebindReport(time.Now().UTC())
	}
	rebindDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rr := httptest.NewRecorder()
		authorizedRebindHandler(app).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/network-enforcement/helper/rebind", strings.NewReader(rebindRequestBody(oldBinding.Generation))))
		rebindDone <- rr
	}()
	<-entered
	destroyDone := make(chan error, 1)
	destroyStarted := make(chan struct{})
	go func() {
		in, _ := structpb.NewStruct(map[string]any{"id": sess.ID})
		close(destroyStarted)
		_, err := (&grpcServer{app: app}).DestroySession(context.Background(), in)
		destroyDone <- err
	}()
	<-destroyStarted
	if _, ok := app.sessions.Get(sess.ID); !ok {
		t.Fatal("gRPC destroy crossed staged rebind topology lock")
	}
	close(release)
	if rr := <-rebindDone; rr.Code != http.StatusOK {
		t.Fatalf("rebind status=%d body=%s", rr.Code, rr.Body.String())
	}
	if err := <-destroyDone; err != nil {
		t.Fatalf("gRPC destroy: %v", err)
	}
}

func TestRebindSerializesHardExpiryAndRetainsFailedStage(t *testing.T) {
	app, sess, oldBinding, _ := newRebindTestApp(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	app.nethelperRebindPreflightForTest = func(context.Context, string) *types.NetworkEnforcement {
		close(entered)
		<-release
		app.nethelperStatusForTest = func(context.Context, nethelperBinding) (nethelper.InstanceStatusResponse, error) {
			return nethelper.InstanceStatusResponse{}, fmt.Errorf("candidate unavailable")
		}
		return &types.NetworkEnforcement{Requested: types.NetworkEnforcementRequestStrict, Status: types.NetworkEnforcementStatusFailed, Readiness: types.NetworkEnforcementStatusFailed,
			Preflight: &types.NetworkPreflightEvidence{RegistrationID: "staged-reg", CgroupID: 7, CgroupPath: "staged-cgroup", Pinned: true}}
	}
	rebindDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rr := httptest.NewRecorder()
		authorizedRebindHandler(app).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/network-enforcement/helper/rebind", strings.NewReader(rebindRequestBody(oldBinding.Generation))))
		rebindDone <- rr
	}()
	<-entered
	reapDone := make(chan []*session.Session, 1)
	reapStarted := make(chan struct{})
	go func() {
		close(reapStarted)
		reapDone <- app.ReapExpiredSessions(time.Now().Add(24*time.Hour), time.Hour, 0)
	}()
	<-reapStarted
	if _, ok := app.sessions.Get(sess.ID); !ok {
		t.Fatal("hard expiry crossed staged rebind topology lock")
	}
	close(release)
	if rr := <-rebindDone; rr.Code != http.StatusBadGateway {
		t.Fatalf("rebind status=%d body=%s", rr.Code, rr.Body.String())
	}
	if reaped := <-reapDone; len(reaped) != 0 {
		t.Fatalf("hard expiry destroyed uncertain stage: %+v", reaped)
	}
	if _, ok := app.sessions.Get(sess.ID); !ok {
		t.Fatal("session missing after uncertain staged cleanup")
	}
}

func TestNethelperRebindGenerationConflictDoesNotCommit(t *testing.T) {
	app, sess, oldBinding, _ := newRebindTestApp(t)
	rr := httptest.NewRecorder()
	authorizedRebindHandler(app).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/network-enforcement/helper/rebind", strings.NewReader(rebindRequestBody(oldBinding.Generation-1))))
	if rr.Code != http.StatusConflict || app.nethelperBindingSnapshot().Generation != oldBinding.Generation {
		t.Fatalf("status=%d binding=%+v body=%s", rr.Code, app.nethelperBindingSnapshot(), rr.Body.String())
	}
}

func TestNethelperRebindFailedPreflightRetainsOldBindingAndStickyFailure(t *testing.T) {
	app, sess, oldBinding, _ := newRebindTestApp(t)
	app.nethelperRebindPreflightForTest = func(context.Context, string) *types.NetworkEnforcement {
		return &types.NetworkEnforcement{Requested: types.NetworkEnforcementRequestStrict, Status: types.NetworkEnforcementStatusFailed, Readiness: types.NetworkEnforcementStatusFailed}
	}
	rr := httptest.NewRecorder()
	authorizedRebindHandler(app).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/network-enforcement/helper/rebind", strings.NewReader(rebindRequestBody(oldBinding.Generation))))
	if rr.Code != http.StatusBadGateway || app.nethelperBindingSnapshot().Generation != oldBinding.Generation {
		t.Fatalf("status=%d binding=%+v body=%s", rr.Code, app.nethelperBindingSnapshot(), rr.Body.String())
	}
	if report := sess.NetworkEnforcement(); report == nil || report.Status != types.NetworkEnforcementStatusFailed {
		t.Fatalf("sticky report=%+v", report)
	}
}

func TestNethelperRebindRejectsCandidateWithoutSessionLifetime(t *testing.T) {
	app, sess, oldBinding, candidate := newRebindTestApp(t)
	candidate.HardExpiresAt = time.Now().UTC().Add(4 * time.Hour)
	app.nethelperCandidateForTest = func(types.NethelperRebindRequest, uint64) (nethelperBinding, error) { return candidate, nil }
	rr := httptest.NewRecorder()
	authorizedRebindHandler(app).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/network-enforcement/helper/rebind", strings.NewReader(rebindRequestBody(oldBinding.Generation))))
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "remaining absolute session lifetime") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestWrapperRecoveryTokenUsesHiddenFixedPrivateTopology(t *testing.T) {
	container := filepath.Join(t.TempDir(), nethelper.WrapperControlDirectoryName)
	if err := os.Mkdir(container, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(container, nethelper.WrapperRecoveryTokenFilename)
	token := strings.Repeat("z", 32)
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, retainedPath := readRecoveryTokenFile(path)
	if got != token || retainedPath != path {
		t.Fatalf("token/path validation failed: %q %q", got, retainedPath)
	}
	jail := buildCommandJailConfig(nil, nil, "", "", "", "", retainedPath, "")
	if !containsString(jail.HideDirectories, container) {
		t.Fatalf("recovery container not hidden: %+v", jail)
	}
	if !isReservedSupervisorEnvKey(nethelper.EnvRecoveryTokenFile) {
		t.Fatal("recovery path environment is not reserved")
	}
	requirements := commandJailRequirements(true)
	if !requirements.CloseNonStdioFDs || !requirements.HideControlPaths {
		t.Fatalf("command jail does not guarantee path/fd secrecy: %+v", requirements)
	}
	wrongPath := filepath.Join(container, "guessable-token")
	if err := os.WriteFile(wrongPath, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	if value, retained := readRecoveryTokenFile(wrongPath); value != "" || retained != "" {
		t.Fatal("arbitrary token topology was accepted")
	}
	if err := os.Chmod(container, 0o755); err != nil {
		t.Fatal(err)
	}
	if value, retained := readRecoveryTokenFile(path); value != "" || retained != "" {
		t.Fatal("same-UID-readable token container was accepted")
	}
}

func TestCommandJailMasksDetachedStateTreeAndPreservesRuntimeDirectories(t *testing.T) {
	stateDir := t.TempDir()
	baseDir := filepath.Join(stateDir, "runtime")
	workspaceDir := filepath.Join(stateDir, "workspace")
	homeDir := filepath.Join(stateDir, "home")
	tmpDir := filepath.Join(stateDir, "tmp")
	for _, path := range []string{baseDir, workspaceDir, homeDir, tmpDir} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{}
	cfg.Sessions.BaseDir = baseDir
	cfg.Sessions.WorkspaceShadow.BaseDir = workspaceDir
	sess := &session.Session{Workspace: workspaceDir, WorkspaceMount: workspaceDir}
	sess.SetRuntimePaths(homeDir, tmpDir, func() error { return nil })
	jail := buildCommandJailConfig(cfg, sess, stateDir, "", "", "", "", "")
	if len(jail.HideDirectoryTrees) != 1 || jail.HideDirectoryTrees[0].Path != stateDir {
		t.Fatalf("detached state tree is not hidden: %+v", jail)
	}
	for _, path := range []string{baseDir, workspaceDir, homeDir, tmpDir} {
		if !containsString(jail.HideDirectoryTrees[0].PreserveDirectories, path) {
			t.Fatalf("runtime directory %q is not preserved: %+v", path, jail)
		}
	}
	for _, name := range []string{"metadata.json", "recovery.json", "runtime-provider.json", "supervisor.sock"} {
		path := filepath.Join(stateDir, name)
		if !pathHiddenByCommandJailTree(path, jail.HideDirectoryTrees[0]) {
			t.Fatalf("control path %q remains exposed: %+v", path, jail)
		}
	}
}

func TestCommandJailDoesNotInferControlTreeFromOrdinarySessionsBaseDir(t *testing.T) {
	baseDir := filepath.Join(t.TempDir(), "sessions")
	if err := os.Mkdir(baseDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Sessions.BaseDir = baseDir
	jail := buildCommandJailConfig(cfg, nil, "", "", "", "", "", "")
	if len(jail.HideDirectoryTrees) != 0 {
		t.Fatalf("ordinary sessions parent was treated as detached control state: %+v", jail)
	}
}

func pathHiddenByCommandJailTree(path string, tree commandJailDirectoryTree) bool {
	if path != tree.Path && !pathWithinRoot(path, tree.Path) {
		return false
	}
	for _, preserved := range tree.PreserveDirectories {
		if path == preserved || pathWithinRoot(path, preserved) {
			return false
		}
	}
	return true
}

func TestAutomaticCompositionMasksHelperObjectsWithoutMaskingLeaseRuntime(t *testing.T) {
	leaseRoot := filepath.Join(t.TempDir(), "lease-11111111-1111-4111-8111-111111111111")
	socket := filepath.Join(leaseRoot, "nethelper.sock")
	credential := filepath.Join(leaseRoot, "instance-credential")
	bootstrap := filepath.Join(leaseRoot, "bootstrap.json")
	scratch := filepath.Join(leaseRoot, "composition")
	jail := buildCommandJailConfig(nil, nil, "", socket, credential, bootstrap, "", scratch)
	for _, path := range []string{socket, credential, bootstrap} {
		if !containsString(jail.HidePaths, path) {
			t.Fatalf("helper control %q is not individually masked: %+v", path, jail)
		}
	}
	if containsString(jail.HideDirectories, leaseRoot) {
		t.Fatalf("composition lease runtime was masked: %+v", jail)
	}
}

func TestNethelperRebindSuccessfulPreflightPreservesSessionAndOmitsSecret(t *testing.T) {
	app, sess, oldBinding, candidate := newRebindTestApp(t)
	originalID := sess.ID
	app.nethelperRebindPreflightForTest = func(context.Context, string) *types.NetworkEnforcement { return provenRebindReport(time.Now().UTC()) }
	rr := httptest.NewRecorder()
	authorizedRebindHandler(app).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/network-enforcement/helper/rebind", strings.NewReader(rebindRequestBody(oldBinding.Generation))))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	binding := app.nethelperBindingSnapshot()
	if binding.Generation != oldBinding.Generation+1 || binding.LeaseID != candidate.LeaseID || sess.ID != originalID {
		t.Fatalf("binding=%+v session=%s", binding, sess.ID)
	}
	if strings.Contains(rr.Body.String(), candidate.Credential) || strings.Contains(rr.Body.String(), oldBinding.Credential) {
		t.Fatal("credential leaked in rebind response")
	}
}
