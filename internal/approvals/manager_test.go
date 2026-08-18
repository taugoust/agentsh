package approvals

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakePrompt lets tests control prompt behavior without a real tty.
type fakePrompt struct {
	res   Resolution
	err   error
	delay time.Duration
}

func (f fakePrompt) call(ctx context.Context, req Request) (Resolution, error) {
	select {
	case <-ctx.Done():
		return Resolution{}, ctx.Err()
	case <-time.After(f.delay):
	}
	return f.res, f.err
}

func TestRequestApproval_ContextCancelUnblocksPrompt(t *testing.T) {
	m := New("local_tty", 5*time.Second, nil)
	fp := fakePrompt{delay: 100 * time.Second} // would hang without ctx
	m.prompt = fp.call

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	res, err := m.RequestApproval(ctx, Request{SessionID: "s1", Kind: "command", Target: "echo"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}
	if res.Approved {
		t.Fatalf("expected denied due to cancel")
	}
}

func TestRequestApproval_TimesOut(t *testing.T) {
	m := New("local_tty", 100*time.Millisecond, nil)
	fp := fakePrompt{delay: 1 * time.Second}
	m.prompt = fp.call

	ctx := context.Background()
	res, err := m.RequestApproval(ctx, Request{SessionID: "s2", Kind: "command", Target: "sleep"})
	if err == nil {
		t.Fatalf("expected timeout error")
	}
	if res.Approved {
		t.Fatalf("expected denied on timeout")
	}
	if res.Reason == "" {
		t.Fatalf("expected reason to be set")
	}
}

func TestRequestApproval_PromptResultWins(t *testing.T) {
	m := New("local_tty", 5*time.Second, nil)
	fp := fakePrompt{delay: 10 * time.Millisecond, res: Resolution{Approved: true, Reason: "ok", At: time.Now()}}
	m.prompt = fp.call

	ctx := context.Background()
	res, err := m.RequestApproval(ctx, Request{SessionID: "s3", Kind: "command", Target: "echo"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Approved {
		t.Fatalf("expected approval to pass through")
	}
}

func TestManagerTOTPMode(t *testing.T) {
	mgr := New("totp", 5*time.Second, nil)

	if mgr.mode != "totp" {
		t.Errorf("mode = %q, want totp", mgr.mode)
	}

	// Verify promptTOTP is set
	if mgr.prompt == nil {
		t.Error("prompt function not set")
	}
}

func TestManagerSetTOTPSecretLookup(t *testing.T) {
	mgr := New("totp", 5*time.Second, nil)

	called := false
	mgr.SetTOTPSecretLookup(func(sessionID string) string {
		called = true
		return "TESTSECRET"
	})

	// Verify the lookup was set
	if mgr.totpSecretLookup == nil {
		t.Error("totpSecretLookup not set")
	}

	// Call it to verify it works
	secret := mgr.totpSecretLookup("test-session")
	if !called {
		t.Error("lookup function not called")
	}
	if secret != "TESTSECRET" {
		t.Errorf("secret = %q, want TESTSECRET", secret)
	}
}

func TestManagerDefaultMode(t *testing.T) {
	mgr := New("", 5*time.Second, nil)

	if mgr.mode != "local_tty" {
		t.Errorf("default mode = %q, want local_tty", mgr.mode)
	}
}

func TestRequestApproval_ExtendsCommandTimeout(t *testing.T) {
	m := New("api", 250*time.Millisecond, nil)
	var got time.Duration
	ctx := WithCommandTimeoutExtension(context.Background(), func(extra time.Duration) {
		got += extra
	})

	go func() {
		for {
			pending := m.ListPending()
			if len(pending) > 0 {
				m.Resolve(pending[0].ID, true, "ok")
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	if _, err := m.RequestApproval(ctx, Request{SessionID: "s4", Kind: "command", Target: "echo"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 250*time.Millisecond {
		t.Fatalf("extension = %s, want 250ms", got)
	}
}

func TestRequestApprovalScoped_CacheHitDoesNotRegisterPending(t *testing.T) {
	m := New("api", time.Second, nil)
	scope, ok := NewFileScopeWithRule("open", "/workspace/.env", "approve-env")
	if !ok {
		t.Fatal("failed to construct file scope")
	}
	if !m.SetScoped(context.Background(), "session", "old-command", scope, true, "cached", "approve-env") {
		t.Fatal("failed to seed scoped decision")
	}

	res, err := m.RequestApprovalScoped(context.Background(), Request{
		ID:        "must-not-be-pending",
		SessionID: "session",
		CommandID: "new-command",
		Kind:      "file",
		Target:    "/workspace/.env",
		Rule:      "approve-env",
	}, scope)
	if err != nil || !res.Approved || res.Reason != "cached" || res.Scope != ScopeSession {
		t.Fatalf("cached result = %+v err=%v", res, err)
	}
	if pending := m.ListPendingForSession("session"); len(pending) != 0 {
		t.Fatalf("cache hit registered pending requests: %+v", pending)
	}
	m.rateMu.Lock()
	rateEntries := len(m.sessionCounts)
	m.rateMu.Unlock()
	if rateEntries != 0 {
		t.Fatalf("cache hit reserved a pending rate slot: %d", rateEntries)
	}
}

func TestRequestApprovalScoped_PreCanceledContextNeverRegisters(t *testing.T) {
	scope, ok := NewFileScopeWithRule("open", "/workspace/canceled", "approve-canceled")
	if !ok {
		t.Fatal("failed to construct file scope")
	}

	for _, test := range []struct {
		name    string
		request func(*Manager, context.Context) (Resolution, error)
	}{
		{
			name: "scoped",
			request: func(m *Manager, ctx context.Context) (Resolution, error) {
				return m.RequestApprovalScoped(ctx, Request{
					ID: "pre-canceled-scoped", SessionID: "session", CommandID: "command",
					Kind: "file", Target: scope.Path, Rule: scope.Rule,
				}, scope)
			},
		},
		{
			name: "shared request path",
			request: func(m *Manager, ctx context.Context) (Resolution, error) {
				return m.RequestApproval(ctx, Request{
					ID: "pre-canceled-unscoped", SessionID: "session", CommandID: "command",
					Kind: "command", Target: "echo",
				})
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			emitter := newResolutionRaceEmitter(1, nil)
			m := New("api", time.Second, emitter)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			res, err := test.request(m, ctx)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("request error = %v, want context.Canceled", err)
			}
			if res.Approved || res.Reason != context.Canceled.Error() || res.Scope != ScopeOnce {
				t.Fatalf("pre-canceled resolution = %+v", res)
			}
			if pending := m.ListPendingForSession("session"); len(pending) != 0 {
				t.Fatalf("pre-canceled request became pending: %+v", pending)
			}
			m.rateMu.Lock()
			rateEntries := len(m.sessionCounts)
			m.rateMu.Unlock()
			if rateEntries != 0 {
				t.Fatalf("pre-canceled request reserved rate slots: %d", rateEntries)
			}
			appended, published := emitter.events()
			if len(appended) != 0 || len(published) != 0 {
				t.Fatalf("pre-canceled request emitted events: appended=%+v published=%+v", appended, published)
			}
		})
	}
}

func TestRequestApprovalScoped_CancellationAndResolutionPublicationOrder(t *testing.T) {
	scope, ok := NewFileScopeWithRule("open", "/workspace/interleaving", "approve-interleaving")
	if !ok {
		t.Fatal("failed to construct file scope")
	}
	request := Request{
		ID: "scoped-interleaving", SessionID: "session", CommandID: "command",
		Kind: "file", Target: scope.Path, Rule: scope.Rule,
	}

	t.Run("cancellation before resolution", func(t *testing.T) {
		gate := make(chan struct{})
		defer releaseResolutionRaceGate(gate)
		emitter := newResolutionRaceEmitter(1, gate)
		m := New("api", time.Second, emitter)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan resolutionRaceRequestResult, 1)
		go func() {
			resolution, err := m.RequestApprovalScoped(ctx, request, scope)
			result <- resolutionRaceRequestResult{resolution: resolution, err: err}
		}()

		receiveResolutionRace(t, emitter.requested)
		cancel()
		if m.ResolveForSessionWithScope(request.SessionID, request.ID, true, "stale approval", ScopeSession) {
			t.Fatal("resolution won after its request context was canceled")
		}
		releaseResolutionRaceGate(gate)

		got := receiveResolutionRace(t, result)
		if !errors.Is(got.err, context.Canceled) || got.resolution.Approved {
			t.Fatalf("cancellation result = %+v err=%v", got.resolution, got.err)
		}
		if decisions := m.SessionScopedDecisions(request.SessionID); len(decisions) != 0 {
			t.Fatalf("canceled resolution published session scope: %+v", decisions)
		}
		m.mu.Lock()
		commandScopes := len(m.commandScoped[request.SessionID])
		m.mu.Unlock()
		if commandScopes != 0 {
			t.Fatalf("canceled resolution published command scopes: %d", commandScopes)
		}
		assertResolutionRaceCleanup(t, m)
	})

	t.Run("resolution before cancellation", func(t *testing.T) {
		gate := make(chan struct{})
		defer releaseResolutionRaceGate(gate)
		emitter := newResolutionRaceEmitter(1, gate)
		m := New("api", time.Second, emitter)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan resolutionRaceRequestResult, 1)
		go func() {
			resolution, err := m.RequestApprovalScoped(ctx, request, scope)
			result <- resolutionRaceRequestResult{resolution: resolution, err: err}
		}()

		receiveResolutionRace(t, emitter.requested)
		if !m.ResolveForSessionWithScope(request.SessionID, request.ID, true, "live approval", ScopeSession) {
			t.Fatal("live resolution did not win")
		}
		decisions := m.SessionScopedDecisions(request.SessionID)
		if len(decisions) != 1 || !decisions[0].Approved || decisions[0].Key != scope.Key {
			t.Fatalf("winning resolution was not published atomically: %+v", decisions)
		}
		cancel()
		releaseResolutionRaceGate(gate)

		got := receiveResolutionRace(t, result)
		if got.err != nil || !got.resolution.Approved || got.resolution.Scope != ScopeSession {
			t.Fatalf("decision result = %+v err=%v", got.resolution, got.err)
		}
		assertResolutionRaceCleanup(t, m)
	})
}

func TestRequestApprovalScoped_MissRegistersExactScopeAndPreservesScopeSemantics(t *testing.T) {
	m := New("api", time.Second, nil)
	scope, ok := NewFileScopeWithRule("stat", "/workspace/config.json", "approve-config")
	if !ok {
		t.Fatal("failed to construct file scope")
	}

	type result struct {
		resolution Resolution
		err        error
	}
	done := make(chan result, 1)
	go func() {
		res, err := m.RequestApprovalScoped(context.Background(), Request{
			ID:        "scoped-miss",
			SessionID: "session",
			CommandID: "command",
			Kind:      "file",
			Target:    "/workspace/config.json",
			Rule:      "approve-config",
			Fields: map[string]any{
				"scope_key": "caller-supplied-wrong-key",
				"operation": "stat",
				"path":      "/workspace/config.json",
			},
		}, scope)
		done <- result{resolution: res, err: err}
	}()

	var pending Request
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		requests := m.ListPendingForSession("session")
		if len(requests) == 1 {
			pending = requests[0]
			break
		}
		time.Sleep(time.Millisecond)
	}
	if pending.ID == "" {
		t.Fatal("scoped cache miss did not register a pending request")
	}
	if got := pending.Fields["scope_key"]; got != scope.Key {
		t.Fatalf("pending scope key = %v, want exact manager scope %q", got, scope.Key)
	}
	if !m.ResolveForSessionWithScope("session", pending.ID, true, "operator", ScopeSession) {
		t.Fatal("failed to resolve scoped request")
	}
	got := <-done
	if got.err != nil || !got.resolution.Approved || got.resolution.Scope != ScopeSession {
		t.Fatalf("scoped request result = %+v err=%v", got.resolution, got.err)
	}

	// The session grant selected by the operator must satisfy a later read-like
	// operation through the same exact atomic API without another registration.
	res, err := m.RequestApprovalScoped(context.Background(), Request{
		ID:        "cached-after-session-grant",
		SessionID: "session",
		CommandID: "later-command",
		Kind:      "file",
		Target:    "/workspace/config.json",
		Rule:      "approve-config",
	}, scope)
	if err != nil || !res.Approved || res.Scope != ScopeSession {
		t.Fatalf("later scoped result = %+v err=%v", res, err)
	}
	if pending := m.ListPendingForSession("session"); len(pending) != 0 {
		t.Fatalf("later cache hit registered pending requests: %+v", pending)
	}
}
