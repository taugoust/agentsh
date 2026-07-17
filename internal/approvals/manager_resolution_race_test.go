package approvals

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

const resolutionRaceGuardTimeout = 5 * time.Second

type resolutionRaceEmitter struct {
	mu sync.Mutex

	appended  []types.Event
	published []types.Event

	requested      chan types.Event
	requestRelease <-chan struct{}
}

func newResolutionRaceEmitter(requestCount int, requestRelease <-chan struct{}) *resolutionRaceEmitter {
	return &resolutionRaceEmitter{
		requested:      make(chan types.Event, requestCount),
		requestRelease: requestRelease,
	}
}

func (e *resolutionRaceEmitter) AppendEvent(_ context.Context, ev types.Event) error {
	e.mu.Lock()
	e.appended = append(e.appended, ev)
	e.mu.Unlock()

	if ev.Type == "approval_requested" {
		e.requested <- ev
		if e.requestRelease != nil {
			<-e.requestRelease
		}
	}
	return nil
}

func (e *resolutionRaceEmitter) Publish(ev types.Event) {
	e.mu.Lock()
	e.published = append(e.published, ev)
	e.mu.Unlock()
}

func (e *resolutionRaceEmitter) events() ([]types.Event, []types.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]types.Event(nil), e.appended...), append([]types.Event(nil), e.published...)
}

type resolutionRaceRequestResult struct {
	resolution Resolution
	err        error
}

func startResolutionRaceRequest(m *Manager, ctx context.Context, req Request) <-chan resolutionRaceRequestResult {
	result := make(chan resolutionRaceRequestResult, 1)
	go func() {
		resolution, err := m.RequestApproval(ctx, req)
		result <- resolutionRaceRequestResult{resolution: resolution, err: err}
	}()
	return result
}

func receiveResolutionRace[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	timer := time.NewTimer(resolutionRaceGuardTimeout)
	defer timer.Stop()
	select {
	case value := <-ch:
		return value
	case <-timer.C:
		t.Fatal("timed out waiting for approval race test barrier")
		var zero T
		return zero
	}
}

func releaseResolutionRaceGate(gate chan struct{}) {
	select {
	case <-gate:
	default:
		close(gate)
	}
}

func addResolutionRacePending(m *Manager, id string) *pending {
	now := time.Now().UTC()
	p := &pending{
		req: Request{
			ID:        id,
			CreatedAt: now,
			ExpiresAt: now.Add(time.Hour),
			SessionID: "race-session",
			Kind:      "command",
		},
		done: make(chan struct{}),
	}
	m.mu.Lock()
	m.pending[id] = p
	m.mu.Unlock()
	return p
}

func getResolutionRacePending(t *testing.T, m *Manager, id string) *pending {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.pending[id]
	if !ok {
		t.Fatalf("approval %q is not pending", id)
	}
	return p
}

func resolutionRaceEventsOfType(events []types.Event, eventType string) []types.Event {
	matched := make([]types.Event, 0)
	for _, event := range events {
		if event.Type == eventType {
			matched = append(matched, event)
		}
	}
	return matched
}

func assertResolutionRaceCleanup(t *testing.T, m *Manager) {
	t.Helper()
	m.mu.Lock()
	pendingCount := len(m.pending)
	m.mu.Unlock()
	if pendingCount != 0 {
		t.Fatalf("pending approvals after resolution = %d, want 0", pendingCount)
	}

	m.rateMu.Lock()
	sessionCountEntries := len(m.sessionCounts)
	m.rateMu.Unlock()
	if sessionCountEntries != 0 {
		t.Fatalf("session rate counters after resolution = %d, want 0", sessionCountEntries)
	}
}

func assertNoResolutionRaceScopes(t *testing.T, m *Manager, sessionID string) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if got := len(m.scoped[sessionID]); got != 0 {
		t.Fatalf("session-scoped decisions after non-decision resolution = %d, want 0", got)
	}
	if got := len(m.commandScoped[sessionID]); got != 0 {
		t.Fatalf("command-scoped decisions after non-decision resolution = %d, want 0", got)
	}
}

func TestApprovalResolutionDuplicateIDCannotReplacePending(t *testing.T) {
	gate := make(chan struct{})
	defer releaseResolutionRaceGate(gate)
	emitter := newResolutionRaceEmitter(1, gate)
	m := New("remote", time.Minute, emitter)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const approvalID = "duplicate-pending"
	firstRequest := Request{
		ID:        approvalID,
		SessionID: "original-session",
		CommandID: "original-command",
		Kind:      "command",
		Target:    "original-target",
	}
	firstResult := startResolutionRaceRequest(m, ctx, firstRequest)
	requested := receiveResolutionRace(t, emitter.requested)
	if requested.SessionID != firstRequest.SessionID || requested.Fields["approval_id"] != approvalID || requested.Fields["target"] != firstRequest.Target {
		t.Fatalf("first requested event = %+v, want original request", requested)
	}
	firstPending := getResolutionRacePending(t, m, approvalID)

	duplicateResult := startResolutionRaceRequest(m, context.Background(), Request{
		ID:        approvalID,
		SessionID: "hijack-session",
		CommandID: "hijack-command",
		Kind:      "network",
		Target:    "hijack-target",
	})
	duplicate := receiveResolutionRace(t, duplicateResult)
	const duplicateError = `approval ID "duplicate-pending" is already pending`
	if duplicate.err == nil || duplicate.err.Error() != duplicateError {
		t.Fatalf("duplicate request error = %v, want %q", duplicate.err, duplicateError)
	}
	if duplicate.resolution.Approved || duplicate.resolution.Reason != duplicateError || duplicate.resolution.Scope != ScopeOnce || duplicate.resolution.At.IsZero() {
		t.Fatalf("duplicate request resolution = %+v, want clear denial", duplicate.resolution)
	}

	m.mu.Lock()
	currentPending, stillPending := m.pending[approvalID]
	pendingCount := len(m.pending)
	m.mu.Unlock()
	if !stillPending || pendingCount != 1 || currentPending != firstPending {
		t.Fatalf("pending entry after duplicate: present=%v count=%d pointer=%p, want original %p", stillPending, pendingCount, currentPending, firstPending)
	}
	if currentPending.req.SessionID != firstRequest.SessionID || currentPending.req.CommandID != firstRequest.CommandID || currentPending.req.Target != firstRequest.Target {
		t.Fatalf("pending request after duplicate = %+v, want original session/command/target", currentPending.req)
	}

	m.rateMu.Lock()
	originalRate := m.sessionCounts[firstRequest.SessionID]
	_, hijackRateExists := m.sessionCounts["hijack-session"]
	rateEntries := len(m.sessionCounts)
	m.rateMu.Unlock()
	if originalRate != 1 || hijackRateExists || rateEntries != 1 {
		t.Fatalf("rate counters after duplicate: original=%d hijackPresent=%v entries=%d, want 1/false/1", originalRate, hijackRateExists, rateEntries)
	}

	if !m.Resolve(approvalID, true, "original approved") {
		t.Fatal("original request did not resolve")
	}
	terminal := m.observePending(firstPending)
	if terminal.cause != terminalCauseDecision || !terminal.resolution.Approved || terminal.resolution.Reason != "original approved" {
		t.Fatalf("original terminal resolution = %+v cause=%v", terminal.resolution, terminal.cause)
	}
	releaseResolutionRaceGate(gate)

	first := receiveResolutionRace(t, firstResult)
	if first.err != nil || first.resolution != terminal.resolution {
		t.Fatalf("original request result = %+v err=%v, want stored decision %+v", first.resolution, first.err, terminal.resolution)
	}

	appended, published := emitter.events()
	for name, events := range map[string][]types.Event{"appended": appended, "published": published} {
		requestedEvents := resolutionRaceEventsOfType(events, "approval_requested")
		resolvedEvents := resolutionRaceEventsOfType(events, "approval_resolved")
		if len(requestedEvents) != 1 || len(resolvedEvents) != 1 {
			t.Fatalf("%s event counts: requested=%d resolved=%d, want 1/1", name, len(requestedEvents), len(resolvedEvents))
		}
		if requestedEvents[0].SessionID != firstRequest.SessionID || requestedEvents[0].Fields["target"] != firstRequest.Target {
			t.Fatalf("%s requested event was hijacked: %+v", name, requestedEvents[0])
		}
	}
	assertResolutionRaceCleanup(t, m)
}

func TestApprovalResolutionSingleWinner(t *testing.T) {
	m := New("remote", time.Minute, nil)
	p := addResolutionRacePending(m, "single-winner")

	type candidate struct {
		approved bool
		reason   string
	}
	type candidateResult struct {
		candidate candidate
		won       bool
	}
	candidates := []candidate{
		{approved: true, reason: "approved"},
		{approved: false, reason: "denied"},
	}
	start := make(chan struct{})
	results := make(chan candidateResult, len(candidates))
	for _, candidate := range candidates {
		candidate := candidate
		go func() {
			<-start
			results <- candidateResult{
				candidate: candidate,
				won:       m.Resolve("single-winner", candidate.approved, candidate.reason),
			}
		}()
	}
	close(start)

	winnerCount := 0
	var winner candidate
	for range candidates {
		result := receiveResolutionRace(t, results)
		if result.won {
			winnerCount++
			winner = result.candidate
		}
	}
	if winnerCount != 1 {
		t.Fatalf("winning resolution count = %d, want 1", winnerCount)
	}

	terminal := m.observePending(p)
	if terminal.cause != terminalCauseDecision {
		t.Fatalf("terminal cause = %v, want decision", terminal.cause)
	}
	if terminal.resolution.Approved != winner.approved || terminal.resolution.Reason != winner.reason {
		t.Fatalf("terminal resolution = %+v, want winner %+v", terminal.resolution, winner)
	}
	if terminal.resolution.Scope != ScopeOnce || terminal.resolution.At.IsZero() {
		t.Fatalf("terminal resolution has invalid scope/time: %+v", terminal.resolution)
	}

	if m.Resolve("single-winner", !winner.approved, "late") {
		t.Fatal("late resolution unexpectedly won")
	}
	if observed := m.observePending(p); observed != terminal {
		t.Fatalf("terminal resolution changed: got %+v, want %+v", observed, terminal)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-p.done:
		default:
			t.Fatal("pending done channel is not closed")
		}
	}
	assertResolutionRaceCleanup(t, m)
}

func TestApprovalResolutionDecisionBeatsReadyNonDecision(t *testing.T) {
	t.Run("cancellation", func(t *testing.T) {
		m := New("remote", time.Minute, nil)
		p := addResolutionRacePending(m, "decision-before-cancel")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if !m.Resolve(p.req.ID, true, "operator approved") {
			t.Fatal("decision did not resolve pending approval")
		}
		cancel()
		terminal := m.waitForPendingResolution(ctx, p, nil)
		if !terminal.resolution.Approved || terminal.resolution.Reason != "operator approved" || terminal.cause != terminalCauseDecision {
			t.Fatalf("terminal resolution = %+v cause=%v, want explicit approval", terminal.resolution, terminal.cause)
		}
		if err := terminalError(ctx, terminal.cause); err != nil {
			t.Fatalf("decision winner returned error: %v", err)
		}
		assertResolutionRaceCleanup(t, m)
	})

	t.Run("timeout", func(t *testing.T) {
		m := New("remote", time.Minute, nil)
		p := addResolutionRacePending(m, "decision-before-timeout")
		if !m.Resolve(p.req.ID, false, "operator denied") {
			t.Fatal("decision did not resolve pending approval")
		}
		timeout := make(chan time.Time)
		close(timeout)
		terminal := m.waitForPendingResolution(context.Background(), p, timeout)
		if terminal.resolution.Approved || terminal.resolution.Reason != "operator denied" || terminal.cause != terminalCauseDecision {
			t.Fatalf("terminal resolution = %+v cause=%v, want explicit denial", terminal.resolution, terminal.cause)
		}
		if err := terminalError(context.Background(), terminal.cause); err != nil {
			t.Fatalf("decision winner returned error: %v", err)
		}
		assertResolutionRaceCleanup(t, m)
	})
}

func TestApprovalResolutionCancellationWins(t *testing.T) {
	m := New("remote", time.Minute, nil)
	p := addResolutionRacePending(m, "cancel-winner")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	terminal := m.waitForPendingResolution(ctx, p, nil)
	if terminal.cause != terminalCauseCanceled || terminal.resolution.Approved || terminal.resolution.Reason != "context canceled" || terminal.resolution.Scope != ScopeOnce {
		t.Fatalf("terminal resolution = %+v cause=%v, want cancellation", terminal.resolution, terminal.cause)
	}
	if err := terminalError(ctx, terminal.cause); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v, want context.Canceled", err)
	}
	if m.Resolve(p.req.ID, true, "late approval") || m.Resolve(p.req.ID, false, "late denial") {
		t.Fatal("late explicit resolution changed cancellation winner")
	}
	if observed := m.observePending(p); observed != terminal {
		t.Fatalf("terminal resolution changed: got %+v, want %+v", observed, terminal)
	}
	assertResolutionRaceCleanup(t, m)
}

func TestApprovalResolutionTimeoutWins(t *testing.T) {
	m := New("remote", time.Minute, nil)
	p := addResolutionRacePending(m, "timeout-winner")
	timeout := make(chan time.Time)
	close(timeout)

	terminal := m.waitForPendingResolution(context.Background(), p, timeout)
	if terminal.cause != terminalCauseTimedOut || terminal.resolution.Approved || terminal.resolution.Reason != "approval timeout" || terminal.resolution.Scope != ScopeOnce {
		t.Fatalf("terminal resolution = %+v cause=%v, want timeout", terminal.resolution, terminal.cause)
	}
	if err := terminalError(context.Background(), terminal.cause); err == nil || err.Error() != "approval timeout" {
		t.Fatalf("timeout error = %v, want approval timeout", err)
	}
	if m.Resolve(p.req.ID, true, "late approval") || m.Resolve(p.req.ID, false, "late denial") {
		t.Fatal("late explicit resolution changed timeout winner")
	}
	if observed := m.observePending(p); observed != terminal {
		t.Fatalf("terminal resolution changed: got %+v, want %+v", observed, terminal)
	}
	assertResolutionRaceCleanup(t, m)
}

func TestApprovalResolutionEventMatchesDecisionWinner(t *testing.T) {
	gate := make(chan struct{})
	defer releaseResolutionRaceGate(gate)
	emitter := newResolutionRaceEmitter(1, gate)
	m := New("remote", time.Minute, emitter)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	result := startResolutionRaceRequest(m, ctx, Request{
		ID:        "event-truth",
		SessionID: "event-session",
		CommandID: "event-command",
		Kind:      "command",
		Target:    "echo",
	})
	requested := receiveResolutionRace(t, emitter.requested)
	if got := requested.Fields["approval_id"]; got != "event-truth" {
		t.Fatalf("requested approval ID = %v, want event-truth", got)
	}
	p := getResolutionRacePending(t, m, "event-truth")
	if !m.Resolve("event-truth", true, "operator approved") {
		t.Fatal("explicit approval did not win")
	}
	winner := m.observePending(p)
	cancel()
	releaseResolutionRaceGate(gate)

	got := receiveResolutionRace(t, result)
	if got.err != nil {
		t.Fatalf("decision winner returned error after cancellation: %v", got.err)
	}
	if got.resolution != winner.resolution {
		t.Fatalf("returned resolution = %+v, want stored winner %+v", got.resolution, winner.resolution)
	}

	appended, published := emitter.events()
	for name, events := range map[string][]types.Event{"appended": appended, "published": published} {
		resolved := resolutionRaceEventsOfType(events, "approval_resolved")
		if len(resolved) != 1 {
			t.Fatalf("%s approval_resolved events = %d, want 1", name, len(resolved))
		}
		event := resolved[0]
		if event.Fields["approval_id"] != "event-truth" || event.Fields["approved"] != true || event.Fields["reason"] != "operator approved" || event.Fields["scope"] != ScopeOnce {
			t.Fatalf("%s resolved event does not match decision winner: %+v", name, event.Fields)
		}
		if event.Fields["reason"] == "context canceled" {
			t.Fatalf("%s resolved event reported losing cancellation", name)
		}
	}
	assertResolutionRaceCleanup(t, m)
}

func TestApprovalResolutionScopeAndCleanupByTerminalCause(t *testing.T) {
	scope, ok := NewNetworkScope("example.com", 443)
	if !ok {
		t.Fatal("failed to create network scope")
	}

	for _, resolutionScope := range []string{ScopeOnce, ScopeSession} {
		resolutionScope := resolutionScope
		t.Run("decision-"+resolutionScope, func(t *testing.T) {
			gate := make(chan struct{})
			defer releaseResolutionRaceGate(gate)
			emitter := newResolutionRaceEmitter(1, gate)
			m := New("remote", time.Minute, emitter)
			request := Request{
				ID:        "scope-" + resolutionScope,
				SessionID: "scope-session",
				CommandID: "scope-command",
				Kind:      "network",
				Target:    scope.Label,
				Rule:      "approve-network",
				Fields:    ScopeFields(scope),
			}
			result := startResolutionRaceRequest(m, context.Background(), request)
			receiveResolutionRace(t, emitter.requested)
			p := getResolutionRacePending(t, m, request.ID)
			if !m.ResolveWithScopeTarget(request.ID, true, "operator", resolutionScope, scope) {
				t.Fatal("explicit scoped decision did not win")
			}
			releaseResolutionRaceGate(gate)

			got := receiveResolutionRace(t, result)
			if got.err != nil {
				t.Fatalf("scoped decision returned error: %v", got.err)
			}
			if got.resolution.Scope != resolutionScope || got.resolution.ScopeKey != scope.Key || m.observePending(p).cause != terminalCauseDecision {
				t.Fatalf("scoped terminal resolution = %+v", got.resolution)
			}

			m.mu.Lock()
			sessionDecision, sessionOK := m.scoped[request.SessionID][scope.Key]
			commandDecision, commandOK := m.commandScoped[request.SessionID][request.CommandID][scope.Key]
			m.mu.Unlock()
			switch resolutionScope {
			case ScopeOnce:
				if !commandOK || !commandDecision.Approved || sessionOK {
					t.Fatalf("once scope state: command=%+v ok=%v session=%+v ok=%v", commandDecision, commandOK, sessionDecision, sessionOK)
				}
			case ScopeSession:
				if !sessionOK || !sessionDecision.Approved || commandOK {
					t.Fatalf("session scope state: session=%+v ok=%v command=%+v ok=%v", sessionDecision, sessionOK, commandDecision, commandOK)
				}
			}
			assertResolutionRaceCleanup(t, m)
		})
	}

	t.Run("cancellation", func(t *testing.T) {
		gate := make(chan struct{})
		defer releaseResolutionRaceGate(gate)
		emitter := newResolutionRaceEmitter(1, gate)
		m := New("remote", time.Minute, emitter)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		request := Request{
			ID:        "scope-cancel",
			SessionID: "scope-cancel-session",
			CommandID: "scope-cancel-command",
			Kind:      "network",
			Fields:    ScopeFields(scope),
		}
		result := startResolutionRaceRequest(m, ctx, request)
		receiveResolutionRace(t, emitter.requested)
		p := getResolutionRacePending(t, m, request.ID)
		cancel()
		releaseResolutionRaceGate(gate)

		got := receiveResolutionRace(t, result)
		if !errors.Is(got.err, context.Canceled) || got.resolution.Reason != "context canceled" || m.observePending(p).cause != terminalCauseCanceled {
			t.Fatalf("cancellation result = %+v err=%v", got.resolution, got.err)
		}
		assertNoResolutionRaceScopes(t, m, request.SessionID)
		assertResolutionRaceCleanup(t, m)
	})

	t.Run("timeout", func(t *testing.T) {
		gate := make(chan struct{})
		defer releaseResolutionRaceGate(gate)
		emitter := newResolutionRaceEmitter(1, gate)
		m := New("remote", time.Minute, emitter)
		m.timeout = 0
		request := Request{
			ID:        "scope-timeout",
			SessionID: "scope-timeout-session",
			CommandID: "scope-timeout-command",
			Kind:      "network",
			Fields:    ScopeFields(scope),
		}
		result := startResolutionRaceRequest(m, context.Background(), request)
		receiveResolutionRace(t, emitter.requested)
		p := getResolutionRacePending(t, m, request.ID)
		releaseResolutionRaceGate(gate)

		got := receiveResolutionRace(t, result)
		if got.err == nil || got.err.Error() != "approval timeout" || got.resolution.Reason != "approval timeout" || m.observePending(p).cause != terminalCauseTimedOut {
			t.Fatalf("timeout result = %+v err=%v", got.resolution, got.err)
		}
		assertNoResolutionRaceScopes(t, m, request.SessionID)
		assertResolutionRaceCleanup(t, m)
	})
}

func TestApprovalResolutionSessionCoverageUsesTerminalTransition(t *testing.T) {
	gate := make(chan struct{})
	defer releaseResolutionRaceGate(gate)
	emitter := newResolutionRaceEmitter(2, gate)
	m := New("remote", time.Minute, emitter)
	scope, ok := NewNetworkScope("example.com", 443)
	if !ok {
		t.Fatal("failed to create network scope")
	}
	request := func(id, commandID string) Request {
		return Request{
			ID:        id,
			SessionID: "covered-session",
			CommandID: commandID,
			Kind:      "network",
			Target:    scope.Label,
			Rule:      "approve-network",
			Fields:    ScopeFields(scope),
		}
	}

	first := startResolutionRaceRequest(m, context.Background(), request("covered-first", "command-1"))
	second := startResolutionRaceRequest(m, context.Background(), request("covered-second", "command-2"))
	seen := make(map[any]bool)
	for i := 0; i < 2; i++ {
		seen[receiveResolutionRace(t, emitter.requested).Fields["approval_id"]] = true
	}
	if !seen["covered-first"] || !seen["covered-second"] {
		t.Fatalf("requested events = %v, want both covered approvals", seen)
	}
	firstPending := getResolutionRacePending(t, m, "covered-first")
	secondPending := getResolutionRacePending(t, m, "covered-second")

	if !m.ResolveForSessionWithScopeTarget("covered-session", "covered-first", true, "operator", ScopeSession, scope) {
		t.Fatal("session decision did not resolve source approval")
	}
	firstTerminal := m.observePending(firstPending)
	secondTerminal := m.observePending(secondPending)
	for id, terminal := range map[string]terminalResolution{
		"covered-first":  firstTerminal,
		"covered-second": secondTerminal,
	} {
		if terminal.cause != terminalCauseDecision || !terminal.resolution.Approved || terminal.resolution.Reason != "operator" || terminal.resolution.Scope != ScopeSession || terminal.resolution.ScopeKey != scope.Key {
			t.Fatalf("%s terminal resolution = %+v cause=%v", id, terminal.resolution, terminal.cause)
		}
	}
	if m.Resolve("covered-second", false, "late denial") {
		t.Fatal("late resolve changed covered terminal result")
	}
	m.mu.Lock()
	pendingCount := len(m.pending)
	m.mu.Unlock()
	if pendingCount != 0 {
		t.Fatalf("covered pending count before waiter release = %d, want 0", pendingCount)
	}
	releaseResolutionRaceGate(gate)

	for id, resultChannel := range map[string]<-chan resolutionRaceRequestResult{
		"covered-first":  first,
		"covered-second": second,
	} {
		result := receiveResolutionRace(t, resultChannel)
		if result.err != nil || !result.resolution.Approved || result.resolution.Reason != "operator" || result.resolution.Scope != ScopeSession || result.resolution.ScopeKey != scope.Key {
			t.Fatalf("%s waiter result = %+v err=%v", id, result.resolution, result.err)
		}
	}

	appended, published := emitter.events()
	for name, events := range map[string][]types.Event{"appended": appended, "published": published} {
		resolved := resolutionRaceEventsOfType(events, "approval_resolved")
		if len(resolved) != 2 {
			t.Fatalf("%s resolved event count = %d, want 2", name, len(resolved))
		}
		ids := make(map[any]int)
		for _, event := range resolved {
			ids[event.Fields["approval_id"]]++
			if event.Fields["approved"] != true || event.Fields["reason"] != "operator" || event.Fields["scope"] != ScopeSession {
				t.Fatalf("%s covered resolved event = %+v", name, event.Fields)
			}
		}
		if ids["covered-first"] != 1 || ids["covered-second"] != 1 {
			t.Fatalf("%s resolved event IDs = %v, want each approval once", name, ids)
		}
	}
	assertResolutionRaceCleanup(t, m)
}
