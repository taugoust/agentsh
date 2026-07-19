package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/commandtimeout"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestCommandTimeoutResolver(t *testing.T) {
	tests := []struct {
		name          string
		request       types.ExecRequest
		policy        time.Duration
		wantDuration  time.Duration
		wantRequested *int64
		wantSource    types.CommandTimeoutSource
	}{
		{
			name:         "policy default",
			policy:       40 * time.Millisecond,
			wantDuration: 40 * time.Millisecond,
			wantSource:   types.CommandTimeoutSourcePolicyDefault,
		},
		{
			name:         "empty is compatible omission",
			request:      types.ExecRequest{Timeout: ""},
			policy:       40 * time.Millisecond,
			wantDuration: 40 * time.Millisecond,
			wantSource:   types.CommandTimeoutSourcePolicyDefault,
		},
		{
			name:         "fallback",
			wantDuration: defaultCommandTimeout,
			wantSource:   types.CommandTimeoutSourceFallback,
		},
		{
			name:          "shorter explicit request",
			request:       types.ExecRequest{Timeout: "12ms"},
			policy:        40 * time.Millisecond,
			wantDuration:  12 * time.Millisecond,
			wantRequested: int64Pointer(12),
			wantSource:    types.CommandTimeoutSourceExplicit,
		},
		{
			name:          "policy cap",
			request:       types.ExecRequest{Timeout: "80ms"},
			policy:        40 * time.Millisecond,
			wantDuration:  40 * time.Millisecond,
			wantRequested: int64Pointer(80),
			wantSource:    types.CommandTimeoutSourcePolicyCap,
		},
		{
			name:          "uncapped explicit request without policy",
			request:       types.ExecRequest{Timeout: "80ms"},
			wantDuration:  80 * time.Millisecond,
			wantRequested: int64Pointer(80),
			wantSource:    types.CommandTimeoutSourceExplicit,
		},
		{
			name:          "fractional explicit request rounds metadata up",
			request:       types.ExecRequest{Timeout: "1.9ms"},
			policy:        40 * time.Millisecond,
			wantDuration:  1900 * time.Microsecond,
			wantRequested: int64Pointer(2),
			wantSource:    types.CommandTimeoutSourceExplicit,
		},
		{
			name:          "fractional policy cap rounds metadata up",
			request:       types.ExecRequest{Timeout: "2.1ms"},
			policy:        1900 * time.Microsecond,
			wantDuration:  1900 * time.Microsecond,
			wantRequested: int64Pointer(3),
			wantSource:    types.CommandTimeoutSourcePolicyCap,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolved, err := resolveCommandTimeout(test.request, test.policy)
			if err != nil {
				t.Fatalf("resolveCommandTimeout: %v", err)
			}
			if resolved.Duration != test.wantDuration {
				t.Fatalf("duration = %s, want %s", resolved.Duration, test.wantDuration)
			}
			wantEffectiveMS := commandtimeout.CeilMilliseconds(test.wantDuration)
			if resolved.Metadata.EffectiveMS != wantEffectiveMS {
				t.Fatalf("effective_ms = %d, want %d", resolved.Metadata.EffectiveMS, wantEffectiveMS)
			}
			if resolved.Metadata.Source != test.wantSource {
				t.Fatalf("source = %q, want %q", resolved.Metadata.Source, test.wantSource)
			}
			if !equalInt64Pointers(resolved.Metadata.RequestedMS, test.wantRequested) {
				t.Fatalf("requested_ms = %v, want %v", resolved.Metadata.RequestedMS, test.wantRequested)
			}
		})
	}
}

func TestCommandTimeoutMetadataReportsBoundedApprovalAllowance(t *testing.T) {
	app := &App{approvals: approvals.New("api", 250*time.Millisecond+time.Nanosecond, nil)}
	resolution, err := app.resolveCommandTimeout(types.ExecRequest{Timeout: "2s"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resolution.Metadata.ApprovalExtensionMS != 251 {
		t.Fatalf("approval_extension_ms = %d, want 251", resolution.Metadata.ApprovalExtensionMS)
	}
}

func TestCommandTimeoutResolverRejectsInvalidExplicitValues(t *testing.T) {
	for _, value := range []string{"not-a-duration", "0", "0s", "-1ms", "500us", "0.5ms", "2562048h"} {
		t.Run(value, func(t *testing.T) {
			if _, err := resolveCommandTimeout(types.ExecRequest{Timeout: value}, time.Second); err == nil {
				t.Fatalf("explicit timeout %q was accepted", value)
			}
		})
	}
}

func TestCommandTimeoutTerminationClassificationUsesRunnerError(t *testing.T) {
	failure := errors.New("execution failed")
	tests := []struct {
		name       string
		execErr    error
		wantReason string
		wantCode   string
	}{
		{name: "command timeout", execErr: errCommandTimeout, wantReason: types.TerminationReasonCommandTimeout, wantCode: "E_COMMAND_TIMEOUT"},
		{name: "caller deadline", execErr: context.DeadlineExceeded, wantReason: types.TerminationReasonCallerDeadline, wantCode: "E_COMMAND_FAILED"},
		{name: "caller cancellation", execErr: context.Canceled, wantReason: types.TerminationReasonCallerCancelled, wantCode: "E_COMMAND_FAILED"},
		{name: "ordinary failure", execErr: failure, wantCode: "E_COMMAND_FAILED"},
		{name: "success remains success"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reason, resultErr := executionTermination(test.execErr)
			if reason != test.wantReason {
				t.Fatalf("termination reason = %q, want %q", reason, test.wantReason)
			}
			if test.wantCode == "" {
				if resultErr != nil {
					t.Fatalf("unexpected result error: %+v", resultErr)
				}
				return
			}
			if resultErr == nil || resultErr.Code != test.wantCode {
				t.Fatalf("result error = %+v, want code %q", resultErr, test.wantCode)
			}
		})
	}
}

func TestCommandTimeoutCauseExpiresAtInitialDeadline(t *testing.T) {
	ctx, cancel := withExtendableCommandTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	select {
	case <-ctx.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("context did not time out")
	}
	if !commandTimedOut(ctx) {
		t.Fatal("command timer was not recognized")
	}
	if !errors.Is(context.Cause(ctx), errCommandTimeout) {
		t.Fatalf("cause = %v, want private command timeout cause", context.Cause(ctx))
	}
}

func TestCommandTimeoutCauseExtendsForApproval(t *testing.T) {
	ctx, cancel := withExtendableCommandTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	approvals.ExtendCommandTimeoutForApproval(ctx, 200*time.Millisecond)

	select {
	case <-ctx.Done():
		t.Fatalf("context ended before extended deadline: %v", context.Cause(ctx))
	case <-time.After(100 * time.Millisecond):
	}

	select {
	case <-ctx.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("context did not time out after extended deadline")
	}
	if !commandTimedOut(ctx) {
		t.Fatal("extended command timer was not recognized")
	}
}

func TestCommandTimeoutApprovalExtensionsShareFirstAllowance(t *testing.T) {
	ctx, extender := newCommandTimeoutExtender(context.Background(), time.Hour)
	defer extender.cancelContext()

	extender.mu.Lock()
	initialDeadline := extender.initialDeadline
	extender.mu.Unlock()
	allowance := 250 * time.Millisecond
	if !extendCommandTimeoutAt(extender, allowance, initialDeadline.Add(-time.Nanosecond)) {
		t.Fatal("first pre-deadline extension was rejected")
	}

	wantMaximum := initialDeadline.Add(allowance)
	for i, extra := range []time.Duration{allowance, time.Second, 24 * time.Hour} {
		if !extendCommandTimeoutAt(extender, extra, initialDeadline.Add(time.Duration(i+1)*time.Nanosecond)) {
			t.Fatalf("pre-deadline extension %d was rejected", i+2)
		}
	}

	extender.mu.Lock()
	deadline := extender.deadline
	maximum := extender.maximumDeadline
	extender.mu.Unlock()
	if !deadline.Equal(wantMaximum) || !maximum.Equal(wantMaximum) {
		t.Fatalf("deadline=%s maximum=%s, want one cumulative allowance ending %s", deadline, maximum, wantMaximum)
	}
	if cause := context.Cause(ctx); cause != nil {
		t.Fatalf("context ended during accepted extensions: %v", cause)
	}
}

func TestCommandTimeoutAcceptedBoundaryExtensionIsNotLost(t *testing.T) {
	ctx, extender := newCommandTimeoutExtender(context.Background(), time.Hour)
	defer extender.cancelContext()

	extender.mu.Lock()
	initialDeadline := extender.initialDeadline
	extender.mu.Unlock()
	allowance := 100 * time.Millisecond
	if !extendCommandTimeoutAt(extender, allowance, initialDeadline.Add(-time.Nanosecond)) {
		t.Fatal("extension acquired immediately before the initial deadline was rejected")
	}

	// Model the old timer callback acquiring the mutex at its original
	// deadline. It must observe the synchronously applied extension rather than
	// discard it and expire the command.
	extender.mu.Lock()
	expired := extender.expireLocked(initialDeadline)
	extender.mu.Unlock()
	if expired || context.Cause(ctx) != nil {
		t.Fatalf("stale timer discarded accepted extension: expired=%v cause=%v", expired, context.Cause(ctx))
	}

	maximumDeadline := initialDeadline.Add(allowance)
	if extendCommandTimeoutAt(extender, time.Second, maximumDeadline) {
		t.Fatal("extension at the maximum deadline was accepted")
	}
	if !errors.Is(context.Cause(ctx), errCommandTimeout) {
		t.Fatalf("boundary loss cause = %v, want errCommandTimeout", context.Cause(ctx))
	}
}

func extendCommandTimeoutAt(extender *commandTimeoutExtender, extra time.Duration, now time.Time) bool {
	extender.mu.Lock()
	defer extender.mu.Unlock()
	return extender.extendLocked(extra, now)
}

func TestCommandTimeoutCauseDoesNotClaimParentDeadline(t *testing.T) {
	parent, parentCancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer parentCancel()
	ctx, cancel := withExtendableCommandTimeout(parent, time.Second)
	defer cancel()
	<-ctx.Done()
	if commandTimedOut(ctx) {
		t.Fatalf("parent deadline was mislabeled: cause=%v", context.Cause(ctx))
	}
	if !errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
		t.Fatalf("cause = %v, want parent deadline", context.Cause(ctx))
	}
}

func int64Pointer(value int64) *int64 { return &value }

func equalInt64Pointers(left, right *int64) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}
