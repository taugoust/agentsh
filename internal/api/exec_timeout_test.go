package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestChooseCommandTimeout_UsesPolicyWhenNoRequest(t *testing.T) {
	req := types.ExecRequest{}
	got := chooseCommandTimeout(req, 10*time.Second)
	if got != 10*time.Second {
		t.Fatalf("expected 10s, got %s", got)
	}
}

func TestChooseCommandTimeout_CapsRequestToPolicy(t *testing.T) {
	req := types.ExecRequest{Timeout: "20s"}
	got := chooseCommandTimeout(req, 10*time.Second)
	if got != 10*time.Second {
		t.Fatalf("expected 10s cap, got %s", got)
	}
}

func TestChooseCommandTimeout_AllowsSmallerRequest(t *testing.T) {
	req := types.ExecRequest{Timeout: "2s"}
	got := chooseCommandTimeout(req, 10*time.Second)
	if got != 2*time.Second {
		t.Fatalf("expected 2s, got %s", got)
	}
}

func TestChooseCommandTimeout_DefaultWhenNoPolicy(t *testing.T) {
	req := types.ExecRequest{}
	got := chooseCommandTimeout(req, 0)
	if got != defaultCommandTimeout {
		t.Fatalf("expected default %s, got %s", defaultCommandTimeout, got)
	}
}

func TestExtendableCommandTimeout_ExpiresAtInitialDeadline(t *testing.T) {
	ctx, cancel := withExtendableCommandTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	select {
	case <-ctx.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("context did not time out")
	}
	if !commandTimedOut(ctx) {
		t.Fatalf("expected commandTimedOut to report deadline")
	}
	if !errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
		t.Fatalf("cause = %v, want deadline exceeded", context.Cause(ctx))
	}
}

func TestExtendableCommandTimeout_ExtendsDeadline(t *testing.T) {
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
		t.Fatalf("expected commandTimedOut to report deadline")
	}
}
