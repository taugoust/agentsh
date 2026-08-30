package api

import (
	"context"
	"testing"

	"github.com/agentsh/agentsh/internal/approvals"
)

func TestValidateGuestEgressApprovalRequest(t *testing.T) {
	valid := guestEgressApprovalRequest{
		DraftSessionID: "session-11111111-1111-1111-1111-111111111111",
		Kind:           "network",
		Target:         "unknown.example:443",
		Rule:           "unknown-egress",
	}
	scope, err := validateGuestEgressApprovalRequest(valid)
	if err != nil || scope.Kind != "network" || scope.Label != "unknown.example:443" {
		t.Fatalf("valid request rejected: scope=%+v err=%v", scope, err)
	}
	cases := []guestEgressApprovalRequest{
		{DraftSessionID: "session-bad", Kind: valid.Kind, Target: valid.Target},
		{DraftSessionID: valid.DraftSessionID, Kind: "command", Target: valid.Target},
		{DraftSessionID: valid.DraftSessionID, Kind: valid.Kind, Target: "unknown.example"},
		{DraftSessionID: valid.DraftSessionID, Kind: valid.Kind, Target: " unknown.example:443"},
	}
	for _, request := range cases {
		if _, err := validateGuestEgressApprovalRequest(request); err == nil {
			t.Fatalf("invalid request accepted: %+v", request)
		}
	}
}

func TestGuestEgressDelegationsPinDraftIndependently(t *testing.T) {
	a := &App{approvals: approvals.New("remote", 0, nil), guestEgressApprovalDelegations: make(map[[32]byte]*guestEgressApprovalDelegation)}
	_, firstDigest, err := mintChildCapabilityToken()
	if err != nil {
		t.Fatal(err)
	}
	_, secondDigest, err := mintChildCapabilityToken()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	a.guestEgressApprovalDelegations[firstDigest] = &guestEgressApprovalDelegation{digest: firstDigest, lifecycle: ctx, cancel: cancel}
	a.guestEgressApprovalDelegations[secondDigest] = &guestEgressApprovalDelegation{digest: secondDigest, lifecycle: ctx, cancel: cancel}
	first := *a.guestEgressApprovalDelegations[firstDigest]
	second := *a.guestEgressApprovalDelegations[secondDigest]
	one := "session-11111111-1111-1111-1111-111111111111"
	two := "session-22222222-2222-2222-2222-222222222222"
	if err := a.bindGuestEgressApprovalDraft(&first, one); err != nil {
		t.Fatal(err)
	}
	if err := a.bindGuestEgressApprovalDraft(&first, two); err == nil {
		t.Fatal("one delegation was rebound across parallel Drafts")
	}
	if err := a.bindGuestEgressApprovalDraft(&second, two); err != nil {
		t.Fatalf("independent delegation was not usable: %v", err)
	}
}
