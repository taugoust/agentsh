package cli

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/detached"
)

func TestGuestControlCommandExposesFixedInputs(t *testing.T) {
	root := newGuestControlCmd("test")
	if !root.Hidden {
		t.Fatal("guest control command must remain hidden from ordinary users")
	}
	run, _, err := root.Find([]string{"run"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"manifest", "handshake", "workspace", "volume-root", "profile", "profile-digest",
		"allowed-policy", "probe-command", "probe-arg", "git-command",
	} {
		if run.Flags().Lookup(name) == nil {
			t.Fatalf("guest control run is missing --%s", name)
		}
	}
}

func TestGuestControlV4CarriesTrustedProxyControlEnvironment(t *testing.T) {
	proxyURL := "http://127.0.0.1:19083"
	assignments := guestEgressProxyEnvironment(proxyURL)
	ctx, err := withDetachedSupervisorFixedEnvironment(context.Background(), assignments)
	if err != nil {
		t.Fatal(err)
	}
	fixed := detachedSupervisorFixedEnvironment(ctx)
	service := detachedSupervisorServiceEnv(fixed, nil)
	want := detached.EnvGuestEgressProxyURL + "=" + proxyURL
	if len(fixed) != 1 || fixed[0] != want || len(service) != 1 || service[0] != want {
		t.Fatalf("fixed=%#v service=%#v, want trusted assignment %q", fixed, service, want)
	}
}

func TestGuestControlShutdownDoesNotWaitForInnerSystemdTimeout(t *testing.T) {
	handler := &guestControlHandler{
		sessionID:  "session-11111111-1111-4111-8111-111111111111",
		stopBudget: time.Millisecond,
		stopSession: func(ctx context.Context, _ string) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}
	if err := handler.Shutdown(context.Background()); err != nil {
		t.Fatalf("outer-owned shutdown refused an expired inner stop budget: %v", err)
	}
	if !handler.shutdownDone {
		t.Fatal("shutdown did not become idempotently complete")
	}
}

func TestGuestControlShutdownReturnsImmediateInnerStopError(t *testing.T) {
	failure := errors.New("inner stop failed")
	handler := &guestControlHandler{
		sessionID: "session-11111111-1111-4111-8111-111111111111",
		stopSession: func(context.Context, string) error {
			return failure
		},
	}
	if err := handler.Shutdown(context.Background()); !errors.Is(err, failure) {
		t.Fatalf("shutdown error = %v, want %v", err, failure)
	}
}

func TestGuestControlRequestAdmissionIsBoundedAndRejectsReplay(t *testing.T) {
	handler := &guestControlHandler{}
	if !handler.ClaimRequest("request-0") || handler.ClaimRequest("request-0") {
		t.Fatal("guest control did not reject a replayed request identity")
	}
	for index := 1; index < 4096; index++ {
		if !handler.ClaimRequest(requestID(index)) {
			t.Fatalf("request %d was refused before the admission bound", index)
		}
	}
	if handler.ClaimRequest("request-overflow") {
		t.Fatal("guest control accepted a request beyond its admission bound")
	}
}

func requestID(index int) string {
	const digits = "0123456789"
	if index == 0 {
		return "request-0"
	}
	var reversed [20]byte
	position := len(reversed)
	for index > 0 {
		position--
		reversed[position] = digits[index%10]
		index /= 10
	}
	return "request-" + string(reversed[position:])
}
