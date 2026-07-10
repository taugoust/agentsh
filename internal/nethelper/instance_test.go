package nethelper

import (
	"context"
	"strings"
	"testing"
)

type fixedRegistrationCount int

func (c fixedRegistrationCount) ActiveRegistrationCount() int { return int(c) }

func TestEphemeralInstanceControllerRelease(t *testing.T) {
	const credential = "0123456789abcdef0123456789abcdef"
	controller := NewEphemeralInstanceController(EphemeralInstanceControllerOptions{
		LeaseID:                  "lease-11111111-1111-4111-8111-111111111111",
		HelperInstanceCredential: credential,
		ExpectedUID:              1000,
		ExpectedGID:              100,
		EnforceGID:               true,
		Registrations:            fixedRegistrationCount(0),
	})
	resp, err := controller.ReleaseInstance(context.Background(), PeerInfo{
		PID:       42,
		UID:       1000,
		GID:       100,
		Supported: true,
	}, ReleaseInstanceRequest{
		ProtocolVersion:          CurrentProtocolVersion,
		RequestID:                "release-1",
		LeaseID:                  "lease-11111111-1111-4111-8111-111111111111",
		HelperInstanceCredential: credential,
	})
	if err != nil {
		t.Fatalf("ReleaseInstance: %v", err)
	}
	if !resp.OK || !controller.Released() {
		t.Fatalf("response=%+v released=%v", resp, controller.Released())
	}
}

func TestEphemeralInstanceControllerReleaseFailsClosed(t *testing.T) {
	const credential = "0123456789abcdef0123456789abcdef"
	base := EphemeralInstanceControllerOptions{
		LeaseID:                  "lease-11111111-1111-4111-8111-111111111111",
		HelperInstanceCredential: credential,
		ExpectedUID:              1000,
		ExpectedGID:              100,
		EnforceGID:               true,
	}
	cases := []struct {
		name          string
		peer          PeerInfo
		credential    string
		lease         string
		registrations int
		want          string
	}{
		{name: "missing peer credentials", peer: PeerInfo{}, credential: credential, lease: base.LeaseID, want: "peer credentials"},
		{name: "wrong uid", peer: PeerInfo{PID: 1, UID: 1001, GID: 100, Supported: true}, credential: credential, lease: base.LeaseID, want: "peer uid"},
		{name: "wrong gid", peer: PeerInfo{PID: 1, UID: 1000, GID: 101, Supported: true}, credential: credential, lease: base.LeaseID, want: "peer gid"},
		{name: "wrong credential", peer: PeerInfo{PID: 1, UID: 1000, GID: 100, Supported: true}, credential: strings.Repeat("a", 32), lease: base.LeaseID, want: "credential"},
		{name: "wrong lease", peer: PeerInfo{PID: 1, UID: 1000, GID: 100, Supported: true}, credential: credential, lease: "lease-22222222-2222-4222-8222-222222222222", want: "lease_id"},
		{name: "active registration", peer: PeerInfo{PID: 1, UID: 1000, GID: 100, Supported: true}, credential: credential, lease: base.LeaseID, registrations: 1, want: "registrations remain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := base
			opts.Registrations = fixedRegistrationCount(tc.registrations)
			controller := NewEphemeralInstanceController(opts)
			resp, err := controller.ReleaseInstance(context.Background(), tc.peer, ReleaseInstanceRequest{
				ProtocolVersion:          CurrentProtocolVersion,
				RequestID:                "release-1",
				LeaseID:                  tc.lease,
				HelperInstanceCredential: tc.credential,
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v, want substring %q", err, tc.want)
			}
			if resp.OK || controller.Released() {
				t.Fatalf("release unexpectedly succeeded: %+v", resp)
			}
		})
	}
}
