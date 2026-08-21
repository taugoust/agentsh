package nethelper

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fixedRegistrationCount int

type fakeInstanceTimer struct{ ch chan time.Time }

func (t *fakeInstanceTimer) C() <-chan time.Time      { return t.ch }
func (t *fakeInstanceTimer) Reset(time.Duration) bool { return true }
func (t *fakeInstanceTimer) Stop() bool               { return true }

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

func TestEphemeralInstanceControllerStatusRenewalAndHardCap(t *testing.T) {
	const credential = "0123456789abcdef0123456789abcdef"
	lease := "lease-11111111-1111-4111-8111-111111111111"
	now := time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC)
	current := now
	controller := NewEphemeralInstanceController(EphemeralInstanceControllerOptions{
		LeaseID: lease, UnitName: "agentsh-nethelper.service", HelperInstanceCredential: credential,
		ExpectedUID: 1000, ExpectedGID: 100, EnforceGID: true,
		CreatedAt: now, HardExpiresAt: now.Add(60 * time.Hour), SoftLease: 49 * time.Hour,
		Now: func() time.Time { return current }, Registrations: fixedRegistrationCount(0),
	})
	peer := PeerInfo{PID: 42, UID: 1000, GID: 100, Supported: true}
	status, err := controller.InstanceStatus(context.Background(), peer, InstanceStatusRequest{ProtocolVersion: 1, RequestID: "status-1", LeaseID: lease, HelperInstanceCredential: credential})
	if err != nil || !status.OK || !status.SoftExpiresAt.Equal(now.Add(49*time.Hour)) {
		t.Fatalf("initial status=%+v err=%v", status, err)
	}
	current = now.Add(20 * time.Hour)
	renewed, err := controller.RenewInstance(context.Background(), peer, RenewInstanceRequest{ProtocolVersion: 1, RequestID: "renew-1", LeaseID: lease, HelperInstanceCredential: credential})
	if err != nil {
		t.Fatalf("RenewInstance: %v", err)
	}
	if !renewed.SoftExpiresAt.Equal(now.Add(60*time.Hour)) || renewed.RenewalGeneration != 1 {
		t.Fatalf("renewed status=%+v", renewed)
	}
	current = now.Add(60 * time.Hour)
	status, err = controller.InstanceStatus(context.Background(), peer, InstanceStatusRequest{ProtocolVersion: 1, RequestID: "status-2", LeaseID: lease, HelperInstanceCredential: credential})
	if err == nil || status.Status != "expired" || status.Reason != "hard-expiry" {
		t.Fatalf("hard-expiry status=%+v err=%v", status, err)
	}
	if _, err := controller.RenewInstance(context.Background(), peer, RenewInstanceRequest{ProtocolVersion: 1, RequestID: "renew-2", LeaseID: lease, HelperInstanceCredential: credential}); err == nil {
		t.Fatal("renewal succeeded after hard expiry")
	}
}

func TestEphemeralInstanceControllerSoftExpiryStopsService(t *testing.T) {
	created := time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC)
	var current atomic.Int64
	current.Store(created.UnixNano())
	timer := &fakeInstanceTimer{ch: make(chan time.Time, 1)}
	stopped := make(chan struct{}, 1)
	controller := NewEphemeralInstanceController(EphemeralInstanceControllerOptions{
		LeaseID:                  "lease-11111111-1111-4111-8111-111111111111",
		HelperInstanceCredential: "0123456789abcdef0123456789abcdef",
		ExpectedUID:              1000, CreatedAt: created, HardExpiresAt: created.Add(192 * time.Hour), SoftLease: 49 * time.Hour,
		Now: func() time.Time { return time.Unix(0, current.Load()) }, NewTimer: func(time.Duration) InstanceTimer { return timer },
		Stop: func() { stopped <- struct{}{} },
	})
	expires := created.Add(49 * time.Hour)
	current.Store(expires.UnixNano())
	timer.ch <- expires
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("soft expiry did not invoke service stop")
	}
	status, err := controller.InstanceStatus(context.Background(), PeerInfo{PID: 1, UID: 1000, Supported: true}, InstanceStatusRequest{
		ProtocolVersion: 1, RequestID: "status", LeaseID: controller.opts.LeaseID, HelperInstanceCredential: controller.opts.HelperInstanceCredential,
	})
	if err == nil || status.Reason != "soft-lease-expired" {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func TestEphemeralInstanceControllerStatusAuthentication(t *testing.T) {
	controller := NewEphemeralInstanceController(EphemeralInstanceControllerOptions{
		LeaseID: "lease-11111111-1111-4111-8111-111111111111", HelperInstanceCredential: "0123456789abcdef0123456789abcdef",
		ExpectedUID: 1000, ExpectedGID: 100, EnforceGID: true,
	})
	resp, err := controller.InstanceStatus(context.Background(), PeerInfo{PID: 1, UID: 1000, GID: 100, Supported: true}, InstanceStatusRequest{
		ProtocolVersion: 1, RequestID: "status-1", LeaseID: "lease-11111111-1111-4111-8111-111111111111", HelperInstanceCredential: strings.Repeat("a", 32),
	})
	if err == nil || resp.OK || strings.Contains(fmt.Sprintf("%+v", resp), "0123456789abcdef") {
		t.Fatalf("unauthenticated status response=%+v err=%v", resp, err)
	}
}

func TestEphemeralInstanceControllerAttestsOnlyFixedAuthenticatedLease(t *testing.T) {
	const (
		lease      = "lease-11111111-1111-4111-8111-111111111111"
		credential = "0123456789abcdef0123456789abcdef"
	)
	called := false
	want := CompositionRuntimeAttestation{
		Runtime:        CompositionRuntimeInode{Device: 1, Inode: 2, Mode: 0o41733, UID: 0, GID: 0},
		LeaseDirectory: CompositionRuntimeInode{Device: 1, Inode: 1, Mode: 0o40711, UID: 0, GID: 0},
	}
	controller := NewEphemeralInstanceController(EphemeralInstanceControllerOptions{
		LeaseID: lease, HelperInstanceCredential: credential, ExpectedUID: 1000, ExpectedGID: 100, EnforceGID: true,
		AttestCompositionRuntime: func(uid uint32, gotLease string) (CompositionRuntimeAttestation, error) {
			called = true
			if uid != 1000 || gotLease != lease {
				t.Fatalf("attester received uid=%d lease=%q", uid, gotLease)
			}
			return want, nil
		},
	})
	peer := PeerInfo{PID: 1, UID: 1000, GID: 100, Supported: true}
	resp, err := controller.AttestCompositionRuntime(context.Background(), peer, AttestCompositionRuntimeRequest{
		ProtocolVersion: CurrentProtocolVersion, RequestID: "attest-1", LeaseID: lease, HelperInstanceCredential: credential,
	})
	if err != nil || !resp.OK || resp.Attestation != want || !called {
		t.Fatalf("attestation response=%+v called=%t err=%v", resp, called, err)
	}
	called = false
	resp, err = controller.AttestCompositionRuntime(context.Background(), peer, AttestCompositionRuntimeRequest{
		ProtocolVersion: CurrentProtocolVersion, RequestID: "attest-2", LeaseID: lease, HelperInstanceCredential: strings.Repeat("a", 32),
	})
	if err == nil || resp.OK || called {
		t.Fatalf("unauthenticated attestation response=%+v called=%t err=%v", resp, called, err)
	}
}

type atomicRegistrationCount struct{ value atomic.Int32 }

func (c *atomicRegistrationCount) ActiveRegistrationCount() int { return int(c.value.Load()) }

func TestEphemeralInstanceControllerRuntimeOnlyUsesHardExpiry(t *testing.T) {
	created := time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC)
	controller := NewEphemeralInstanceController(EphemeralInstanceControllerOptions{CreatedAt: created, HardExpiresAt: created.Add(192 * time.Hour)})
	if !controller.softExpiresAt.Equal(controller.opts.HardExpiresAt) {
		t.Fatalf("runtime-only soft expiry=%s hard=%s", controller.softExpiresAt, controller.opts.HardExpiresAt)
	}
}

func TestReleaseWaitsForInFlightRegistrationAndClosesAdmission(t *testing.T) {
	const credential = "0123456789abcdef0123456789abcdef"
	gate := NewOperationGate()
	registrations := &atomicRegistrationCount{}
	done, err := gate.Admit()
	if err != nil {
		t.Fatal(err)
	}
	controller := NewEphemeralInstanceController(EphemeralInstanceControllerOptions{
		LeaseID: "lease-11111111-1111-4111-8111-111111111111", HelperInstanceCredential: credential,
		ExpectedUID: 1000, Registrations: registrations, Operations: gate,
	})
	result := make(chan error, 1)
	go func() {
		_, releaseErr := controller.ReleaseInstance(context.Background(), PeerInfo{PID: 1, UID: 1000, Supported: true}, ReleaseInstanceRequest{
			ProtocolVersion: 1, RequestID: "release", LeaseID: controller.opts.LeaseID, HelperInstanceCredential: credential,
		})
		result <- releaseErr
	}()
	// StopAndWait has closed admission before waiting for the held operation.
	for i := 0; i < 100; i++ {
		if rejectedDone, rejected := gate.Admit(); rejected != nil {
			break
		} else {
			rejectedDone()
			time.Sleep(time.Millisecond)
		}
		if i == 99 {
			t.Fatal("release did not close lifecycle admission")
		}
	}
	registrations.value.Store(1)
	done()
	if releaseErr := <-result; releaseErr == nil || !strings.Contains(releaseErr.Error(), "registrations remain") {
		t.Fatalf("release error=%v", releaseErr)
	}
	if controller.Released() {
		t.Fatal("controller released with live registration")
	}
	cleanupDone, err := gate.Admit()
	if err != nil {
		t.Fatalf("admission was not rolled back for cleanup: %v", err)
	}
	cleanupDone()
}

func TestReleaseTimeoutReopensLifecycleAdmission(t *testing.T) {
	const credential = "0123456789abcdef0123456789abcdef"
	gate := NewOperationGate()
	held, err := gate.Admit()
	if err != nil {
		t.Fatal(err)
	}
	defer held()
	controller := NewEphemeralInstanceController(EphemeralInstanceControllerOptions{
		LeaseID: "lease-11111111-1111-4111-8111-111111111111", HelperInstanceCredential: credential,
		ExpectedUID: 1000, Operations: gate, ReleaseDrainTimeout: 20 * time.Millisecond,
	})
	started := time.Now()
	_, err = controller.ReleaseInstance(context.Background(), PeerInfo{PID: 1, UID: 1000, Supported: true}, ReleaseInstanceRequest{
		ProtocolVersion: 1, RequestID: "release-timeout", LeaseID: controller.opts.LeaseID, HelperInstanceCredential: credential,
	})
	if err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("release error=%v", err)
	}
	if time.Since(started) > time.Second || controller.Released() {
		t.Fatal("timed-out release stalled or committed")
	}
	cleanup, err := gate.Admit()
	if err != nil {
		t.Fatalf("release timeout left admission closed: %v", err)
	}
	cleanup()
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
