package runtimeprovider

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/pkg/types"
)

type fakeProvider struct {
	mu           sync.Mutex
	name         string
	capabilities Capabilities
	instance     *fakeInstance
	startErr     error
	recoverErr   error
	openErr      error
	preflightErr error
	recoverBlock <-chan struct{}
	starts       int
	recovers     int
	opens        int
}

func (p *fakeProvider) Name() string { return p.name }
func (p *fakeProvider) Preflight(context.Context, Request) (Capabilities, error) {
	return p.capabilities, p.preflightErr
}
func (p *fakeProvider) Start(context.Context, Request) (Instance, error) {
	p.starts++
	return p.instance, p.startErr
}
func (p *fakeProvider) Open(context.Context, Manifest) (Instance, error) {
	p.opens++
	return p.instance, p.openErr
}
func (p *fakeProvider) OpenUnprovisionedCleanup(context.Context, Manifest) (Instance, error) {
	p.opens++
	return p.instance, p.openErr
}
func (p *fakeProvider) Recover(context.Context, Manifest) (Instance, error) {
	p.mu.Lock()
	p.recovers++
	p.mu.Unlock()
	if p.recoverBlock != nil {
		<-p.recoverBlock
	}
	return p.instance, p.recoverErr
}

type resumableFakeProvider struct{ *fakeProvider }

func (p *resumableFakeProvider) CanResumeStopped(Manifest) bool { return true }

type fakeInstance struct {
	mu              sync.Mutex
	identity        Identity
	endpoint        Endpoint
	status          Status
	probeErr        error
	stopErr         error
	destroyErr      error
	stops           int
	destroys        int
	cleanupCanceled bool
	controlPlane    ControlPlaneSnapshot
	controlPlaneErr error
	stopStarted     chan struct{}
	stopRelease     <-chan struct{}
	stopSignalOnce  sync.Once
}

func (i *fakeInstance) Identity() Identity { return i.identity }
func (i *fakeInstance) Endpoint() Endpoint { return i.endpoint }
func (i *fakeInstance) Probe(ctx context.Context) (Status, error) {
	if i.probeErr != nil {
		return Status{}, i.probeErr
	}
	if err := ctx.Err(); err != nil {
		return Status{}, err
	}
	return i.status, nil
}
func (i *fakeInstance) ControlPlane(context.Context) (ControlPlaneSnapshot, error) {
	return i.controlPlane, i.controlPlaneErr
}
func (i *fakeInstance) Stop(ctx context.Context, _ StopReason) error {
	i.mu.Lock()
	i.stops++
	i.cleanupCanceled = i.cleanupCanceled || ctx.Err() != nil
	started := i.stopStarted
	release := i.stopRelease
	err := i.stopErr
	i.mu.Unlock()
	if started != nil {
		i.stopSignalOnce.Do(func() { close(started) })
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}
func (i *fakeInstance) Destroy(ctx context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.destroys++
	i.cleanupCanceled = i.cleanupCanceled || ctx.Err() != nil
	return i.destroyErr
}

func TestControllerStartPersistsReadyExactRuntime(t *testing.T) {
	request, provider, instance := readyFixture(t)
	controller := Controller{CleanupTimeout: time.Second}
	got, err := controller.Start(context.Background(), provider, request)
	if err != nil {
		t.Fatal(err)
	}
	if got != instance || provider.starts != 1 || instance.stops != 0 || instance.destroys != 0 {
		t.Fatalf("start lifecycle provider=%d stops=%d destroys=%d", provider.starts, instance.stops, instance.destroys)
	}
	manifest, err := ReadManifest(request.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.State != StateReady || manifest.Identity != instance.identity || manifest.Endpoint != instance.endpoint || manifest.CleanupComplete {
		t.Fatalf("ready manifest = %+v", manifest)
	}
	info, err := os.Stat(ManifestPath(request.StateDir))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("manifest mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestControllerResumesStoppedRetainedRuntimeAtHigherGeneration(t *testing.T) {
	request, base, instance := readyFixture(t)
	provider := &resumableFakeProvider{fakeProvider: base}
	controller := Controller{CleanupTimeout: time.Second}
	if _, err := controller.Start(context.Background(), provider, request); err != nil {
		t.Fatal(err)
	}
	ready, err := ReadManifest(request.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Stop(context.Background(), provider, request.StateDir, ready, StopReasonUser); err != nil {
		t.Fatal(err)
	}
	stopped, err := ReadManifest(request.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	instance.identity.Generation++
	instance.identity.IncarnationID = "incarnation-resumed"
	instance.status = Status{Identity: instance.identity, Endpoint: instance.endpoint, State: StateReady, Ready: true, Recoverable: true}
	if _, err := controller.Recover(context.Background(), provider, request.StateDir, stopped); err != nil {
		t.Fatal(err)
	}
	resumed, err := ReadManifest(request.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.State != StateReady || resumed.Identity.Generation != stopped.Identity.Generation+1 || resumed.CleanupComplete {
		t.Fatalf("resumed manifest = %+v", resumed)
	}
}

func TestControllerCancelledStartUsesIndependentExactCleanup(t *testing.T) {
	request, provider, instance := readyFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (Controller{CleanupTimeout: time.Second}).Start(ctx, provider, request)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled start error = %v", err)
	}
	if instance.stops != 1 || instance.destroys != 1 || instance.cleanupCanceled {
		t.Fatalf("cleanup stops=%d destroys=%d cancelled=%t", instance.stops, instance.destroys, instance.cleanupCanceled)
	}
	manifest, readErr := ReadManifest(request.StateDir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if manifest.State != StateFailed || !manifest.CleanupComplete {
		t.Fatalf("cancelled manifest = %+v", manifest)
	}
}

func TestControllerRejectsIdentityMismatchAndCleansExactStartedInstance(t *testing.T) {
	request, provider, instance := readyFixture(t)
	instance.identity.SessionID = "session-other"
	instance.status.Identity = instance.identity
	_, err := (Controller{CleanupTimeout: time.Second}).Start(context.Background(), provider, request)
	if err == nil || !strings.Contains(err.Error(), "different exact identity") {
		t.Fatalf("identity mismatch error = %v", err)
	}
	if instance.stops != 1 || instance.destroys != 1 {
		t.Fatalf("mismatched runtime cleanup stops=%d destroys=%d", instance.stops, instance.destroys)
	}
}

func TestControllerRecoversCrashedRuntimeWithNewIncarnation(t *testing.T) {
	request, provider, instance := readyFixture(t)
	controller := Controller{CleanupTimeout: time.Second}
	if _, err := controller.Start(context.Background(), provider, request); err != nil {
		t.Fatal(err)
	}
	manifest, err := ReadManifest(request.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	instance.status = Status{Identity: instance.identity, Endpoint: instance.endpoint, State: StateFailed, Ready: false, Recoverable: true, LastError: "runtime crashed"}
	crashed, err := instance.Probe(context.Background())
	if err != nil || crashed.State != StateFailed {
		t.Fatalf("crash probe = %+v, %v", crashed, err)
	}
	instance.identity.Generation++
	instance.identity.IncarnationID = "incarnation-2"
	instance.status = Status{Identity: instance.identity, Endpoint: instance.endpoint, State: StateReady, Ready: true, Recoverable: true}
	got, err := controller.Recover(context.Background(), provider, request.StateDir, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if got != instance || provider.recovers != 1 {
		t.Fatalf("recovery result = %v, recovers=%d", got, provider.recovers)
	}
	recovered, err := ReadManifest(request.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.State != StateReady || recovered.Identity.Generation != 2 || recovered.Identity.IncarnationID != "incarnation-2" {
		t.Fatalf("recovered manifest = %+v", recovered)
	}
}

func TestControllerRecoverReturnsHealthyExactIncarnationWithoutProviderRecovery(t *testing.T) {
	request, provider, instance := readyFixture(t)
	controller := Controller{CleanupTimeout: time.Second}
	if _, err := controller.Start(context.Background(), provider, request); err != nil {
		t.Fatal(err)
	}
	manifest, err := ReadManifest(request.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := controller.Recover(ctx, provider, request.StateDir, manifest); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled healthy recovery error = %v", err)
	}
	if provider.recovers != 0 || instance.stops != 0 || instance.destroys != 0 {
		t.Fatalf("cancelled healthy recovery recovers=%d stops=%d destroys=%d", provider.recovers, instance.stops, instance.destroys)
	}

	got, err := controller.Recover(context.Background(), provider, request.StateDir, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if got != instance || provider.opens != 1 || provider.recovers != 0 || instance.stops != 0 || instance.destroys != 0 {
		t.Fatalf("healthy recovery opens=%d recovers=%d stops=%d destroys=%d", provider.opens, provider.recovers, instance.stops, instance.destroys)
	}
}

func TestControllerSerializesRecoveryAndRejectsStaleSecondRevision(t *testing.T) {
	request, provider, instance := readyFixture(t)
	controller := Controller{CleanupTimeout: time.Second}
	if _, err := controller.Start(context.Background(), provider, request); err != nil {
		t.Fatal(err)
	}
	manifest, err := ReadManifest(request.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	instance.status = Status{Identity: instance.identity, Endpoint: instance.endpoint, State: StateFailed, Recoverable: true}
	provider.openErr = errors.New("crashed")
	instance.identity.Generation++
	instance.identity.IncarnationID = "incarnation-2"
	instance.status = Status{Identity: instance.identity, Endpoint: instance.endpoint, State: StateReady, Ready: true, Recoverable: true}
	block := make(chan struct{})
	provider.recoverBlock = block
	firstDone := make(chan error, 1)
	go func() {
		_, recoverErr := controller.Recover(context.Background(), provider, request.StateDir, manifest)
		firstDone <- recoverErr
	}()
	deadline := time.Now().Add(time.Second)
	for {
		provider.mu.Lock()
		recovers := provider.recovers
		provider.mu.Unlock()
		if recovers == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first recovery did not reach provider")
		}
		time.Sleep(time.Millisecond)
	}
	secondDone := make(chan error, 1)
	go func() {
		_, recoverErr := controller.Recover(context.Background(), provider, request.StateDir, manifest)
		secondDone <- recoverErr
	}()
	close(block)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err == nil || !strings.Contains(err.Error(), "changed before recovery") {
		t.Fatalf("second recovery error = %v", err)
	}
	if instance.stops != 0 || instance.destroys != 0 {
		t.Fatalf("stale recovery cleaned replacement stops=%d destroys=%d", instance.stops, instance.destroys)
	}
}

func TestControllerRecoverRejectsGenerationIdentitySubstitution(t *testing.T) {
	request, provider, instance := readyFixture(t)
	controller := Controller{CleanupTimeout: time.Second}
	if _, err := controller.Start(context.Background(), provider, request); err != nil {
		t.Fatal(err)
	}
	manifest, err := ReadManifest(request.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	instance.identity.IncarnationID = "substituted-same-generation"
	instance.status.Identity = instance.identity
	_, err = controller.Recover(context.Background(), provider, request.StateDir, manifest)
	if err == nil || !strings.Contains(err.Error(), "changed an existing generation") {
		t.Fatalf("recovery substitution error = %v", err)
	}
	if instance.stops != 0 || instance.destroys != 0 {
		t.Fatalf("uncommitted substituted recovery was cleaned stops=%d destroys=%d", instance.stops, instance.destroys)
	}
}

func TestControllerStopCompletesAfterCallerCancellation(t *testing.T) {
	request, provider, instance := readyFixture(t)
	controller := Controller{CleanupTimeout: time.Second}
	if _, err := controller.Start(context.Background(), provider, request); err != nil {
		t.Fatal(err)
	}
	manifest, err := ReadManifest(request.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := controller.Stop(ctx, provider, request.StateDir, manifest, StopReasonUser); err != nil {
		t.Fatal(err)
	}
	if provider.opens != 1 || instance.stops != 1 || instance.destroys != 1 || instance.cleanupCanceled {
		t.Fatalf("stop opens=%d stops=%d destroys=%d cancelled=%t", provider.opens, instance.stops, instance.destroys, instance.cleanupCanceled)
	}
	stopped, err := ReadManifest(request.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if stopped.State != StateStopped || !stopped.CleanupComplete {
		t.Fatalf("stopped manifest = %+v", stopped)
	}
	if err := controller.Stop(context.Background(), provider, request.StateDir, stopped, StopReasonUser); err != nil {
		t.Fatal(err)
	}
	if instance.stops != 1 || instance.destroys != 1 {
		t.Fatalf("idempotent stop repeated cleanup")
	}
}

func TestControllerFailedStartedCleanupCommitsStoppingAndRejectsRecovery(t *testing.T) {
	request, provider, instance := readyFixture(t)
	provider.startErr = errors.New("provider start failed")
	instance.stopErr = errors.New("stop failed")
	instance.stopStarted = make(chan struct{})
	release := make(chan struct{})
	instance.stopRelease = release
	controller := Controller{CleanupTimeout: time.Second}
	done := make(chan error, 1)
	go func() {
		_, err := controller.Start(context.Background(), provider, request)
		done <- err
	}()
	<-instance.stopStarted
	manifest, err := ReadManifest(request.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.State != StateStopping || manifest.CleanupComplete || manifest.Identity != instance.identity || manifest.Endpoint != instance.endpoint {
		t.Fatalf("cleanup intent manifest=%+v", manifest)
	}
	recoveryManifest := manifest
	recoverDone := make(chan error, 1)
	go func() {
		_, recoverErr := controller.Recover(context.Background(), provider, request.StateDir, recoveryManifest)
		recoverDone <- recoverErr
	}()
	select {
	case err := <-recoverDone:
		t.Fatalf("recovery bypassed in-flight operation lock: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-done; err == nil || !strings.Contains(err.Error(), "provider start failed") || !strings.Contains(err.Error(), "stop failed") {
		t.Fatalf("Start error=%v", err)
	}
	manifest, err = ReadManifest(request.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.State != StateStopping || manifest.CleanupComplete {
		t.Fatalf("failed cleanup manifest=%+v", manifest)
	}
	if err := <-recoverDone; err == nil {
		t.Fatal("stale concurrent recovery unexpectedly succeeded")
	}
	if _, err := controller.Recover(context.Background(), provider, request.StateDir, manifest); err == nil || !strings.Contains(err.Error(), "cannot be recovered") {
		t.Fatalf("fresh Recover error=%v", err)
	}
	if provider.recovers != 0 {
		t.Fatalf("provider recovery calls=%d", provider.recovers)
	}
}

func TestControllerUnboundFailedCleanupCannotBeRecovered(t *testing.T) {
	request, provider, instance := readyFixture(t)
	provider.startErr = errors.New("provider start failed")
	instance.identity = Identity{ContractVersion: ContractVersion, Provider: NativeProvider, Profile: DefaultProfile, SessionID: "other", Generation: 1, IncarnationID: "other"}
	instance.stopErr = errors.New("stop failed")
	_, err := (Controller{CleanupTimeout: time.Second}).Start(context.Background(), provider, request)
	if err == nil {
		t.Fatal("mismatched failed start succeeded")
	}
	manifest, readErr := ReadManifest(request.StateDir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if manifest.State != StateFailed || manifest.CleanupComplete || manifest.Identity != (Identity{}) || manifest.Endpoint != (Endpoint{}) {
		t.Fatalf("unbound cleanup manifest=%+v", manifest)
	}
	opens, recovers := provider.opens, provider.recovers
	if _, err := (Controller{CleanupTimeout: time.Second}).Recover(context.Background(), provider, request.StateDir, manifest); err == nil || !strings.Contains(err.Error(), "incomplete or ambiguous cleanup") {
		t.Fatalf("Recover error=%v", err)
	}
	if provider.opens != opens || provider.recovers != recovers {
		t.Fatalf("provider called during refused recovery opens=%d recovers=%d", provider.opens, provider.recovers)
	}
}

func TestControllerRejectsLegacyAmbiguousFailedCleanup(t *testing.T) {
	request, provider, instance := readyFixture(t)
	manifest := NewManifest(request, time.Now().UTC())
	manifest.State = StateFailed
	manifest.Identity = instance.identity
	manifest.Endpoint = instance.endpoint
	manifest.CleanupComplete = false
	manifest.CleanupIntentKnown = false
	if err := WriteManifest(request.StateDir, manifest); err != nil {
		t.Fatal(err)
	}
	manifest, _ = ReadManifest(request.StateDir)
	if _, err := (Controller{CleanupTimeout: time.Second}).Recover(context.Background(), provider, request.StateDir, manifest); err == nil || !strings.Contains(err.Error(), "ambiguous cleanup") {
		t.Fatalf("Recover error=%v", err)
	}
	if provider.opens != 0 || provider.recovers != 0 {
		t.Fatalf("provider called opens=%d recovers=%d", provider.opens, provider.recovers)
	}
}

func TestControllerRecoverAllowsProviderReportedFailedRuntime(t *testing.T) {
	request, provider, instance := readyFixture(t)
	manifest := NewManifest(request, time.Now().UTC())
	manifest.State = StateFailed
	manifest.Identity = instance.identity
	manifest.Endpoint = instance.endpoint
	manifest.CleanupComplete = false
	manifest.LastError = "runtime crashed"
	if err := WriteManifest(request.StateDir, manifest); err != nil {
		t.Fatal(err)
	}
	manifest, _ = ReadManifest(request.StateDir)
	provider.openErr = errors.New("old incarnation unavailable")
	instance.identity.Generation = 2
	instance.identity.IncarnationID = "incarnation-2"
	instance.status = Status{Identity: instance.identity, Endpoint: instance.endpoint, State: StateReady, Ready: true, Recoverable: true}
	if _, err := (Controller{CleanupTimeout: time.Second}).Recover(context.Background(), provider, request.StateDir, manifest); err != nil {
		t.Fatal(err)
	}
	if provider.recovers != 1 {
		t.Fatalf("recover calls=%d", provider.recovers)
	}
}

func TestControllerFailedStopPreservesStopIntentAndRejectsRecovery(t *testing.T) {
	request, provider, instance := readyFixture(t)
	controller := Controller{CleanupTimeout: time.Second}
	if _, err := controller.Start(context.Background(), provider, request); err != nil {
		t.Fatal(err)
	}
	manifest, err := ReadManifest(request.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	instance.stopErr = errors.New("stop failed")
	if err := controller.Stop(context.Background(), provider, request.StateDir, manifest, StopReasonUser); err == nil {
		t.Fatal("failed stop unexpectedly succeeded")
	}
	stopping, err := ReadManifest(request.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if stopping.State != StateStopping || stopping.CleanupComplete {
		t.Fatalf("failed stop manifest = %+v", stopping)
	}
	if _, err := controller.Recover(context.Background(), provider, request.StateDir, stopping); err == nil || !strings.Contains(err.Error(), "cannot be recovered") {
		t.Fatalf("recover after failed stop error = %v", err)
	}
}

func TestManifestRejectsMismatchedStorageDirectory(t *testing.T) {
	request, _, _ := readyFixture(t)
	manifest := NewManifest(request, time.Now().UTC())
	other := filepath.Join(t.TempDir(), request.SessionID)
	if err := WriteManifest(other, manifest); err == nil || !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("mismatched manifest write error = %v", err)
	}
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ManifestPath(other), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(other); err == nil || !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("mismatched manifest read error = %v", err)
	}
}

func TestManifestRejectsUnknownFieldsAndUnsafePermissions(t *testing.T) {
	request, _, _ := readyFixture(t)
	manifest := NewManifest(request, time.Now().UTC())
	if err := WriteManifest(request.StateDir, manifest); err != nil {
		t.Fatal(err)
	}
	path := ManifestPath(request.StateDir)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "\n}", ",\n  \"unknown\": true\n}", 1))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(request.StateDir); err == nil || !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("unknown manifest field error = %v", err)
	}
	if err := WriteManifest(request.StateDir, manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(request.StateDir); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("unsafe manifest error = %v", err)
	}
}

func TestControlPlaneSnapshotValidatesProviderNeutralIdentity(t *testing.T) {
	request, _, instance := readyFixture(t)
	snapshot := ControlPlaneSnapshot{
		Metadata: detached.Metadata{
			SessionID: request.SessionID, Generation: instance.identity.Generation,
			IncarnationID: instance.identity.IncarnationID, SupervisorSock: instance.endpoint.Address,
		},
		Session:  types.Session{ID: request.SessionID},
		StateDir: request.StateDir,
		Status: detached.RuntimeStatus{
			SessionID: request.SessionID, Generation: instance.identity.Generation,
			IncarnationID: instance.identity.IncarnationID,
		},
	}
	if err := snapshot.Validate(instance.identity, instance.endpoint); err != nil {
		t.Fatal(err)
	}
	snapshot.Status.IncarnationID = "other"
	if err := snapshot.Validate(instance.identity, instance.endpoint); err == nil || !strings.Contains(err.Error(), "status identity") {
		t.Fatalf("mismatched control-plane status error = %v", err)
	}
}

func TestRegistryRejectsDuplicateAndUnknownProviders(t *testing.T) {
	provider := &fakeProvider{name: NativeProvider}
	if _, err := NewRegistry(provider, provider); err == nil {
		t.Fatal("duplicate runtime provider was accepted")
	}
	registry, err := NewRegistry(provider)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Resolve("microvm"); err == nil {
		t.Fatal("unknown runtime provider was resolved")
	}
}

func TestControllerStopCleansCrashReleasedUnprovisionedRuntime(t *testing.T) {
	request, provider, instance := readyFixture(t)
	if err := os.MkdirAll(request.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := NewManifest(request, time.Now().UTC())
	if err := WriteManifest(request.StateDir, manifest); err != nil {
		t.Fatal(err)
	}
	manifest, err := ReadManifest(request.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	instance.identity = Identity{
		ContractVersion: ContractVersion, Provider: request.Provider, Profile: request.Profile, SessionID: request.SessionID,
	}
	instance.status = Status{}
	controller := Controller{CleanupTimeout: time.Second}
	if err := controller.Stop(context.Background(), provider, request.StateDir, manifest, StopReasonStartupFailed); err != nil {
		t.Fatal(err)
	}
	cleaned, err := ReadManifest(request.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if cleaned.State != StateFailed || !cleaned.CleanupComplete || cleaned.CleanupPending || provider.opens != 1 || instance.stops != 1 || instance.destroys != 1 {
		t.Fatalf("unprovisioned cleanup manifest=%+v opens=%d stops=%d destroys=%d", cleaned, provider.opens, instance.stops, instance.destroys)
	}
	if err := controller.Stop(context.Background(), provider, request.StateDir, cleaned, StopReasonStartupFailed); err != nil {
		t.Fatal(err)
	}
	if instance.stops != 1 || instance.destroys != 1 {
		t.Fatal("completed unprovisioned cleanup repeated provider teardown")
	}
}

func readyFixture(t *testing.T) (Request, *fakeProvider, *fakeInstance) {
	t.Helper()
	stateDir := filepath.Join(t.TempDir(), "session-test")
	workspace := t.TempDir()
	request := Request{
		SessionID: "session-test", Provider: NativeProvider, Profile: DefaultProfile,
		StateDir: stateDir,
		Session:  types.CreateSessionRequest{ID: "session-test", Workspace: workspace},
	}
	identity := Identity{
		ContractVersion: ContractVersion, Provider: NativeProvider, Profile: DefaultProfile,
		SessionID: request.SessionID, Generation: 1, IncarnationID: "incarnation-1",
		OwnerPID: 101, OwnerStartIdentity: "start-1", BootID: "boot-1",
	}
	endpoint := Endpoint{Transport: "unix", Address: filepath.Join(stateDir, "supervisor.sock")}
	instance := &fakeInstance{
		identity: identity,
		endpoint: endpoint,
		status:   Status{Identity: identity, Endpoint: endpoint, State: StateReady, Ready: true, Recoverable: true},
	}
	provider := &fakeProvider{
		name:         NativeProvider,
		capabilities: Capabilities{ContractVersion: ContractVersion, Provider: NativeProvider, Recoverable: true, Transports: []string{"unix"}},
		instance:     instance,
	}
	return request, provider, instance
}
