//go:build linux

package externalrunner

import (
	"context"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/guestcontrol"
)

type lifecycleTestEgressBroker struct {
	closed   atomic.Bool
	calls    atomic.Int32
	done     chan struct{}
	doneOnce sync.Once
	err      error
	onClose  func()
}

func (b *lifecycleTestEgressBroker) Done() <-chan struct{} { return b.done }
func (b *lifecycleTestEgressBroker) Err() error            { return b.err }
func (b *lifecycleTestEgressBroker) Close() error {
	b.calls.Add(1)
	if b.onClose != nil {
		b.onClose()
	}
	b.closed.Store(true)
	b.doneOnce.Do(func() { close(b.done) })
	return b.err
}

func TestHostMonitorV3RequestAndManifestBindDistinctPerCIDPorts(t *testing.T) {
	_, request, profile, manifest := prepareV3HostMonitorFixture(t)
	if request.EgressPort != request.CIDLease.CID || manifest.EgressPort != request.EgressPort {
		t.Fatalf("CID=%d request port=%d manifest port=%d", request.CIDLease.CID, request.EgressPort, manifest.EgressPort)
	}
	nextCID := request.CIDLease.CID + 1
	if nextCID > profile.VSock.CIDMax {
		nextCID = request.CIDLease.CID - 1
	}
	nextPort, err := deriveHostEgressPort(profile, nextCID)
	if err != nil {
		t.Fatal(err)
	}
	if nextPort == request.EgressPort {
		t.Fatalf("parallel CIDs %d and %d collide on port %d", request.CIDLease.CID, nextCID, nextPort)
	}
	drifted := request
	drifted.EgressPort = nextPort
	if err := validateHostMonitorProfileBinding(drifted, profile, request.ProfileFileSHA256); err == nil {
		t.Fatal("host request accepted an egress port derived from a different CID")
	}
}

func TestHostMonitorV3StartsBrokerBeforeRunnerAndStopsItWithLifecycle(t *testing.T) {
	stateDir, request, profile, manifest := prepareV3HostMonitorFixture(t)
	start, boot, err := detached.CurrentProcessIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeHostRunner{
		identity: HostProcessIdentity{PID: os.Getpid(), ProcessGroup: os.Getpid(), StartIdentity: start, BootID: boot},
		done:     make(chan hostRunnerResult, 1), waitDone: make(chan struct{}),
	}
	broker := &lifecycleTestEgressBroker{done: make(chan struct{})}
	var brokerStarted atomic.Bool
	handshake := testHostHandshake(manifest)
	control := &fakeHostControl{handshake: handshake, runner: runner}
	control.onHello = func(requireNetwork bool) {
		if requireNetwork {
			t.Error("v3 readiness requested the legacy direct-network enforcement claim")
		}
	}
	broker.onClose = func() {
		status, statusErr := ReadHostMonitorStatus(stateDir)
		if statusErr != nil || status.State != HostMonitorStopping || status.EgressBrokerClosed {
			t.Errorf("broker closed before durable open-broker stopping evidence: %+v, %v", status, statusErr)
		}
	}
	control.onShutdown = func() {
		if !broker.closed.Load() {
			t.Error("guest shutdown began before the host egress broker closed")
		}
	}
	var openedVolume *WorkspaceVolume
	deps := hostMonitorDeps{
		newControl: func(got guestcontrol.Manifest) (hostMonitorControl, error) {
			if got != manifest {
				t.Fatal("monitor control manifest changed")
			}
			return control, nil
		},
		newRelay: func(path string, got hostMonitorControl) (hostMonitorRelay, error) {
			if got != control {
				t.Fatal("relay received a different authenticated control client")
			}
			return &fakeHostRelay{path: path}, nil
		},
		createVolume: func(_ context.Context, got WorkspaceVolumeRequest, volumeID string) (*WorkspaceVolume, error) {
			openedVolume = testOpenedHostMonitorVolume(t, got, volumeID, nil)
			return openedVolume, nil
		},
		startEgressBroker: func(_ context.Context, got Profile, layout HostMonitorLayout, sessionID string, cid, port uint32, token string) (hostEgressBroker, error) {
			status, statusErr := ReadHostMonitorStatus(stateDir)
			if statusErr != nil || status.State != HostMonitorInitializing || !status.EgressBrokerClosed {
				t.Fatalf("broker startup preceded durable initializing evidence: %+v, %v", status, statusErr)
			}
			if got.Schema != ProfileSchemaV3 || got.HostEgress == nil || *got.HostEgress != *profile.HostEgress || layout.NetworkAudit == "" || sessionID != request.SessionID || cid != request.CIDLease.CID || port != request.EgressPort || token != manifest.EgressToken {
				t.Fatal("broker startup identity changed")
			}
			brokerStarted.Store(true)
			return broker, nil
		},
		startRunner: func(got Profile, _ HostMonitorLayout, cid uint32, volume *WorkspaceVolume, _ io.Writer) (hostRunner, error) {
			if !brokerStarted.Load() || broker.closed.Load() {
				t.Fatal("runner started without the exact live egress broker")
			}
			if got.Schema != ProfileSchemaV3 || cid != request.CIDLease.CID || volume != openedVolume {
				t.Fatal("v3 runner binding changed")
			}
			return runner, nil
		},
		validateRunner: func(Profile) error { return nil },
		lock:           func(context.Context, string) (io.Closer, error) { return nopCloser{}, nil },
		now:            func() time.Time { return time.Now().UTC() },
	}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- runHostMonitor(ctx, stateDir, deps) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		status, readErr := ReadHostMonitorStatus(stateDir)
		if readErr == nil && status.State == HostMonitorControlReady {
			if status.SchemaVersion != HostMonitorSchemaVersionV3 || status.EgressBrokerClosed || status.Guest == nil || status.Guest.EgressPort != request.EgressPort || !status.Guest.EgressReady || status.Guest.NetworkReady {
				t.Fatalf("v3 control-ready status = %+v", status)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("v3 monitor did not become ready: %v", readErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("v3 monitor stop: %v", err)
	}
	status, err := ReadHostMonitorStatus(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != HostMonitorStopped || !status.EgressBrokerClosed || !status.VolumeClosed || !status.RunnerReaped || !status.RelayClosed {
		t.Fatalf("v3 terminal status = %+v", status)
	}
	if broker.calls.Load() != 1 {
		t.Fatalf("broker Close calls = %d, want 1", broker.calls.Load())
	}
}
