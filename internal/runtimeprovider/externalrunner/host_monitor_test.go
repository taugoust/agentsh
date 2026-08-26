//go:build linux

package externalrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/guestcontrol"
)

type fakeHostRunner struct {
	identity        HostProcessIdentity
	done            chan hostRunnerResult
	waitDone        chan struct{}
	result          hostRunnerResult
	once            sync.Once
	ensureOnce      sync.Once
	onEnsureStopped func()
}

func (r *fakeHostRunner) Identity() HostProcessIdentity { return r.identity }
func (r *fakeHostRunner) Done() <-chan hostRunnerResult { return r.done }
func (r *fakeHostRunner) stop(result hostRunnerResult) {
	r.once.Do(func() {
		r.result = result
		close(r.waitDone)
		r.done <- result
	})
}
func (r *fakeHostRunner) ForceStop() error {
	r.stop(hostRunnerResult{Exit: HostRunnerExit{ExitCode: -1, Signaled: true}, Err: errors.New("forced")})
	return nil
}
func (r *fakeHostRunner) EnsureStopped(ctx context.Context) (*hostRunnerResult, error) {
	select {
	case <-r.waitDone:
		r.ensureOnce.Do(func() {
			if r.onEnsureStopped != nil {
				r.onEnsureStopped()
			}
		})
		result := r.result
		return &result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type partialStartupHostRunner struct {
	forceOnce           sync.Once
	forceFailures       int32
	forceCalls          atomic.Int32
	ensureBeforeCleanup atomic.Bool
	forced              chan struct{}
	reap                chan struct{}
	done                chan hostRunnerResult
	reaped              atomic.Bool
}

func newPartialStartupHostRunner() *partialStartupHostRunner {
	return &partialStartupHostRunner{
		forced: make(chan struct{}), reap: make(chan struct{}), done: make(chan hostRunnerResult),
	}
}

func (r *partialStartupHostRunner) Identity() HostProcessIdentity { return HostProcessIdentity{} }
func (r *partialStartupHostRunner) Done() <-chan hostRunnerResult { return r.done }
func (r *partialStartupHostRunner) ForceStop() error {
	if r.forceCalls.Add(1) <= r.forceFailures {
		return errors.New("injected exact process-group cleanup failure")
	}
	r.forceOnce.Do(func() { close(r.forced) })
	return nil
}
func (r *partialStartupHostRunner) EnsureStopped(ctx context.Context) (*hostRunnerResult, error) {
	select {
	case <-r.forced:
	default:
		r.ensureBeforeCleanup.Store(true)
		return nil, errors.New("reap attempted before exact process-group cleanup")
	}
	select {
	case <-r.reap:
		r.reaped.Store(true)
		return &hostRunnerResult{Exit: HostRunnerExit{ExitCode: -1, Signaled: true}}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type fakeHostControl struct {
	handshake guestcontrol.Handshake
	runner    *fakeHostRunner
	helloErr  error
}

func (c *fakeHostControl) Hello(context.Context, bool) (guestcontrol.Handshake, error) {
	return c.handshake, c.helloErr
}
func (c *fakeHostControl) Shutdown(context.Context) error {
	c.runner.stop(hostRunnerResult{Exit: HostRunnerExit{ExitCode: 0}})
	return nil
}

type fakeHostRelay struct {
	path string
}

func (r *fakeHostRelay) Path() string { return r.path }
func (r *fakeHostRelay) Serve(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
func (r *fakeHostRelay) Close() error { return nil }

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

type hostMonitorTestCloser func() error

func (f hostMonitorTestCloser) Close() error { return f() }

func testOpenedHostMonitorVolume(t *testing.T, request WorkspaceVolumeRequest, volumeID string, onClose func()) *WorkspaceVolume {
	t.Helper()
	imagePath := filepath.Join(t.TempDir(), WorkspaceVolumeImageName)
	image, err := os.OpenFile(imagePath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	manifest := newWorkspaceVolumeCreateIntent(request, volumeID, time.Now().UTC()).manifest(WorkspaceVolumeImageIdentity{
		FileName: WorkspaceVolumeImageName, Inode: 1, HeaderSHA256: digest([]byte("host-monitor-test-header")),
	})
	return &WorkspaceVolume{
		Manifest: manifest,
		Image:    image,
		lock: hostMonitorTestCloser(func() error {
			if onClose != nil {
				onClose()
			}
			return nil
		}),
	}
}

func TestLinuxHostRunnerUsesExactGroupAndBoundedForce(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	layout := HostMonitorLayout{RuntimeDir: root, WorkspaceDir: filepath.Join(root, "workspace")}
	if err := os.Mkdir(layout.WorkspaceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	scriptData := []byte("#!" + shell + "\nprintf '%s\\n' \"$PI_AGENT_MICROVM_VSOCK_CID\" > workspace/cid\nwhile :; do :; done\n")
	script := filepath.Join(root, "runner")
	if err := os.WriteFile(script, scriptData, 0o555); err != nil {
		t.Fatal(err)
	}
	profile := testProfile(t)
	profile.Runner = Runner{Path: script, SHA256: digest(scriptData), ProcessModel: "direct-exec"}
	var output bytes.Buffer
	runner, err := startHostRunner(profile, layout, 41123, nil, &output)
	if err != nil {
		t.Fatal(err)
	}
	if runner.Identity().PID != runner.Identity().ProcessGroup {
		t.Fatalf("runner identity = %+v", runner.Identity())
	}
	deadline := time.Now().Add(time.Second)
	for {
		data, readErr := os.ReadFile(filepath.Join(layout.WorkspaceDir, "cid"))
		if readErr == nil && string(data) == "41123\n" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("runner did not receive fixed CID environment: %v", readErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := runner.ForceStop(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := runner.EnsureStopped(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Exit.Signaled {
		t.Fatalf("forced runner result = %+v", result)
	}
}

func TestPartialLinuxHostRunnerDefersWaitUntilExactGroupCleanupAndBecomesIdempotent(t *testing.T) {
	cmd := &exec.Cmd{Process: &os.Process{Pid: 4242}}
	runner := newPartialLinuxHostRunner(cmd, 99, 4242)
	var signalCalls atomic.Int32
	var groupCalls atomic.Int32
	var waitCalls atomic.Int32
	var closeCalls atomic.Int32
	runner.signalLeader = func() error {
		signalCalls.Add(1)
		return nil
	}
	runner.killExactProcessGroup = func() error {
		if groupCalls.Add(1) == 1 {
			return syscall.EPERM
		}
		return nil
	}
	runner.waitCommand = func() (*hostRunnerResult, error) {
		waitCalls.Add(1)
		return &hostRunnerResult{Exit: HostRunnerExit{ExitCode: -1, Signaled: true}}, nil
	}
	runner.closePIDFD = func() error {
		closeCalls.Add(1)
		return nil
	}

	_ = runner.Done()
	if waitCalls.Load() != 0 {
		t.Fatal("observing partial runner completion started cmd.Wait")
	}
	if err := runner.ForceStop(); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("first exact process-group kill error = %v", err)
	}
	if result, err := runner.EnsureStopped(context.Background()); err == nil || result != nil {
		t.Fatalf("partial runner reaped before exact group cleanup: result=%+v err=%v", result, err)
	}
	if waitCalls.Load() != 0 || closeCalls.Load() != 0 {
		t.Fatalf("failed group cleanup waited or closed pidfd: wait=%d close=%d", waitCalls.Load(), closeCalls.Load())
	}

	if err := runner.ForceStop(); err != nil {
		t.Fatalf("second exact process-group kill: %v", err)
	}
	result, err := runner.EnsureStopped(context.Background())
	if err != nil || result == nil || result.Exit.ExitCode != -1 || !result.Exit.Signaled {
		t.Fatalf("exact partial-runner reap = %+v, %v", result, err)
	}
	if err := runner.ForceStop(); err != nil {
		t.Fatalf("idempotent force after reap: %v", err)
	}
	again, err := runner.EnsureStopped(context.Background())
	if err != nil || again == nil || again.Exit != result.Exit {
		t.Fatalf("idempotent exact reap = %+v, %v", again, err)
	}
	if signalCalls.Load() != 2 || groupCalls.Load() != 2 || waitCalls.Load() != 1 || closeCalls.Load() != 1 {
		t.Fatalf("partial runner calls: signal=%d group=%d wait=%d close=%d", signalCalls.Load(), groupCalls.Load(), waitCalls.Load(), closeCalls.Load())
	}
}

func TestLinuxHostRunnerV2InheritsExactImageAsFD4WithFixedEnvironment(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	resultPath := filepath.Join(root, "result")
	volumeFDPath := filepath.Join(string(filepath.Separator), "proc", "self", "fd", "4")
	scriptData := []byte("#!" + shell + "\nIFS= read -r marker < " + volumeFDPath + "\nprintf '%s|%s|%s\\n' \"$marker\" \"$PI_AGENT_MICROVM_VSOCK_CID\" \"${HOME-unset}\" > result\nwhile :; do :; done\n")
	script := filepath.Join(root, "runner")
	if err := os.WriteFile(script, scriptData, 0o555); err != nil {
		t.Fatal(err)
	}
	imagePath := filepath.Join(t.TempDir(), "opaque-volume-image")
	if err := os.WriteFile(imagePath, []byte("exact-volume\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	image, err := os.OpenFile(imagePath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	info, err := image.Stat()
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("workspace image lacks Linux file identity")
	}
	profile := testProviderV2Profile(t)
	profile.Runner = Runner{Path: script, SHA256: digest(scriptData), ProcessModel: "direct-exec"}
	volume := &WorkspaceVolume{
		Manifest: WorkspaceVolumeManifest{
			WorkspaceVolume: *profile.WorkspaceVolume,
			Image: WorkspaceVolumeImageIdentity{
				FileName: WorkspaceVolumeImageName, Device: uint64(stat.Dev), Inode: stat.Ino,
			},
		},
		Image: image,
		lock:  nopCloser{},
	}
	if got := fixedHostRunnerEnvironment(41124); len(got) != 1 || got[0] != "PI_AGENT_MICROVM_VSOCK_CID=41124" || strings.Contains(strings.Join(got, "\n"), imagePath) {
		t.Fatalf("fixed runner environment = %#v", got)
	}
	var output bytes.Buffer
	runner, err := startHostRunner(profile, HostMonitorLayout{RuntimeDir: root}, 41124, volume, &output)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		data, readErr := os.ReadFile(resultPath)
		if readErr == nil && string(data) == "exact-volume|41124|unset\n" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("v2 runner did not receive exact fd 4 and allowlisted environment: data=%q err=%v output=%q", data, readErr, output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := runner.ForceStop(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := runner.EnsureStopped(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := volume.Image.Stat(); err != nil {
		t.Fatalf("runner reaping closed monitor-owned volume: %v", err)
	}
	if err := volume.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHostMonitorPublishesOnlyAfterAuthenticationAndStopsExactly(t *testing.T) {
	stateDir, request, profile, manifest := prepareHostMonitorFixture(t)
	start, boot, err := detached.CurrentProcessIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeHostRunner{
		identity: HostProcessIdentity{PID: os.Getpid(), ProcessGroup: os.Getpid(), StartIdentity: start, BootID: boot},
		done:     make(chan hostRunnerResult, 1),
		waitDone: make(chan struct{}),
	}
	control := &fakeHostControl{handshake: testHostHandshake(manifest), runner: runner}
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
		createVolume: func(context.Context, WorkspaceVolumeRequest, string) (*WorkspaceVolume, error) {
			t.Fatal("v1 monitor attempted to create a workspace volume")
			return nil, nil
		},
		startRunner: func(got Profile, layout HostMonitorLayout, cid uint32, volume *WorkspaceVolume, output io.Writer) (hostRunner, error) {
			if volume != nil {
				t.Fatal("v1 runner received a workspace volume")
			}
			if got.Name != profile.Name || cid != request.CIDLease.CID || layout.StateDir != stateDir {
				t.Fatal("runner launch identity changed")
			}
			_, _ = output.Write([]byte("runner output"))
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
			if status.Guest == nil || status.Endpoint == nil || status.Endpoint.Address == "" {
				t.Fatal("control-ready status omitted authenticated guest endpoint")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("monitor did not become control ready: %v", readErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("monitor stop: %v", err)
	}
	status, err := ReadHostMonitorStatus(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != HostMonitorStopped || !status.StopRequested || !status.RunnerReaped || !status.RelayClosed || status.RunnerExit.ExitCode != 0 {
		t.Fatalf("terminal status = %+v", status)
	}
	data, err := os.ReadFile(filepath.Join(stateDir, "runtime", "host", HostMonitorStatusName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), manifest.ControlToken) || strings.Contains(string(data), manifest.SupervisorToken) {
		t.Fatal("host monitor status leaked a guest credential")
	}
	if strings.Contains(string(data), "volume_id") || strings.Contains(string(data), "volume_closed") || strings.Contains(string(data), "startup_child_reaped") {
		t.Fatal("v1 host monitor status protocol gained schema-v2 fields")
	}
	if err := VerifyCIDLease(context.Background(), request.CIDLeaseRoot, request.CIDLease, profile.VSock.CIDMin, profile.VSock.CIDMax); err != nil {
		t.Fatalf("monitor incorrectly released provider-owned CID lease: %v", err)
	}
}

func TestHostMonitorV2CreatesOrReopensExactVolumeAfterDurableRequestAndClosesOnlyAfterRunnerReaping(t *testing.T) {
	stateDir, request, profile, manifest := prepareV2HostMonitorFixture(t)
	start, boot, err := detached.CurrentProcessIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	var runnerReaped atomic.Bool
	var volumeClosed atomic.Bool
	var volumeClosedEarly atomic.Bool
	runner := &fakeHostRunner{
		identity: HostProcessIdentity{PID: os.Getpid(), ProcessGroup: os.Getpid(), StartIdentity: start, BootID: boot},
		done:     make(chan hostRunnerResult, 1), waitDone: make(chan struct{}),
		onEnsureStopped: func() { runnerReaped.Store(true) },
	}
	control := &fakeHostControl{handshake: testHostHandshake(manifest), runner: runner}
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
			durableRequest, requestErr := ReadHostMonitorRequest(stateDir)
			durableStatus, statusErr := ReadHostMonitorStatus(stateDir)
			if requestErr != nil || statusErr != nil || durableRequest.MonitorID != request.MonitorID || durableRequest.VolumeID != request.VolumeID ||
				durableRequest.SchemaVersion != HostMonitorSchemaVersionV2 || durableRequest.WorkspaceVolume == nil || *durableRequest.WorkspaceVolume != *request.WorkspaceVolume ||
				durableStatus.SchemaVersion != HostMonitorSchemaVersionV2 || durableStatus.State != HostMonitorInitializing {
				t.Fatalf("volume creation preceded durable v2 monitor evidence: request=%+v (%v), status=%+v (%v)", durableRequest, requestErr, durableStatus, statusErr)
			}
			if volumeID != request.VolumeID || got.StateDir != stateDir || got.SessionID != request.SessionID ||
				got.Profile.Schema != ProfileSchemaV2 || got.Profile.Name != profile.Name || got.ProfileFileSHA256 != request.ProfileFileSHA256 {
				t.Fatalf("monitor volume create = %#v, id %q", got, volumeID)
			}
			openedVolume = testOpenedHostMonitorVolume(t, got, volumeID, func() {
				if !runnerReaped.Load() {
					volumeClosedEarly.Store(true)
				}
				volumeClosed.Store(true)
			})
			return openedVolume, nil
		},
		startRunner: func(got Profile, layout HostMonitorLayout, cid uint32, volume *WorkspaceVolume, _ io.Writer) (hostRunner, error) {
			if got.Schema != ProfileSchemaV2 || layout.StateDir != stateDir || cid != request.CIDLease.CID || volume != openedVolume || volumeClosed.Load() {
				t.Fatal("runner did not receive the exact open v2 workspace volume")
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
			if status.VolumeID != request.VolumeID || status.VolumeClosed {
				t.Fatalf("live v2 volume status = %+v", status)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("v2 monitor did not become control ready: %v", readErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("v2 monitor stop: %v", err)
	}
	status, err := ReadHostMonitorStatus(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != HostMonitorStopped || status.VolumeID != request.VolumeID || !status.VolumeClosed ||
		!status.RunnerReaped || !status.RelayClosed || !volumeClosed.Load() || volumeClosedEarly.Load() {
		t.Fatalf("terminal v2 status = %+v, reaped=%t closed=%t closed_early=%t", status, runnerReaped.Load(), volumeClosed.Load(), volumeClosedEarly.Load())
	}
	if !exactHostMonitorStatusTerminal(status, status.Monitor) {
		t.Fatal("complete v2 teardown evidence was not terminal")
	}
}

func TestHostMonitorV2PreLaunchFailureClosesButDoesNotDeleteVolumeAndIsTerminal(t *testing.T) {
	stateDir, request, _, _ := prepareV2HostMonitorFixture(t)
	var volumeClosed atomic.Bool
	var retainedPath string
	deps := hostMonitorDeps{
		createVolume: func(_ context.Context, got WorkspaceVolumeRequest, volumeID string) (*WorkspaceVolume, error) {
			volume := testOpenedHostMonitorVolume(t, got, volumeID, func() { volumeClosed.Store(true) })
			retainedPath = volume.Image.Name()
			return volume, nil
		},
		startRunner: func(Profile, HostMonitorLayout, uint32, *WorkspaceVolume, io.Writer) (hostRunner, error) {
			return nil, errors.New("injected runner startup failure")
		},
		validateRunner: func(Profile) error { return nil },
		lock:           func(context.Context, string) (io.Closer, error) { return nopCloser{}, nil },
		now:            func() time.Time { return time.Now().UTC() },
	}
	if err := runHostMonitor(context.Background(), stateDir, deps); err == nil {
		t.Fatal("injected v2 startup failure succeeded")
	}
	status, err := ReadHostMonitorStatus(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if status.SchemaVersion != HostMonitorSchemaVersionV2 || status.State != HostMonitorFailed || status.Runner != nil || status.StartupChildReaped ||
		status.RunnerExit != nil || status.RunnerReaped || status.VolumeID != request.VolumeID || !status.VolumeClosed || !volumeClosed.Load() {
		t.Fatalf("v2 no-child startup-failure status = %+v, closed=%t", status, volumeClosed.Load())
	}
	if !exactHostMonitorStatusTerminal(status, status.Monitor) {
		t.Fatal("fully cleaned v2 pre-launch failure was not terminal")
	}
	if _, err := os.Lstat(retainedPath); err != nil {
		t.Fatalf("v2 startup failure deleted retained volume image: %v", err)
	}
}

func TestHostMonitorV2PartialStartupRetainsLeaseUntilExactReap(t *testing.T) {
	stateDir, request, _, _ := prepareV2HostMonitorFixture(t)
	partial := newPartialStartupHostRunner()
	partial.forceFailures = 1
	var volumeClosed atomic.Bool
	var volumeClosedEarly atomic.Bool
	deps := hostMonitorDeps{
		createVolume: func(_ context.Context, got WorkspaceVolumeRequest, volumeID string) (*WorkspaceVolume, error) {
			return testOpenedHostMonitorVolume(t, got, volumeID, func() {
				if !partial.reaped.Load() {
					volumeClosedEarly.Store(true)
				}
				volumeClosed.Store(true)
			}), nil
		},
		startRunner: func(Profile, HostMonitorLayout, uint32, *WorkspaceVolume, io.Writer) (hostRunner, error) {
			return partial, errors.New("injected partial runner startup")
		},
		validateRunner: func(Profile) error { return nil },
		lock:           func(context.Context, string) (io.Closer, error) { return nopCloser{}, nil },
		now:            func() time.Time { return time.Now().UTC() },
	}
	result := make(chan error, 1)
	go func() { result <- runHostMonitor(context.Background(), stateDir, deps) }()
	select {
	case <-partial.forced:
	case <-time.After(3 * time.Second):
		t.Fatal("partial runner was not force-stopped")
	}
	status, err := ReadHostMonitorStatus(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != HostMonitorInitializing || status.StartupChildReaped || status.RunnerExit != nil || status.RunnerReaped ||
		status.VolumeClosed || volumeClosed.Load() || exactHostMonitorStatusTerminal(status, status.Monitor) {
		t.Fatalf("partial startup published reap evidence, terminal state, or released volume early: status=%+v closed=%t", status, volumeClosed.Load())
	}
	close(partial.reap)
	if err := <-result; err == nil {
		t.Fatal("partial startup failure unexpectedly succeeded")
	}
	status, err = ReadHostMonitorStatus(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != HostMonitorFailed || status.Runner != nil || !status.StartupChildReaped || status.RunnerExit == nil ||
		status.RunnerExit.ExitCode != -1 || !status.RunnerExit.Signaled || status.RunnerReaped || status.VolumeID != request.VolumeID || !status.VolumeClosed ||
		!volumeClosed.Load() || volumeClosedEarly.Load() || partial.ensureBeforeCleanup.Load() || partial.forceCalls.Load() != 2 ||
		!exactHostMonitorStatusTerminal(status, status.Monitor) {
		t.Fatalf("partial startup cleanup status=%+v closed=%t early=%t force_calls=%d ensure_early=%t", status, volumeClosed.Load(), volumeClosedEarly.Load(), partial.forceCalls.Load(), partial.ensureBeforeCleanup.Load())
	}
}

func TestHostMonitorAuthenticationFailureNeverPublishesEndpoint(t *testing.T) {
	stateDir, _, _, manifest := prepareHostMonitorFixture(t)
	start, boot, err := detached.CurrentProcessIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeHostRunner{
		identity: HostProcessIdentity{PID: os.Getpid(), ProcessGroup: os.Getpid(), StartIdentity: start, BootID: boot},
		done:     make(chan hostRunnerResult, 1),
		waitDone: make(chan struct{}),
	}
	runner.stop(hostRunnerResult{Exit: HostRunnerExit{ExitCode: 1}, Err: errors.New("boot failed")})
	relayCalled := false
	deps := hostMonitorDeps{
		newControl: func(guestcontrol.Manifest) (hostMonitorControl, error) {
			return &fakeHostControl{handshake: testHostHandshake(manifest), runner: runner, helloErr: errors.New("authentication failed " + manifest.ControlToken)}, nil
		},
		newRelay: func(string, hostMonitorControl) (hostMonitorRelay, error) {
			relayCalled = true
			return nil, errors.New("must not publish")
		},
		createVolume: func(context.Context, WorkspaceVolumeRequest, string) (*WorkspaceVolume, error) {
			t.Fatal("v1 monitor attempted to create a workspace volume")
			return nil, nil
		},
		startRunner: func(Profile, HostMonitorLayout, uint32, *WorkspaceVolume, io.Writer) (hostRunner, error) {
			return runner, nil
		},
		validateRunner: func(Profile) error { return nil },
		lock:           func(context.Context, string) (io.Closer, error) { return nopCloser{}, nil },
		now:            func() time.Time { return time.Now().UTC() },
	}
	if err := runHostMonitor(context.Background(), stateDir, deps); err == nil {
		t.Fatal("unauthenticated guest monitor succeeded")
	}
	if relayCalled {
		t.Fatal("monitor published a relay before authenticated readiness")
	}
	status, err := ReadHostMonitorStatus(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != HostMonitorFailed || status.Endpoint != nil || !status.RunnerReaped || strings.Contains(status.LastError, manifest.ControlToken) {
		t.Fatalf("failed status = %+v", status)
	}
}

func TestHostMonitorV1JSONKeepsSchemaV2FieldsUnknown(t *testing.T) {
	_, request, _, _ := prepareHostMonitorFixture(t)
	start, boot, err := detached.CurrentProcessIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	status := HostMonitorStatus{
		SchemaVersion: HostMonitorSchemaVersionV1, Revision: 1,
		MonitorID: request.MonitorID, SessionID: request.SessionID,
		Profile: request.ProfileName, ExternalProfileDigest: request.ProfileDigest, GuestProfileDigest: request.GuestProfileDigest,
		State: HostMonitorInitializing, CreatedAt: now, UpdatedAt: now,
		Monitor: HostProcessIdentity{PID: os.Getpid(), StartIdentity: start, BootID: boot}, RelayClosed: true,
	}
	tests := []struct {
		name      string
		fixture   any
		field     string
		isRequest bool
	}{
		{name: "request-volume", fixture: request, field: "volume_id", isRequest: true},
		{name: "status-volume", fixture: status, field: "volume_closed"},
		{name: "status-startup-child", fixture: status, field: "startup_child_reaped"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := json.Marshal(test.fixture)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			fields[test.field] = json.RawMessage("null")
			data, err = json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			var decodeErr error
			if test.isRequest {
				var decoded HostMonitorRequest
				decodeErr = json.Unmarshal(data, &decoded)
			} else {
				var decoded HostMonitorStatus
				decodeErr = json.Unmarshal(data, &decoded)
			}
			if decodeErr == nil || !strings.Contains(decodeErr.Error(), "unknown field") {
				t.Fatalf("schema-v1 fixture accepted %s: %v", test.field, decodeErr)
			}
		})
	}
}

func TestHostMonitorV2StartupChildReapEvidenceValidation(t *testing.T) {
	start, boot, err := detached.CurrentProcessIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	base := func() HostMonitorStatus {
		now := time.Now().UTC()
		return HostMonitorStatus{
			SchemaVersion: HostMonitorSchemaVersionV2, Revision: 1,
			MonitorID: strings.Repeat("4", 64), SessionID: "session-11111111-1111-4111-8111-111111111111",
			VolumeID: "22222222-2222-4222-8222-222222222222",
			State:    HostMonitorFailed, CreatedAt: now, UpdatedAt: now,
			Monitor:      HostProcessIdentity{PID: os.Getpid(), StartIdentity: start, BootID: boot},
			RelayClosed:  true,
			VolumeClosed: true,
		}
	}
	noChild := base()
	startupChild := base()
	startupChild.StartupChildReaped = true
	startupChild.RunnerExit = &HostRunnerExit{ExitCode: -1, Signaled: true}
	missingExit := base()
	missingExit.StartupChildReaped = true
	exitWithoutMarker := base()
	exitWithoutMarker.RunnerExit = &HostRunnerExit{ExitCode: -1, Signaled: true}
	runnerReapedWithoutIdentity := startupChild
	runnerReapedWithoutIdentity.RunnerReaped = true
	markerWithRunner := startupChild
	markerWithRunner.Runner = &HostProcessIdentity{PID: 123, ProcessGroup: 123, StartIdentity: "runner-start", BootID: boot}
	markerOutsideFailure := startupChild
	markerOutsideFailure.State = HostMonitorInitializing
	markerOutsideFailure.VolumeClosed = false
	v1Marker := startupChild
	v1Marker.SchemaVersion = HostMonitorSchemaVersionV1
	v1Marker.VolumeID = ""
	v1Marker.VolumeClosed = false

	for name, test := range map[string]struct {
		status HostMonitorStatus
		valid  bool
	}{
		"true-no-child":                  {status: noChild, valid: true},
		"exact-startup-child-reap":       {status: startupChild, valid: true},
		"startup-child-without-exit":     {status: missingExit},
		"exit-without-startup-marker":    {status: exitWithoutMarker},
		"runner-reaped-without-identity": {status: runnerReapedWithoutIdentity},
		"startup-marker-with-runner":     {status: markerWithRunner},
		"startup-marker-outside-failure": {status: markerOutsideFailure},
		"schema-v1-startup-marker":       {status: v1Marker},
	} {
		t.Run(name, func(t *testing.T) {
			err := test.status.Validate()
			if test.valid && err != nil {
				t.Fatalf("valid status rejected: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("inconsistent startup-child evidence was accepted")
			}
		})
	}
}

func TestHostMonitorRequestIsExclusiveAndStrict(t *testing.T) {
	stateDir, request, _, _ := prepareHostMonitorFixture(t)
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(`"volume_id"`)) {
		t.Fatal("v1 host monitor request protocol gained a v2 volume field")
	}
	if err := WriteHostMonitorRequest(stateDir, request); !errors.Is(err, os.ErrExist) {
		t.Fatalf("duplicate immutable request error = %v", err)
	}
	path := filepath.Join(stateDir, "runtime", "host", HostMonitorRequestName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-2] = ','
	data = append(data[:len(data)-1], []byte("\n  \"unknown\": true\n}\n")...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadHostMonitorRequest(stateDir); err == nil {
		t.Fatal("host monitor accepted an unknown request field")
	}
}

func prepareHostMonitorFixture(t *testing.T) (string, HostMonitorRequest, Profile, guestcontrol.Manifest) {
	t.Helper()
	return prepareHostMonitorFixtureForSchema(t, ProfileSchemaV1)
}

func prepareV2HostMonitorFixture(t *testing.T) (string, HostMonitorRequest, Profile, guestcontrol.Manifest) {
	t.Helper()
	return prepareHostMonitorFixtureForSchema(t, ProfileSchemaV2)
}

func prepareHostMonitorFixtureForSchema(t *testing.T, schema string) (string, HostMonitorRequest, Profile, guestcontrol.Manifest) {
	t.Helper()
	stateDir := filepath.Join(t.TempDir(), "session-11111111-1111-4111-8111-111111111111")
	paths := []string{
		stateDir,
		filepath.Join(stateDir, "runtime"),
		filepath.Join(stateDir, "runtime", "control"),
		filepath.Join(stateDir, "runtime", "host"),
		filepath.Join(stateDir, "runtime", "logs"),
	}
	if schema == ProfileSchemaV1 {
		paths = append(paths, filepath.Join(stateDir, "runtime", "workspace"))
	}
	for _, path := range paths {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	profile := testProfile(t)
	if schema == ProfileSchemaV2 {
		profile.Schema = ProfileSchemaV2
		profile.Name = "pi-linux-qemu-v2"
		profile.WorkspaceVolume = &WorkspaceVolumeSpec{
			Model: WorkspaceVolumeModel, Format: WorkspaceVolumeFormat, Filesystem: WorkspaceVolumeFilesystem,
			RunnerFD: WorkspaceVolumeRunnerFD, VirtualSizeBytes: 8 << 30,
		}
	}
	profile.Timeouts.ReadinessSeconds = 1
	profile.Timeouts.GracefulShutdownSeconds = 1
	profilePath := writeProfile(t, profile)
	_, profileFileDigest, err := ReadProfileSnapshot(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	leaseRoot := filepath.Join(t.TempDir(), "cid-leases")
	lease, err := AllocateCID(context.Background(), leaseRoot, filepath.Base(stateDir), profile.VSock.CIDMin, profile.VSock.CIDMax)
	if err != nil {
		t.Fatal(err)
	}
	manifest := guestcontrol.Manifest{
		ProtocolVersion: guestcontrol.ProtocolVersion,
		SessionID:       filepath.Base(stateDir), LaunchNonce: strings.Repeat("1", 64),
		ControlToken: strings.Repeat("2", 64), SupervisorToken: strings.Repeat("3", 64),
		Profile: profile.Name, ProfileDigest: profile.Guest.ProfileDigest,
		Policy: profile.Guest.Policy, Workspace: profile.Guest.Workspace,
		VSockCID: lease.CID, VSockPort: profile.Guest.ControlPort, SupervisorPort: profile.Guest.SupervisorPort,
		ExpectedGeneration: 1,
	}
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(stateDir, "runtime", "control", "request.json")
	if err := os.WriteFile(manifestPath, manifestData, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestDigest, err := HostMonitorFileSHA256(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	monitorSchema, err := hostMonitorSchemaVersionForProfile(schema)
	if err != nil {
		t.Fatal(err)
	}
	request := HostMonitorRequest{
		SchemaVersion: monitorSchema, MonitorID: strings.Repeat("4", 64),
		SessionID: filepath.Base(stateDir), StateDir: stateDir, SourceWorkspace: filepath.Join(t.TempDir(), "source"), ProfileFile: profilePath,
		ProfileFileSHA256: profileFileDigest, ProfileName: profile.Name, ProfileDigest: profile.ProfileDigest, GuestProfileDigest: profile.Guest.ProfileDigest,
		GuestPolicy: profile.Guest.Policy, GuestControlPort: profile.Guest.ControlPort, GuestSupervisorPort: profile.Guest.SupervisorPort,
		GuestManifestSHA256: manifestDigest, ExpectedGuestGeneration: manifest.ExpectedGeneration, LaunchNonce: manifest.LaunchNonce,
		CIDLeaseRoot: leaseRoot, CIDLease: lease, CreatedAt: time.Now().UTC(),
	}
	if schema == ProfileSchemaV2 {
		contract := *profile.WorkspaceVolume
		request.ProfileSchema = profile.Schema
		request.WorkspaceVolume = &contract
		request.VolumeID = testWorkspaceVolumeID
	}
	if err := WriteHostMonitorRequest(stateDir, request); err != nil {
		t.Fatal(err)
	}
	return stateDir, request, profile, manifest
}

func testHostHandshake(manifest guestcontrol.Manifest) guestcontrol.Handshake {
	return guestcontrol.Handshake{
		ProtocolVersion: guestcontrol.ProtocolVersion, SessionID: manifest.SessionID,
		Generation: manifest.ExpectedGeneration, IncarnationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		LaunchNonce: manifest.LaunchNonce, GuestBootID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		Profile: manifest.Profile, ProfileDigest: manifest.ProfileDigest,
		AgentSHVersion: "test", EventToken: strings.Repeat("7", 64), Policy: manifest.Policy, VSockCID: manifest.VSockCID,
		VSockPort: manifest.VSockPort, SupervisorPort: manifest.SupervisorPort,
		Capabilities: []string{"exec_probe", "shutdown", "supervisor_proxy", manifest.ControlToken},
	}
}
