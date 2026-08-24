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
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/guestcontrol"
)

type fakeHostRunner struct {
	identity HostProcessIdentity
	done     chan hostRunnerResult
	waitDone chan struct{}
	result   hostRunnerResult
	once     sync.Once
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
		result := r.result
		return &result, nil
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
	runner, err := startHostRunner(profile, layout, 41123, &output)
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
		startRunner: func(got Profile, layout HostMonitorLayout, cid uint32, output io.Writer) (hostRunner, error) {
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
	if err := VerifyCIDLease(context.Background(), request.CIDLeaseRoot, request.CIDLease, profile.VSock.CIDMin, profile.VSock.CIDMax); err != nil {
		t.Fatalf("monitor incorrectly released provider-owned CID lease: %v", err)
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
		startRunner:    func(Profile, HostMonitorLayout, uint32, io.Writer) (hostRunner, error) { return runner, nil },
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

func TestHostMonitorRequestIsExclusiveAndStrict(t *testing.T) {
	stateDir, request, _, _ := prepareHostMonitorFixture(t)
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
	stateDir := filepath.Join(t.TempDir(), "session-11111111-1111-4111-8111-111111111111")
	for _, path := range []string{
		stateDir,
		filepath.Join(stateDir, "runtime"),
		filepath.Join(stateDir, "runtime", "workspace"),
		filepath.Join(stateDir, "runtime", "control"),
		filepath.Join(stateDir, "runtime", "host"),
		filepath.Join(stateDir, "runtime", "logs"),
	} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	profile := testProfile(t)
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
	request := HostMonitorRequest{
		SchemaVersion: HostMonitorSchemaVersion, MonitorID: strings.Repeat("4", 64),
		SessionID: filepath.Base(stateDir), StateDir: stateDir, ProfileFile: profilePath,
		ProfileFileSHA256: profileFileDigest, ProfileName: profile.Name, ProfileDigest: profile.ProfileDigest, GuestProfileDigest: profile.Guest.ProfileDigest,
		GuestPolicy: profile.Guest.Policy, GuestControlPort: profile.Guest.ControlPort, GuestSupervisorPort: profile.Guest.SupervisorPort,
		GuestManifestSHA256: manifestDigest, ExpectedGuestGeneration: manifest.ExpectedGeneration, LaunchNonce: manifest.LaunchNonce,
		CIDLeaseRoot: leaseRoot, CIDLease: lease, CreatedAt: time.Now().UTC(),
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
		AgentSHVersion: "test", Policy: manifest.Policy, VSockCID: manifest.VSockCID,
		VSockPort: manifest.VSockPort, SupervisorPort: manifest.SupervisorPort,
		Capabilities: []string{"exec_probe", "shutdown", "supervisor_proxy", manifest.ControlToken},
	}
}
