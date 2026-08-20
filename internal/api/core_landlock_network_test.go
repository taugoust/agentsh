//go:build linux

package api

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestSelectSandboxCompositionRequiresMetadataInterception(t *testing.T) {
	enabled := true
	disabled := false
	cfg := &config.Config{}
	cfg.Landlock.Enabled = true
	cfg.Sandbox.Composition.Bubblewrap.Enabled = true
	cfg.Sandbox.Composition.Bubblewrap.Dialect = "0.11.2"
	cfg.Sandbox.Composition.Bubblewrap.ScratchRoot = "/agentsh-composition-scratch"
	cfg.Sandbox.Network.EBPF.Required = true
	cfg.Sandbox.Seccomp.Execve.Enabled = true
	cfg.Sandbox.Seccomp.FileMonitor.Enabled = &enabled
	cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE = &enabled
	cfg.Sandbox.Seccomp.FileMonitor.WriteOnlyOpens = &disabled
	cfg.Sandbox.Seccomp.FileMonitor.BlockIOUring = &enabled
	cfg.Sandbox.Seccomp.FileMonitor.InterceptMetadata = &disabled
	app := &App{cfg: cfg}

	decision := &policy.Decision{
		EffectiveDecision:  types.DecisionAllow,
		SandboxComposition: bubblewrapCompositionMode,
	}
	mode, code := app.selectSandboxComposition(decision)
	if mode != "" || code != "E_COMPOSITION_BACKEND_UNAVAILABLE" || decision.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("metadata-disabled selection mode=%q code=%q decision=%+v", mode, code, decision)
	}
	if !strings.Contains(decision.Message, "metadata file interception") {
		t.Fatalf("metadata-disabled message = %q", decision.Message)
	}

	cfg.Sandbox.Seccomp.FileMonitor.InterceptMetadata = &enabled
	decision = &policy.Decision{
		EffectiveDecision:  types.DecisionAllow,
		SandboxComposition: bubblewrapCompositionMode,
	}
	mode, code = app.selectSandboxComposition(decision)
	if mode != bubblewrapCompositionMode || code != "" {
		t.Fatalf("metadata-enabled selection mode=%q code=%q decision=%+v", mode, code, decision)
	}
}

func TestConfigureExecveCompositionRequiresMetadataInterceptionAtRuntime(t *testing.T) {
	handler := unixmon.NewExecveHandler(unixmon.ExecveHandlerConfig{}, nil, nil, nil)
	wrapperCfg := seccompWrapperConfig{
		SandboxComposition: bubblewrapCompositionMode,
		LandlockEnabled:    true,
		FileMonitorEnabled: true,
		WriteOnlyOpens:     false,
		BlockIOUring:       true,
		InterceptMetadata:  false,
	}
	app := &App{cfg: &config.Config{}}
	err := app.configureExecveComposition(handler, &session.Session{}, wrapperCfg, nil, 1)
	if err == nil || !strings.Contains(err.Error(), "metadata file interception") {
		t.Fatalf("metadata-disabled runtime error = %v", err)
	}

	wrapperCfg.InterceptMetadata = true
	err = app.configureExecveComposition(handler, &session.Session{}, wrapperCfg, nil, 0)
	if err == nil || !strings.Contains(err.Error(), "trusted wrapper PID") {
		t.Fatalf("zero wrapper PID should fail sender binding, got %v", err)
	}
	err = app.configureExecveComposition(handler, &session.Session{}, wrapperCfg, nil, 1)
	if err == nil || !strings.Contains(err.Error(), "setup channel") {
		t.Fatalf("metadata-enabled runtime should advance to setup-channel check, got %v", err)
	}
}

func TestSetupSeccompWrapperDefersCompositionUntilStartedWrapperPID(t *testing.T) {
	if !capabilities.DetectLandlock().Available {
		t.Skip("Landlock not available on this host")
	}
	enabled := true
	disabled := false
	cfg := &config.Config{}
	cfg.Landlock.Enabled = true
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = testNoopExecutable(t)
	cfg.Sandbox.Network.EBPF.Required = true
	cfg.Sandbox.Seccomp.Execve.Enabled = true
	cfg.Sandbox.Seccomp.FileMonitor.Enabled = &enabled
	cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE = &enabled
	cfg.Sandbox.Seccomp.FileMonitor.InterceptMetadata = &enabled
	cfg.Sandbox.Seccomp.FileMonitor.WriteOnlyOpens = &disabled
	cfg.Sandbox.Seccomp.FileMonitor.BlockIOUring = &enabled
	cfg.Sandbox.Composition.Bubblewrap.Enabled = true
	cfg.Sandbox.Composition.Bubblewrap.Dialect = "0.11.2"
	cfg.Sandbox.Composition.Bubblewrap.ScratchRoot = "/agentsh-composition-scratch"
	app := newTestAppForSeccomp(t, cfg)
	sess := &session.Session{Workspace: t.TempDir()}
	sess.SetCurrentSandboxComposition(bubblewrapCompositionMode)

	result := app.setupSeccompWrapper(types.ExecRequest{Command: testNoopExecutable(t)}, "composition-deferred", sess)
	if result == nil || result.setupErr != nil {
		t.Fatalf("composition wrapper setup failed before process start: %#v", result)
	}
	if result.extraCfg == nil || result.extraCfg.compositionParentSock == nil || result.extraCfg.configureComposition == nil {
		t.Fatalf("composition setup was not deferred with retained state: %#v", result.extraCfg)
	}
	closePreStartProcessFiles(result.extraCfg)
}

func TestBuildSeccompWrapperConfig_DeviceIOCTLOnlyForComposition(t *testing.T) {
	if !capabilities.DetectLandlock().Available {
		t.Skip("Landlock not available on this host")
	}
	cfg := &config.Config{}
	cfg.Landlock.Enabled = true
	cfg.Sandbox.Composition.Bubblewrap.ScratchRoot = "/agentsh-composition-scratch"
	cfg.Sandbox.Composition.Bubblewrap.DeviceIOCTLPaths = []string{"/dev/null"}
	app := newTestAppForSeccomp(t, cfg)
	sess := &session.Session{Workspace: "/tmp"}

	ordinary := app.buildSeccompWrapperConfig(sess, seccompWrapperParams{})
	if ordinary.HandleDeviceIOCTL || len(ordinary.AllowDeviceIOCTL) != 0 {
		t.Fatalf("ordinary command unexpectedly handles device ioctls: %+v", ordinary)
	}

	sess.SetCurrentSandboxComposition(bubblewrapCompositionMode)
	composition := app.buildSeccompWrapperConfig(sess, seccompWrapperParams{})
	if !composition.HandleDeviceIOCTL {
		t.Fatal("composition command does not handle ABI-5 device ioctls")
	}
	if len(composition.AllowDeviceIOCTL) != 1 || composition.AllowDeviceIOCTL[0] != "/dev/null" {
		t.Fatalf("composition device ioctl paths = %#v", composition.AllowDeviceIOCTL)
	}
	if len(composition.DenyPaths) == 0 || composition.DenyPaths[0] != "/agentsh-composition-scratch" {
		t.Fatalf("composition internal deny paths = %#v", composition.DenyPaths)
	}

	// A wrap-init snapshot must override stale session-global state in both
	// directions; concurrent requests cannot borrow one another's selection.
	boundOrdinary := app.buildSeccompWrapperConfig(sess, seccompWrapperParams{CompositionSelectionBound: true})
	if boundOrdinary.SandboxComposition != "" || boundOrdinary.HandleDeviceIOCTL {
		t.Fatalf("explicit empty composition snapshot inherited stale session state: %+v", boundOrdinary)
	}
	sess.SetCurrentSandboxComposition("")
	boundComposition := app.buildSeccompWrapperConfig(sess, seccompWrapperParams{
		CompositionSelectionBound: true,
		SandboxComposition:        bubblewrapCompositionMode,
	})
	if boundComposition.SandboxComposition != bubblewrapCompositionMode || !boundComposition.HandleDeviceIOCTL {
		t.Fatalf("explicit composition snapshot was lost: %+v", boundComposition)
	}
}

// TestSetupSeccompWrapper_LandlockNetwork_HonorsConfig verifies that the
// seccompWrapperConfig JSON produced by setupSeccompWrapper reflects
// landlock.network.allow_connect_tcp / allow_bind_tcp values rather than
// hardcoded true/true.
func TestSetupSeccompWrapper_LandlockNetwork_HonorsConfig(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("seccomp wrapper only available on Linux")
	}
	if !capabilities.DetectLandlock().Available {
		t.Skip("Landlock not available on this host")
	}

	cases := []struct {
		name     string
		connect  bool
		bind     bool
		wantNet  bool
		wantBind bool
	}{
		{"both_true", true, true, true, true},
		{"connect_true_bind_false", true, false, true, false},
		{"connect_false_bind_false", false, false, false, false},
		{"connect_true_bind_true", true, true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			connect := tc.connect
			bind := tc.bind

			enabled := true
			cfg := &config.Config{}
			cfg.Sandbox.UnixSockets.Enabled = &enabled
			cfg.Sandbox.UnixSockets.WrapperBin = testNoopExecutable(t)
			cfg.Landlock.Enabled = true
			cfg.Landlock.Network.AllowConnectTCP = &connect
			cfg.Landlock.Network.AllowBindTCP = &bind

			app := newTestAppForSeccomp(t, cfg)
			req := types.ExecRequest{Command: "/bin/echo", Args: []string{"hi"}}
			sess := &session.Session{Workspace: "/tmp"}

			result := app.setupSeccompWrapper(req, "test-session", sess)
			if result == nil || result.extraCfg == nil {
				t.Fatal("expected non-nil wrapper setup result with extraCfg")
			}
			defer func() {
				if result.extraCfg.notifyParentSock != nil {
					result.extraCfg.notifyParentSock.Close()
				}
				for _, f := range result.extraCfg.extraFiles {
					if f != nil {
						f.Close()
					}
				}
			}()

			seccompJSON, ok := result.wrappedReq.Env["AGENTSH_SECCOMP_CONFIG"]
			if !ok {
				t.Fatal("AGENTSH_SECCOMP_CONFIG env var not set")
			}

			var parsed map[string]any
			if err := json.Unmarshal([]byte(seccompJSON), &parsed); err != nil {
				t.Fatalf("unmarshal seccomp config: %v\n%s", err, seccompJSON)
			}

			gotNet, _ := parsed["allow_network"].(bool)
			gotBind, _ := parsed["allow_bind"].(bool)
			if gotNet != tc.wantNet {
				t.Errorf("allow_network = %v; want %v (JSON: %s)", gotNet, tc.wantNet, seccompJSON)
			}
			if gotBind != tc.wantBind {
				t.Errorf("allow_bind = %v; want %v (JSON: %s)", gotBind, tc.wantBind, seccompJSON)
			}
		})
	}
}
