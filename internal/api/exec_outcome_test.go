package api

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestRunCommandAuthoritativeStartOutcomes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX command outcome fixture")
	}
	manager := session.NewManager(1)
	sess, err := manager.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cases := []struct {
		name        string
		req         types.ExecRequest
		wantStarted bool
		wantExit    int
		wantCode    string
	}{
		{name: "nonexistent command", req: types.ExecRequest{Command: filepath.Join(t.TempDir(), "missing")}, wantExit: 127, wantCode: "E_COMMAND_START"},
		{name: "invalid cwd", req: types.ExecRequest{Command: "sh", WorkingDir: filepath.Join(t.TempDir(), "missing")}, wantExit: 2, wantCode: "E_INVALID_WORKING_DIRECTORY"},
		{name: "invalid environment", req: types.ExecRequest{Command: "sh", Args: []string{"-c", "true"}, Env: map[string]string{"BAD=KEY": "value"}}, wantExit: 2, wantCode: "E_INVALID_ENVIRONMENT"},
		{name: "genuine child 127", req: types.ExecRequest{Command: "sh", Args: []string{"-c", "exit 127"}}, wantStarted: true, wantExit: 127, wantCode: "E_CHILD_EXIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			started := false
			exitCode, _, _, _, _, _, _, _, runErr := runCommandWithResources(context.Background(), sess, "cmd-outcome", tc.req, cfg, policy.ResolvedEnvPolicy{}, 0, nil, nil, nil, "", func() { started = true })
			if started != tc.wantStarted || exitCode != tc.wantExit {
				t.Fatalf("started=%t exit=%d err=%v", started, exitCode, runErr)
			}
			outcome := normalizeExecOutcome(started, exitCode, runErr)
			if outcome.CommandStarted != tc.wantStarted || outcome.Code != tc.wantCode {
				t.Fatalf("outcome=%+v err=%v", outcome, runErr)
			}
		})
	}
}

func TestRunCommandStreamingAuthoritativeStartSharedBySSEAndGRPC(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX command outcome fixture")
	}
	manager := session.NewManager(1)
	sess, err := manager.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		req         types.ExecRequest
		wantStarted bool
		wantCode    string
	}{
		{name: "start failure", req: types.ExecRequest{Command: filepath.Join(t.TempDir(), "missing")}, wantCode: "E_COMMAND_START"},
		{name: "child 127", req: types.ExecRequest{Command: "sh", Args: []string{"-c", "exit 127"}}, wantStarted: true, wantCode: "E_CHILD_EXIT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started := false
			exitCode, _, _, _, _, _, _, _, runErr := runCommandWithResourcesStreamingEmit(context.Background(), sess, "cmd-stream-outcome", tc.req, &config.Config{}, 0, func(string, map[string]any) error { return nil }, nil, nil, nil, "", func() { started = true })
			outcome := normalizeExecOutcome(started, exitCode, runErr)
			if started != tc.wantStarted || outcome.Code != tc.wantCode {
				t.Fatalf("started=%t outcome=%+v err=%v", started, outcome, runErr)
			}
		})
	}
}

func TestNormalizeBarrierFailureBeforeReleaseIsNotStarted(t *testing.T) {
	err := markPreExecEnforcementError("E_PRE_EXEC_RELEASE", context.Canceled)
	outcome := normalizeExecOutcome(false, 127, err)
	if outcome.CommandStarted || outcome.DispatchState != "pre_exec_refused" || outcome.Code != "E_PRE_EXEC_RELEASE" {
		t.Fatalf("outcome=%+v", outcome)
	}
}
