package api

import (
	"runtime"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
)

func TestDeriveLandlockAllowPaths_IncludesApproveOnlyWhenDynamicFileApprovalsActive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Landlock derivation tests use Unix paths")
	}
	boolPtr := func(v bool) *bool { return &v }
	pol := &policy.Policy{FileRules: []policy.FileRule{
		{Name: "approve-env", Paths: []string{"/repo/.env"}, Operations: []string{"open"}, Decision: "approve"},
	}}
	engine, err := policy.NewEngine(pol, true, true)
	if err != nil {
		t.Fatal(err)
	}
	s, err := session.NewManager(1).Create(t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}
	s.SetPolicyEngine(engine)

	cfg := &config.Config{}
	cfg.Approvals.Enabled = true
	cfg.Approvals.Mode = "api"
	cfg.Sandbox.Seccomp.FileMonitor.Enabled = boolPtr(true)
	cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE = boolPtr(true)
	app := &App{cfg: cfg, approvals: approvals.New("api", time.Minute, nil)}

	_, read, _ := app.deriveLandlockAllowPaths(s)
	if !containsString(read, "/repo") {
		t.Fatalf("active dynamic approvals should include approvable read prefix, got %#v", read)
	}

	cfg.Sandbox.Seccomp.FileMonitor.Enabled = boolPtr(false)
	_, read, _ = app.deriveLandlockAllowPaths(s)
	if containsString(read, "/repo") {
		t.Fatalf("disabled file monitor should not widen Landlock for approvals, got %#v", read)
	}
}

func TestDeriveLandlockAllowPaths_DenyPathDoesNotWidenApprove(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Landlock derivation tests use Unix paths")
	}
	boolPtr := func(v bool) *bool { return &v }
	pol := &policy.Policy{FileRules: []policy.FileRule{
		{Name: "approve-secret", Paths: []string{"/repo/secret/**"}, Operations: []string{"open"}, Decision: "approve"},
	}}
	engine, err := policy.NewEngine(pol, true, true)
	if err != nil {
		t.Fatal(err)
	}
	s, err := session.NewManager(1).Create(t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}
	s.SetPolicyEngine(engine)
	cfg := &config.Config{}
	cfg.Approvals.Enabled = true
	cfg.Approvals.Mode = "api"
	cfg.Sandbox.Seccomp.FileMonitor.Enabled = boolPtr(true)
	cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE = boolPtr(true)
	cfg.Landlock.DenyPaths = []string{"/repo/secret/token"}
	app := &App{cfg: cfg, approvals: approvals.New("api", time.Minute, nil)}

	_, read, _ := app.deriveLandlockAllowPaths(s)
	if containsString(read, "/repo/secret") {
		t.Fatalf("deny-overlapping approve prefix should not be widened, got %#v", read)
	}
}
