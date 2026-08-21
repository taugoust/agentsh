package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestDiscoverProjectOverlaysDisabled(t *testing.T) {
	root := t.TempDir()
	writeOverlay(t, root, "xilinx.yaml", "name: xilinx\nfile_rules:\n  - name: allow-xilinx\n    paths: [/share/xilinx/**]\n    operations: [read]\n    decision: allow\n")
	files, err := DiscoverProjectOverlays(root, ProjectOverlaysConfig{Enabled: false})
	if err != nil {
		t.Fatalf("DiscoverProjectOverlays: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("disabled discovery returned %d overlays", len(files))
	}
}

func TestDiscoverProjectOverlaysValidation(t *testing.T) {
	root := t.TempDir()
	for _, pattern := range []string{"/tmp/*.yaml", "../*.yaml"} {
		_, err := DiscoverProjectOverlays(root, ProjectOverlaysConfig{Enabled: true, Paths: []string{pattern}})
		if err == nil {
			t.Fatalf("pattern %q: expected error", pattern)
		}
	}
}

func TestLoadOverlayKnownFieldsAndDuplicates(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "bad.yaml")
	if err := os.WriteFile(path, []byte("name: bad\nversion: 1\nfile_rules:\n  - name: dup\n    paths: [/**]\n    operations: [read]\n    decision: allow\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOverlay(path); err == nil || !strings.Contains(err.Error(), "field version not found") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}

	path = filepath.Join(root, "bad-command.yaml")
	if err := os.WriteFile(path, []byte("name: bad-command\ncommand_rules:\n  - name: typo\n    command: [echo]\n    decision: allow\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOverlay(path); err == nil || !strings.Contains(err.Error(), "field command not found") {
		t.Fatalf("expected nested command-rule unknown-field error, got %v", err)
	}

	path = filepath.Join(root, "bad-context.yaml")
	if err := os.WriteFile(path, []byte("name: bad-context\ncommand_rules:\n  - name: typo\n    commands: [echo]\n    context:\n      min_dept: 1\n    decision: allow\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOverlay(path); err == nil || !strings.Contains(err.Error(), "field min_dept not found") {
		t.Fatalf("expected nested context unknown-field error, got %v", err)
	}

	path = filepath.Join(root, "bad-redirect.yaml")
	if err := os.WriteFile(path, []byte("name: bad-redirect\ncommand_rules:\n  - name: typo\n    commands: [echo]\n    decision: redirect\n    redirect_to:\n      commmand: printf\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOverlay(path); err == nil || !strings.Contains(err.Error(), "field commmand not found") {
		t.Fatalf("expected nested redirect unknown-field error, got %v", err)
	}

	path = filepath.Join(root, "valid-context.yaml")
	if err := os.WriteFile(path, []byte("name: valid-context\ncommand_rules:\n  - &nested_rule\n    name: nested\n    commands: [echo]\n    context: &nested_context\n      min_depth: 1\n    decision: allow\n    timeout: 5m\n  - name: direct\n    commands: [printf]\n    context: [direct]\n    decision: allow\n  - name: alias-context\n    commands: [pwd]\n    context: *nested_context\n    decision: allow\n  - <<: *nested_rule\n    name: merged-rule\n    commands: [true]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	valid, err := LoadOverlay(path)
	if err != nil {
		t.Fatalf("expected valid command contexts, aliases, and merge keys, got %v", err)
	}
	if got := valid.CommandRules[0].Context; got.MinDepth != 1 || got.MaxDepth != -1 {
		t.Fatalf("object context = %+v, want min_depth=1 max_depth=-1", got)
	}
	if got := valid.CommandRules[0].Timeout.Duration; got != 5*time.Minute {
		t.Fatalf("command timeout = %s, want 5m", got)
	}
	if got := valid.CommandRules[1].Context; got.MinDepth != 0 || got.MaxDepth != 0 {
		t.Fatalf("array context = %+v, want direct-only", got)
	}
	if got := valid.CommandRules[2].Context; got.MinDepth != 1 || got.MaxDepth != -1 {
		t.Fatalf("aliased context = %+v, want min_depth=1 max_depth=-1", got)
	}
	if got := valid.CommandRules[3].Context; got.MinDepth != 1 || got.MaxDepth != -1 {
		t.Fatalf("merged rule context = %+v, want min_depth=1 max_depth=-1", got)
	}
	if got := valid.CommandRules[3].Timeout.Duration; got != 5*time.Minute {
		t.Fatalf("merged command timeout = %s, want 5m", got)
	}

	path = filepath.Join(root, "dup.yaml")
	if err := os.WriteFile(path, []byte("name: dup\nfile_rules:\n  - name: same\n    paths: [/a]\n    operations: [read]\n    decision: allow\ncommand_rules:\n  - name: same\n    commands: [echo]\n    decision: allow\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOverlay(path); err == nil || !strings.Contains(err.Error(), "duplicate overlay rule name") {
		t.Fatalf("expected duplicate-name error, got %v", err)
	}
}

func TestLoadOverlayCommandRuleSchemaCompatibility(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "configs", "policies", "*.yaml"))
	if err != nil {
		t.Fatalf("glob policies: %v", err)
	}
	paths = append(paths, filepath.Join("..", "..", "configs", "default-policy.yaml"))
	if len(paths) < 2 {
		t.Fatal("expected checked-in policy fixtures")
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			if _, err := LoadFromFile(path); err != nil {
				t.Fatalf("LoadFromFile(%s): %v", path, err)
			}
		})
	}
}

func TestMergePolicyOverlaysOrdering(t *testing.T) {
	base := &Policy{
		Version: 1,
		Name:    "base",
		FileRules: []FileRule{
			{Name: "deny-secrets", Paths: []string{"/secret/**"}, Operations: []string{"read"}, Decision: "deny"},
			{Name: "default-deny-files", Paths: []string{"**"}, Operations: []string{"*"}, Decision: "deny"},
		},
		CommandRules: []CommandRule{
			{Name: "default-deny-commands", Decision: "deny"},
		},
	}
	overlay := PolicyOverlay{
		Name:         "xilinx",
		FileRules:    []FileRule{{Name: "allow-xilinx-read-exec", Paths: []string{"/share/xilinx", "/share/xilinx/**"}, Operations: []string{"read", "open", "stat", "list", "readlink", "execute"}, Decision: "allow"}},
		CommandRules: []CommandRule{{Name: "allow-xsc", Commands: []string{"xsc", "/share/xilinx/**"}, Decision: "allow"}},
	}
	merged, err := MergePolicyOverlays(base, []PolicyOverlay{overlay})
	if err != nil {
		t.Fatalf("MergePolicyOverlays: %v", err)
	}
	gotFile := []string{merged.FileRules[0].Name, merged.FileRules[1].Name, merged.FileRules[2].Name}
	wantFile := []string{"deny-secrets", "allow-xilinx-read-exec", "default-deny-files"}
	for i := range wantFile {
		if gotFile[i] != wantFile[i] {
			t.Fatalf("file rule order = %v, want %v", gotFile, wantFile)
		}
	}
	gotCmd := []string{merged.CommandRules[0].Name, merged.CommandRules[1].Name}
	wantCmd := []string{"allow-xsc", "default-deny-commands"}
	for i := range wantCmd {
		if gotCmd[i] != wantCmd[i] {
			t.Fatalf("command rule order = %v, want %v", gotCmd, wantCmd)
		}
	}
}

func TestMergePolicyOverlaysLoadsBoundaryFromYAML(t *testing.T) {
	base, err := LoadFromBytes([]byte(`
version: 1
name: base
file_rules:
  - name: approve-outside
    project_overlay_boundary: true
    paths: ["**"]
    operations: ["*"]
    decision: approve
command_rules:
  - name: approve-unknown
    project_overlay_boundary: true
    decision: approve
`))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	overlay := PolicyOverlay{
		Name:         "project",
		FileRules:    []FileRule{{Name: "allow-project-file", Paths: []string{"/project"}, Operations: []string{"read"}, Decision: "allow"}},
		CommandRules: []CommandRule{{Name: "allow-project-command", Commands: []string{"project-tool"}, Decision: "allow"}},
	}
	merged, err := MergePolicyOverlays(base, []PolicyOverlay{overlay})
	if err != nil {
		t.Fatalf("MergePolicyOverlays: %v", err)
	}
	assertRuleOrder(t, "file", fileRuleNames(merged.FileRules), []string{"allow-project-file", "approve-outside"})
	assertRuleOrder(t, "command", commandRuleNames(merged.CommandRules), []string{"allow-project-command", "approve-unknown"})
}

func TestMergePolicyOverlaysPrecedesFallbackApprovals(t *testing.T) {
	base := &Policy{
		Version: 1,
		Name:    "pi-supervised-like",
		FileRules: []FileRule{
			{Name: "approve-sensitive", Paths: []string{"/sensitive/**"}, Operations: []string{"*"}, Decision: "approve"},
			{Name: "allow-runtime", Paths: []string{"/runtime/**"}, Operations: []string{"*"}, Decision: "allow"},
			{Name: "approve-outside-writes", ProjectOverlayBoundary: true, Paths: []string{"**"}, Operations: []string{"write", "create"}, Decision: "approve"},
			{Name: "approve-outside-reads", Paths: []string{"**"}, Operations: []string{"read", "open", "stat", "list", "readlink"}, Decision: "approve"},
			{Name: "default-deny-files", Paths: []string{"**"}, Operations: []string{"*"}, Decision: "deny"},
		},
		CommandRules: []CommandRule{
			{Name: "approve-privilege", Commands: []string{"sudo"}, Decision: "approve"},
			{Name: "allow-runtime-tools", Commands: []string{"sh"}, Decision: "allow"},
			{Name: "approve-unknown-nix-store", ProjectOverlayBoundary: true, Commands: []string{"/nix/store/*/bin/*"}, Decision: "approve"},
			{Name: "approve-unknown", Decision: "approve"},
		},
	}
	overlay := PolicyOverlay{
		Name: "xilinx",
		FileRules: []FileRule{
			{Name: "deny-xilinx-writes", Paths: []string{"/share/xilinx/**"}, Operations: []string{"write", "create"}, Decision: "deny"},
			{Name: "allow-xilinx-reads", Paths: []string{"/share/xilinx/**"}, Operations: []string{"read", "open", "stat", "list", "readlink"}, Decision: "allow"},
		},
		CommandRules: []CommandRule{
			{Name: "approve-programming", Commands: []string{"program-cli"}, Decision: "approve", Message: "Physical FPGA deployment requires approval."},
			{Name: "allow-vivado", Commands: []string{"vivado"}, Decision: "allow"},
		},
	}

	merged, err := MergePolicyOverlays(base, []PolicyOverlay{overlay})
	if err != nil {
		t.Fatalf("MergePolicyOverlays: %v", err)
	}
	assertRuleOrder(t, "file", fileRuleNames(merged.FileRules), []string{
		"approve-sensitive",
		"allow-runtime",
		"deny-xilinx-writes",
		"allow-xilinx-reads",
		"approve-outside-writes",
		"approve-outside-reads",
		"default-deny-files",
	})
	assertRuleOrder(t, "command", commandRuleNames(merged.CommandRules), []string{
		"approve-privilege",
		"allow-runtime-tools",
		"approve-programming",
		"allow-vivado",
		"approve-unknown-nix-store",
		"approve-unknown",
	})

	engine, err := NewEngine(merged, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	assertDecision(t, "Xilinx read", engine.CheckFile("/share/xilinx/Vivado/2022.2/bin/vivado", "open"), types.DecisionAllow, "allow-xilinx-reads")
	assertDecision(t, "Xilinx write", engine.CheckFile("/share/xilinx/Vivado/2022.2/bin/vivado", "write"), types.DecisionDeny, "deny-xilinx-writes")
	assertDecision(t, "sensitive base guardrail", engine.CheckFile("/sensitive/token", "open"), types.DecisionApprove, "approve-sensitive")
	assertDecision(t, "unmatched outside read", engine.CheckFile("/outside/file", "open"), types.DecisionApprove, "approve-outside-reads")
	assertDecision(t, "unmatched outside write", engine.CheckFile("/outside/file", "write"), types.DecisionApprove, "approve-outside-writes")

	assertDecision(t, "Vivado wrapper", engine.CheckCommand("/nix/store/hash-vivado/bin/vivado", nil), types.DecisionAllow, "allow-vivado")
	programming := engine.CheckCommand("/nix/store/hash-program-cli/bin/program-cli", nil)
	assertDecision(t, "programming", programming, types.DecisionApprove, "approve-programming")
	if programming.Message != "Physical FPGA deployment requires approval." {
		t.Fatalf("programming approval message = %q", programming.Message)
	}
	assertDecision(t, "privilege base guardrail", engine.CheckCommand("/nix/store/hash-sudo/bin/sudo", nil), types.DecisionApprove, "approve-privilege")
	assertDecision(t, "unknown Nix-store executable", engine.CheckCommand("/nix/store/hash-other/bin/other", nil), types.DecisionApprove, "approve-unknown-nix-store")
	assertDecision(t, "unknown executable", engine.CheckCommand("/opt/other", nil), types.DecisionApprove, "approve-unknown")
}

func TestMergePolicyOverlaysBaseGuardrailsPrecedeBroadOverlay(t *testing.T) {
	base := &Policy{
		Version: 1,
		Name:    "guarded",
		FileRules: []FileRule{
			{Name: "approve-protected-files", Paths: []string{"/protected/**"}, Operations: []string{"*"}, Decision: "approve"},
			{Name: "file-fallback", ProjectOverlayBoundary: true, Paths: []string{"**"}, Operations: []string{"*"}, Decision: "approve"},
		},
		CommandRules: []CommandRule{
			{Name: "approve-sudo", Commands: []string{"sudo"}, Decision: "approve"},
			{Name: "command-fallback", ProjectOverlayBoundary: true, Decision: "approve"},
		},
	}
	overlay := PolicyOverlay{
		Name:         "broad",
		FileRules:    []FileRule{{Name: "allow-all-overlay-files", Paths: []string{"**"}, Operations: []string{"*"}, Decision: "allow"}},
		CommandRules: []CommandRule{{Name: "allow-all-overlay-commands", Decision: "allow"}},
	}
	merged, err := MergePolicyOverlays(base, []PolicyOverlay{overlay})
	if err != nil {
		t.Fatalf("MergePolicyOverlays: %v", err)
	}
	engine, err := NewEngine(merged, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	assertDecision(t, "protected file", engine.CheckFile("/protected/token", "open"), types.DecisionApprove, "approve-protected-files")
	assertDecision(t, "ordinary overlay file", engine.CheckFile("/ordinary", "open"), types.DecisionAllow, "allow-all-overlay-files")
	assertDecision(t, "sudo", engine.CheckCommand("/nix/store/hash-sudo/bin/sudo", nil), types.DecisionApprove, "approve-sudo")
	assertDecision(t, "ordinary overlay command", engine.CheckCommand("/opt/ordinary", nil), types.DecisionAllow, "allow-all-overlay-commands")
}

func TestMergePolicyOverlaysExplicitBoundariesAllOrderedFamilies(t *testing.T) {
	base := &Policy{
		Version: 1,
		Name:    "base",
		FileRules: []FileRule{
			{Name: "base-file", Paths: []string{"/base"}, Operations: []string{"read"}, Decision: "allow"},
			{Name: "fallback-file", ProjectOverlayBoundary: true, Paths: []string{"**"}, Operations: []string{"*"}, Decision: "approve"},
		},
		NetworkRules: []NetworkRule{
			{Name: "base-network", Domains: []string{"base.example"}, Decision: "allow"},
			{Name: "fallback-network", ProjectOverlayBoundary: true, Domains: []string{"*"}, Decision: "approve"},
		},
		CommandRules: []CommandRule{
			{Name: "base-command", Commands: []string{"base"}, Decision: "allow"},
			{Name: "fallback-command", ProjectOverlayBoundary: true, Decision: "approve"},
		},
		UnixRules: []UnixSocketRule{
			{Name: "base-unix", Paths: []string{"/base.sock"}, Decision: "allow"},
			{Name: "fallback-unix", ProjectOverlayBoundary: true, Paths: []string{"**"}, Decision: "approve"},
		},
		SignalRules: []SignalRule{
			{Name: "base-signal", Signals: []string{"SIGTERM"}, Decision: "allow"},
			{Name: "fallback-signal", ProjectOverlayBoundary: true, Signals: []string{"*"}, Decision: "approve"},
		},
	}
	overlay := PolicyOverlay{
		Name:         "all-families",
		FileRules:    []FileRule{{Name: "overlay-file", Paths: []string{"/overlay"}, Operations: []string{"read"}, Decision: "allow"}},
		NetworkRules: []NetworkRule{{Name: "overlay-network", Domains: []string{"overlay.example"}, Decision: "allow"}},
		CommandRules: []CommandRule{{Name: "overlay-command", Commands: []string{"overlay"}, Decision: "allow"}},
		UnixRules:    []UnixSocketRule{{Name: "overlay-unix", Paths: []string{"/overlay.sock"}, Decision: "allow"}},
		SignalRules:  []SignalRule{{Name: "overlay-signal", Signals: []string{"SIGUSR1"}, Decision: "allow"}},
	}

	merged, err := MergePolicyOverlays(base, []PolicyOverlay{overlay})
	if err != nil {
		t.Fatalf("MergePolicyOverlays: %v", err)
	}
	assertRuleOrder(t, "file", fileRuleNames(merged.FileRules), []string{"base-file", "overlay-file", "fallback-file"})
	assertRuleOrder(t, "network", networkRuleNames(merged.NetworkRules), []string{"base-network", "overlay-network", "fallback-network"})
	assertRuleOrder(t, "command", commandRuleNames(merged.CommandRules), []string{"base-command", "overlay-command", "fallback-command"})
	assertRuleOrder(t, "unix", unixRuleNames(merged.UnixRules), []string{"base-unix", "overlay-unix", "fallback-unix"})
	assertRuleOrder(t, "signal", signalRuleNames(merged.SignalRules), []string{"base-signal", "overlay-signal", "fallback-signal"})
}

func TestMergePolicyOverlaysAppendsWithoutBoundaryOrTerminalDeny(t *testing.T) {
	base := &Policy{
		Version:      1,
		Name:         "allow-only",
		FileRules:    []FileRule{{Name: "base-file", Paths: []string{"/base"}, Operations: []string{"read"}, Decision: "allow"}},
		CommandRules: []CommandRule{{Name: "base-command", Commands: []string{"base"}, Decision: "allow"}},
	}
	overlay := PolicyOverlay{
		Name:         "project",
		FileRules:    []FileRule{{Name: "overlay-file", Paths: []string{"/overlay"}, Operations: []string{"read"}, Decision: "allow"}},
		CommandRules: []CommandRule{{Name: "overlay-command", Commands: []string{"overlay"}, Decision: "allow"}},
	}
	merged, err := MergePolicyOverlays(base, []PolicyOverlay{overlay})
	if err != nil {
		t.Fatalf("MergePolicyOverlays: %v", err)
	}
	assertRuleOrder(t, "file", fileRuleNames(merged.FileRules), []string{"base-file", "overlay-file"})
	assertRuleOrder(t, "command", commandRuleNames(merged.CommandRules), []string{"base-command", "overlay-command"})
}

func TestMergePolicyOverlaysPreservesOverlayOrder(t *testing.T) {
	base := &Policy{
		Version:      1,
		Name:         "legacy-base",
		FileRules:    []FileRule{{Name: "default-deny-files", Paths: []string{"**"}, Operations: []string{"*"}, Decision: "deny"}},
		CommandRules: []CommandRule{{Name: "default-deny-commands", Decision: "deny"}},
	}
	first := PolicyOverlay{
		Name:         "first",
		FileRules:    []FileRule{{Name: "first-overlay-file-deny", Paths: []string{"**"}, Operations: []string{"*"}, Decision: "deny"}},
		CommandRules: []CommandRule{{Name: "first-overlay-command-deny", Decision: "deny"}},
	}
	second := PolicyOverlay{
		Name:         "second",
		FileRules:    []FileRule{{Name: "second-overlay-file-allow", Paths: []string{"/second"}, Operations: []string{"read"}, Decision: "allow"}},
		CommandRules: []CommandRule{{Name: "second-overlay-command-allow", Commands: []string{"second"}, Decision: "allow"}},
	}

	merged, err := MergePolicyOverlays(base, []PolicyOverlay{first, second})
	if err != nil {
		t.Fatalf("MergePolicyOverlays: %v", err)
	}
	assertRuleOrder(t, "file", fileRuleNames(merged.FileRules), []string{
		"first-overlay-file-deny",
		"second-overlay-file-allow",
		"default-deny-files",
	})
	assertRuleOrder(t, "command", commandRuleNames(merged.CommandRules), []string{
		"first-overlay-command-deny",
		"second-overlay-command-allow",
		"default-deny-commands",
	})
}

func TestMergePolicyOverlaysRejectsProcessContextBoundary(t *testing.T) {
	_, err := LoadFromBytes([]byte(`
version: 1
name: nested-boundary
process_contexts:
  child:
    command_rules:
      - name: nested
        project_overlay_boundary: true
        commands: [child]
        decision: allow
`))
	if err == nil || !strings.Contains(err.Error(), "supported only on top-level rules") {
		t.Fatalf("expected nested project-overlay boundary rejection, got %v", err)
	}
}

func TestMergePolicyOverlaysRejectsOverlayBoundary(t *testing.T) {
	overlay := PolicyOverlay{
		Name: "untrusted-boundary",
		FileRules: []FileRule{{
			Name:                   "move-boundary",
			ProjectOverlayBoundary: true,
			Paths:                  []string{"/x"},
			Operations:             []string{"read"},
			Decision:               "allow",
		}},
	}
	if _, err := MergePolicyOverlays(&Policy{Version: 1, Name: "base"}, []PolicyOverlay{overlay}); err == nil || !strings.Contains(err.Error(), "must not set project_overlay_boundary") {
		t.Fatalf("expected project-overlay boundary rejection, got %v", err)
	}
}

func TestMergePolicyOverlaysRejectsMultipleBaseBoundaries(t *testing.T) {
	base := &Policy{
		Version: 1,
		Name:    "ambiguous",
		FileRules: []FileRule{
			{Name: "first", ProjectOverlayBoundary: true, Paths: []string{"/a"}, Operations: []string{"read"}, Decision: "approve"},
			{Name: "second", ProjectOverlayBoundary: true, Paths: []string{"/b"}, Operations: []string{"read"}, Decision: "approve"},
		},
	}
	overlay := PolicyOverlay{Name: "o", FileRules: []FileRule{{Name: "allow-x", Paths: []string{"/x"}, Operations: []string{"read"}, Decision: "allow"}}}
	if _, err := MergePolicyOverlays(base, []PolicyOverlay{overlay}); err == nil || !strings.Contains(err.Error(), "project_overlay_boundary may appear at most once") {
		t.Fatalf("expected multiple-boundary rejection, got %v", err)
	}
}

func TestMergePolicyOverlaysRejectsBaseNameConflict(t *testing.T) {
	base := &Policy{Version: 1, Name: "base", FileRules: []FileRule{{Name: "same", Paths: []string{"**"}, Operations: []string{"*"}, Decision: "deny"}}}
	overlay := PolicyOverlay{Name: "o", FileRules: []FileRule{{Name: "same", Paths: []string{"/x"}, Operations: []string{"read"}, Decision: "allow"}}}
	if _, err := MergePolicyOverlays(base, []PolicyOverlay{overlay}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected conflict error, got %v", err)
	}
}

func assertRuleOrder(t *testing.T, family string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s rule order = %v, want %v", family, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s rule order = %v, want %v", family, got, want)
		}
	}
}

func assertDecision(t *testing.T, name string, got Decision, wantDecision types.Decision, wantRule string) {
	t.Helper()
	if got.PolicyDecision != wantDecision || got.Rule != wantRule {
		t.Fatalf("%s decision = (%s, %q), want (%s, %q)", name, got.PolicyDecision, got.Rule, wantDecision, wantRule)
	}
}

func writeOverlay(t *testing.T, root, name, content string) {
	t.Helper()
	dir := filepath.Join(root, ".agentsh", "policy-overlays")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
