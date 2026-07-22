package policy

import (
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestCommandRuleCarriesSandboxComposition(t *testing.T) {
	policy := &Policy{
		Version: 1,
		Name:    "composition",
		CommandRules: []CommandRule{{
			Name:               "allow-fpga-shell",
			Commands:           []string{"nix"},
			Decision:           "allow",
			SandboxComposition: "bubblewrap-0.11.2",
		}},
	}
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(policy, true, true)
	if err != nil {
		t.Fatal(err)
	}
	decision := engine.CheckCommand("nix", []string{"develop"})
	if decision.EffectiveDecision != types.DecisionAllow || decision.SandboxComposition != "bubblewrap-0.11.2" {
		t.Fatalf("decision=%+v", decision)
	}
}

func TestProjectOverlayCompositionRequiresExplicitTrustedBoundary(t *testing.T) {
	overlay := PolicyOverlay{
		Name: "fpga",
		CommandRules: []CommandRule{{
			Name:               "fpga-shell",
			Commands:           []string{"nix"},
			Decision:           "allow",
			SandboxComposition: "bubblewrap-0.11.2",
		}},
	}
	base := &Policy{
		Version: 1,
		Name:    "base",
		CommandRules: []CommandRule{{
			Name:     "default-deny-commands",
			Decision: "deny",
		}},
	}
	if _, err := MergePolicyOverlays(base, []PolicyOverlay{overlay}); err == nil {
		t.Fatal("composition overlay unexpectedly accepted without a trusted boundary")
	}

	base.CommandRules = append([]CommandRule{{
		Name:                   "project-composition-boundary",
		ProjectOverlayBoundary: true,
		Commands:               []string{"nix"},
		Decision:               "deny",
	}}, base.CommandRules...)
	merged, err := MergePolicyOverlays(base, []PolicyOverlay{overlay})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(merged, true, true)
	if err != nil {
		t.Fatal(err)
	}
	decision := engine.CheckCommand("nix", []string{"develop"})
	if decision.SandboxComposition != "bubblewrap-0.11.2" || decision.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("overlay composition decision = %+v", decision)
	}
}

func TestCommandRuleCompositionRequiresNormalizedWorkingDirectoryRoot(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "composition-cwd",
		CommandRules: []CommandRule{
			{
				Name:                  "qshell-project",
				Commands:              []string{"bash"},
				ArgsPatterns:          []string{`^-c nix develop \.#ultrascale`},
				WorkingDirectoryRoots: []string{"${PROJECT_ROOT}"},
				Decision:              "allow",
				SandboxComposition:    "bubblewrap-0.11.2",
			},
			{Name: "broad-bash", Commands: []string{"bash"}, Decision: "allow"},
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngineWithVariables(p, true, true, map[string]string{"PROJECT_ROOT": "/scratch/theo/qshell-project"})
	if err != nil {
		t.Fatal(err)
	}
	check := func(name, cwd, wantRule, wantComposition string) {
		t.Helper()
		decision := engine.CheckCommandWithExecveProvenanceContext(
			"bash",
			[]string{"-c", "nix develop .#ultrascale --command true"},
			true,
			ShellCOpaqueEnforce,
			CommandProvenanceNone,
			CommandMatchContext{WorkingDirectory: cwd},
		)
		if decision.Rule != wantRule || decision.SandboxComposition != wantComposition {
			t.Errorf("%s: decision=%+v, want rule=%q composition=%q", name, decision, wantRule, wantComposition)
		}
	}
	check("project root", "/scratch/theo/qshell-project", "qshell-project", "bubblewrap-0.11.2")
	check("project descendant", "/scratch/theo/qshell-project/qshell", "qshell-project", "bubblewrap-0.11.2")
	check("outside", "/scratch/theo/other-project", "broad-bash", "")
	check("relative is not normalized", "qshell", "broad-bash", "")
	check("missing", "", "broad-bash", "")

	// Runtime exec checks have no trusted request cwd and must not activate the
	// request-local composition rule.
	if decision := engine.CheckExecve("bash", []string{"bash", "-c", "nix develop .#ultrascale --command true"}, 0); decision.Rule != "broad-bash" || decision.SandboxComposition != "" {
		t.Fatalf("runtime exec decision=%+v", decision)
	}
}

func TestCommandRuleRejectsInvalidWorkingDirectoryRoots(t *testing.T) {
	for _, root := range []string{"relative", "/scratch/../etc", "/scratch/*"} {
		p := Policy{Version: 1, Name: "bad-cwd", CommandRules: []CommandRule{{Name: "bad", Decision: "allow", WorkingDirectoryRoots: []string{root}}}}
		if err := p.Validate(); err == nil {
			t.Errorf("working directory root %q unexpectedly validated", root)
		}
	}
}

func TestCommandRuleRejectsUnknownSandboxComposition(t *testing.T) {
	policy := Policy{
		Version: 1,
		Name:    "composition",
		CommandRules: []CommandRule{{
			Name:               "bad",
			Decision:           "allow",
			SandboxComposition: "arbitrary-mounts",
		}},
	}
	if err := policy.Validate(); err == nil {
		t.Fatal("expected unknown sandbox composition to be rejected")
	}
}
