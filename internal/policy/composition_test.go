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
