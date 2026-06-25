package api

import (
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
)

func TestSessionParentTraversalPaths(t *testing.T) {
	paths := sessionParentTraversalPaths(map[string]string{
		"PROJECT_ROOT": "/mnt/virtiofs/Research/tum/dos/projects/arancini/asplos-26",
		"GIT_ROOT":     "/mnt/virtiofs/Research/tum/dos/projects/arancini/asplos-26",
	})
	want := []string{
		"/",
		"/mnt",
		"/mnt/virtiofs",
		"/mnt/virtiofs/Research",
		"/mnt/virtiofs/Research/tum",
		"/mnt/virtiofs/Research/tum/dos",
		"/mnt/virtiofs/Research/tum/dos/projects",
		"/mnt/virtiofs/Research/tum/dos/projects/arancini",
	}
	if len(paths) != len(want) {
		t.Fatalf("paths = %#v, want %#v", paths, want)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Fatalf("paths = %#v, want %#v", paths, want)
		}
	}
}

func TestWithSessionParentTraversalRulesPrependsMetadataAllow(t *testing.T) {
	p := &policy.Policy{FileRules: []policy.FileRule{{
		Name:       "approve-outside-workspace-reads",
		Paths:      []string{"**"},
		Operations: []string{"read", "open", "stat", "readlink"},
		Decision:   "approve",
	}}}
	out := withSessionParentTraversalRules(p, map[string]string{
		"PROJECT_ROOT": "/mnt/virtiofs/Research/tum/project",
	})
	if out == p {
		t.Fatal("expected policy clone")
	}
	if len(out.FileRules) != 4 {
		t.Fatalf("len(FileRules) = %d", len(out.FileRules))
	}
	contextRule := out.FileRules[0]
	if contextRule.Name != "allow-session-parent-context-files" || contextRule.Decision != "allow" {
		t.Fatalf("unexpected context rule: %#v", contextRule)
	}
	if !containsString(contextRule.Paths, "/mnt/virtiofs/Research/tum/AGENTS.md") {
		t.Fatalf("context paths missing parent AGENTS.md: %#v", contextRule.Paths)
	}
	dirOpenRule := out.FileRules[1]
	if dirOpenRule.Name != "allow-session-parent-directory-open" || dirOpenRule.Decision != "allow" {
		t.Fatalf("unexpected directory-open rule: %#v", dirOpenRule)
	}
	if containsString(dirOpenRule.Paths, "/") {
		t.Fatalf("directory-open rule should not include root: %#v", dirOpenRule.Paths)
	}
	if got, want := dirOpenRule.Operations, []string{"open"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("directory-open operations = %#v, want %#v", got, want)
	}
	rule := out.FileRules[2]
	if rule.Name != "allow-session-parent-path-traversal" || rule.Decision != "allow" {
		t.Fatalf("unexpected traversal rule: %#v", rule)
	}
	if got, want := rule.Operations, []string{"stat", "readlink", "access"}; len(got) != len(want) {
		t.Fatalf("operations = %#v", got)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("operations = %#v, want %#v", got, want)
			}
		}
	}
	if out.FileRules[3].Name != "approve-outside-workspace-reads" {
		t.Fatalf("original rule not preserved after generated rules: %#v", out.FileRules)
	}
}
