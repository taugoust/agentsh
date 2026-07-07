package api

import (
	"reflect"
	"testing"
)

func TestValidateSpawnSubagentRequestModes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		req     spawnSubagentToolRequest
		wantErr bool
		mode    string
	}{
		{name: "none", req: spawnSubagentToolRequest{}, wantErr: true},
		{name: "single", req: spawnSubagentToolRequest{Task: "summarize"}, mode: "single"},
		{name: "parallel", req: spawnSubagentToolRequest{Tasks: []subagentItemRequest{{Task: "a"}, {Task: "b"}}}, mode: "parallel"},
		{name: "chain", req: spawnSubagentToolRequest{Chain: []subagentItemRequest{{Task: "a"}, {Task: "b"}}}, mode: "chain"},
		{name: "multiple", req: spawnSubagentToolRequest{Task: "x", Tasks: []subagentItemRequest{{Task: "y"}}}, wantErr: true},
		{name: "empty item", req: spawnSubagentToolRequest{Tasks: []subagentItemRequest{{Task: ""}}}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode, _, err := validateSpawnSubagentRequest(tc.req)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if mode != tc.mode {
				t.Fatalf("mode = %q, want %q", mode, tc.mode)
			}
		})
	}
}

func TestValidateSpawnSubagentRequestParallelLimit(t *testing.T) {
	items := make([]subagentItemRequest, maxSubagentParallelTasks+1)
	for i := range items {
		items[i] = subagentItemRequest{Task: "x"}
	}
	_, _, err := validateSpawnSubagentRequest(spawnSubagentToolRequest{Tasks: items})
	if err == nil {
		t.Fatal("expected too many tasks error")
	}
}

func TestSplitCommandArgs(t *testing.T) {
	got, err := splitCommandArgs(`--flag "two words" 'three words' plain\ value`)
	if err != nil {
		t.Fatalf("splitCommandArgs error: %v", err)
	}
	want := []string{"--flag", "two words", "three words", "plain value"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

func TestParsePiJSONFinal(t *testing.T) {
	stdout := `{"type":"message_start","message":{"role":"assistant","content":[{"type":"text","text":"draft"}]}}
{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"final"}]}}
`
	if got := parseSubagentFinal("pi-json", stdout); got != "final" {
		t.Fatalf("final = %q, want final", got)
	}
}

func TestSubagentDepthFromActor(t *testing.T) {
	if got := subagentDepthFromActor(piToolActor{"subagent_depth": float64(2)}); got != 2 {
		t.Fatalf("depth = %d, want 2", got)
	}
	if got := subagentDepthFromActor(piToolActor{"subagent_depth": "3"}); got != 3 {
		t.Fatalf("depth = %d, want 3", got)
	}
}

func TestAppendSubagentTaskArgsPiJSON(t *testing.T) {
	got := appendSubagentTaskArgs([]string{"--mode", "json", "-p"}, subagentItemRequest{
		Task:  "inspect README",
		Model: "test-model",
		Tools: []string{"read", "grep"},
	}, "pi-json", "/tmp/prompt.md")
	want := []string{"--mode", "json", "-p", "--model", "test-model", "--tools", "read,grep", "--append-system-prompt", "/tmp/prompt.md", "inspect README"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

func TestAppendSubagentTaskArgsTextRuntimeStaysGeneric(t *testing.T) {
	got := appendSubagentTaskArgs([]string{"--flag"}, subagentItemRequest{
		Task:  "inspect README",
		Model: "test-model",
		Tools: []string{"read"},
	}, "text", "/tmp/prompt.md")
	want := []string{"--flag", "inspect README"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

func TestWithEnvOverridesReplacesExisting(t *testing.T) {
	got := withEnvOverrides([]string{"A=old", "B=keep", "AGENTSH_TOKEN=secret"}, map[string]string{"A": "new", "C": "add"})
	m := map[string]string{}
	for _, item := range got {
		for i, ch := range item {
			if ch == '=' {
				m[item[:i]] = item[i+1:]
				break
			}
		}
	}
	if m["A"] != "new" || m["B"] != "keep" || m["C"] != "add" {
		t.Fatalf("env overrides not applied: %#v", got)
	}
}
