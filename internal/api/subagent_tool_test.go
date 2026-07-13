package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
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

func TestPrepareSubagentPiDirsSharesAuthRootAndIsolatesSessions(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "auth.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PI_CODING_AGENT_DIR", base)
	s := &session.Session{}

	agentDir1, sessionDir1, err := prepareSubagentPiDirs(s, "subagent-one")
	if err != nil {
		t.Fatalf("prepare first child dirs: %v", err)
	}
	agentDir2, sessionDir2, err := prepareSubagentPiDirs(s, "subagent-two")
	if err != nil {
		t.Fatalf("prepare second child dirs: %v", err)
	}
	if agentDir1 != base || agentDir2 != base {
		t.Fatalf("children must share lifecycle auth/config root: %q, %q; want %q", agentDir1, agentDir2, base)
	}
	if sessionDir1 == sessionDir2 {
		t.Fatalf("children unexpectedly share session state: %q", sessionDir1)
	}
	for _, dir := range []string{sessionDir1, sessionDir2} {
		info, statErr := os.Stat(dir)
		if statErr != nil {
			t.Fatalf("stat child session dir: %v", statErr)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Fatalf("child session dir mode = %o, want 700", got)
		}
	}
	if _, statErr := os.Stat(filepath.Join(base, "subagents", "subagent-one", "agent", "auth.json")); !os.IsNotExist(statErr) {
		t.Fatalf("auth credential was copied into a child-specific path: %v", statErr)
	}
}

func TestPrepareSubagentPiDirsRejectsRelativeAgentDir(t *testing.T) {
	t.Setenv("PI_CODING_AGENT_DIR", "relative/pi-agent")
	if _, _, err := prepareSubagentPiDirs(&session.Session{}, "subagent-one"); err == nil {
		t.Fatal("expected relative Pi agent directory to be rejected")
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

func decodeSubagentStreamEvents(t *testing.T, body string) []map[string]any {
	t.Helper()
	var events []map[string]any
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("decode stream event: %v\n%s", err, scanner.Text())
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan stream: %v", err)
	}
	return events
}

func terminalStateFromDone(t *testing.T, done map[string]any) (string, string) {
	t.Helper()
	result, ok := done["result"].(map[string]any)
	if !ok {
		t.Fatalf("done result type = %T", done["result"])
	}
	terminal, ok := result["terminal"].(map[string]any)
	if !ok {
		t.Fatalf("terminal type = %T", result["terminal"])
	}
	state, _ := terminal["state"].(string)
	cause, _ := terminal["cancellation_cause"].(string)
	return state, cause
}

func TestSubagentStreamEndpointTerminalContract(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh is unavailable")
	}
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	agentDir := filepath.Join(root, "pi-agent")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(agentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(root, "child.sh")
	script := `if [ -n "$AGENTSH_SUBAGENT_SYSTEM_PROMPT" ]; then
  printf '%s\n' '{"type":"message_end","message":{"role":"assistant","content":[],"stopReason":"error","errorMessage":"system prompt leaked through environment"}}'
  exit 9
fi
case "$1" in
  fail)
    printf '%s\n' '{"type":"message_end","message":{"role":"assistant","content":[],"stopReason":"error","errorMessage":"model failed"}}'
    exit 7
    ;;
  timeout)
    trap 'exit 0' TERM
    while :; do sleep 1; done
    ;;
  *)
    printf '%s\n' '{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"complete"}],"stopReason":"stop"}}'
    ;;
esac
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("AGENTSH_SUBAGENT_COMMAND", sh)
	t.Setenv("AGENTSH_SUBAGENT_ARGS", strconv.Quote(scriptPath))
	t.Setenv("AGENTSH_SUBAGENT_TASK_MODE", "arg")
	t.Setenv("AGENTSH_SUBAGENT_PROTOCOL", "pi-json")
	t.Setenv("AGENTSH_SUBAGENT_MAX_DEPTH", "1")
	t.Setenv("PI_CODING_AGENT_DIR", agentDir)

	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	sess, err := sessions.Create(workspace, "default")
	if err != nil {
		t.Fatal(err)
	}
	app := newTestApp(t, sessions, store)
	handler := app.Router()

	for _, tc := range []struct {
		name      string
		body      string
		wantState string
		wantCause string
	}{
		{name: "completed", body: `{"task":"complete","systemPrompt":"system-prompt-sentinel","stream":true}`, wantState: "completed"},
		{name: "failed task is protocol success", body: `{"task":"fail","stream":true}`, wantState: "failed"},
		{name: "timeout", body: `{"task":"timeout","stream":true,"timeout_ms":50}`, wantState: "timed_out", wantCause: "request_timeout"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/spawn_subagent", strings.NewReader(tc.body))
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
			}
			events := decodeSubagentStreamEvents(t, rr.Body.String())
			doneCount := 0
			var done map[string]any
			for index, event := range events {
				if event["event"] == "done" {
					doneCount++
					done = event
					if index != len(events)-1 {
						t.Fatalf("event emitted after done: %#v", events[index+1:])
					}
				}
			}
			if doneCount != 1 {
				t.Fatalf("done count = %d, events=%#v", doneCount, events)
			}
			if ok, _ := done["ok"].(bool); !ok {
				t.Fatalf("executed child task must be a protocol success: %#v", done)
			}
			state, cause := terminalStateFromDone(t, done)
			if state != tc.wantState || cause != tc.wantCause {
				t.Fatalf("terminal state=%q cause=%q, want state=%q cause=%q", state, cause, tc.wantState, tc.wantCause)
			}
		})
	}

	t.Run("client cancellation", func(t *testing.T) {
		rr := httptest.NewRecorder()
		ctx, cancel := context.WithCancel(context.Background())
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/spawn_subagent", strings.NewReader(`{"task":"timeout","stream":true}`)).WithContext(ctx)
		doneServing := make(chan struct{})
		go func() {
			defer close(doneServing)
			handler.ServeHTTP(rr, req)
		}()
		time.Sleep(50 * time.Millisecond)
		cancel()
		select {
		case <-doneServing:
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for cancelled stream handler")
		}
		events := decodeSubagentStreamEvents(t, rr.Body.String())
		var done map[string]any
		for _, event := range events {
			if event["event"] == "done" {
				if done != nil {
					t.Fatalf("duplicate done events: %#v", events)
				}
				done = event
			}
		}
		if done == nil {
			t.Fatalf("missing done event: %#v", events)
		}
		state, cause := terminalStateFromDone(t, done)
		if state != "cancelled" || cause != "client_disconnected" {
			t.Fatalf("terminal state=%q cause=%q", state, cause)
		}
	})
}
