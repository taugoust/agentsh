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

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestSubagentExecutionTimeoutDefaultsAndOverrides(t *testing.T) {
	app := &App{cfg: &config.Config{}}
	got, err := app.subagentExecutionTimeout(nil, 0)
	if err != nil || got != 2*time.Hour {
		t.Fatalf("default timeout = %s, err=%v; want %s", got, err, 2*time.Hour)
	}

	app.cfg.Sessions.Subagents.DefaultTimeout = "45m"
	got, err = app.subagentExecutionTimeout(nil, 0)
	if err != nil || got != 45*time.Minute {
		t.Fatalf("configured fallback timeout = %s, err=%v; want %s", got, err, 45*time.Minute)
	}

	policyDocument, err := policy.LoadFromBytes([]byte("version: 1\nname: subagent-timeout-test\nresource_limits:\n  subagent_timeout: 4h\n"))
	if err != nil {
		t.Fatal(err)
	}
	app.policy, err = policy.NewEngine(policyDocument, false, true)
	if err != nil {
		t.Fatal(err)
	}
	got, err = app.subagentExecutionTimeout(nil, 0)
	if err != nil || got != 4*time.Hour {
		t.Fatalf("policy timeout = %s, err=%v; want %s", got, err, 4*time.Hour)
	}

	got, err = app.subagentExecutionTimeout(nil, 125)
	if err != nil || got != 125*time.Millisecond {
		t.Fatalf("request timeout = %s, err=%v; want %s", got, err, 125*time.Millisecond)
	}

	got, err = app.subagentExecutionTimeout(nil, int64((5*time.Hour)/time.Millisecond))
	if err != nil || got != 4*time.Hour {
		t.Fatalf("request above policy ceiling = %s, err=%v; want %s", got, err, 4*time.Hour)
	}

	if _, err = app.subagentExecutionTimeout(nil, -1); err == nil {
		t.Fatal("negative timeout_ms was accepted")
	}
	if _, err = app.subagentExecutionTimeout(nil, 1<<62); err == nil {
		t.Fatal("overflowing timeout_ms was accepted")
	}
}

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

func TestValidateSpawnSubagentRequestInheritsParentCwd(t *testing.T) {
	original := []subagentItemRequest{
		{Task: "inherited"},
		{Task: "relative", Cwd: "rtl/package"},
		{Task: "absolute", Cwd: "/workspace/other"},
	}
	_, items, err := validateSpawnSubagentRequest(spawnSubagentToolRequest{
		Cwd:   "/workspace/project",
		Tasks: original,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/workspace/project",
		"/workspace/project/rtl/package",
		"/workspace/other",
	}
	for i := range items {
		if items[i].Cwd != want[i] {
			t.Errorf("item %d cwd = %q, want %q", i, items[i].Cwd, want[i])
		}
	}
	if original[0].Cwd != "" || original[1].Cwd != "rtl/package" {
		t.Fatalf("request items were mutated: %+v", original)
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
{"type":"agent_settled"}
`
	if got := parseSubagentFinal("pi-json", stdout); got != "final" {
		t.Fatalf("final = %q, want final", got)
	}
}

func TestCappedBufferRetainsSlidingTail(t *testing.T) {
	var buffer cappedBuffer
	buffer.limit = 5
	_, _ = buffer.Write([]byte("abc"))
	_, _ = buffer.Write([]byte("defg"))
	if got := buffer.String(); got != "cdefg" {
		t.Fatalf("sliding tail = %q, want cdefg", got)
	}
	if !buffer.truncated || buffer.total != 7 {
		t.Fatalf("sliding metadata: truncated=%v total=%d", buffer.truncated, buffer.total)
	}
	_, _ = buffer.Write([]byte("0123456789"))
	if got := buffer.String(); got != "56789" {
		t.Fatalf("oversized write tail = %q, want 56789", got)
	}
	if buffer.total != 17 {
		t.Fatalf("sliding total = %d, want 17", buffer.total)
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
  printf '%s\n' '{"type":"agent_settled"}'
  exit 9
fi
if [ -z "$AGENTSH_CHILD_CAPABILITY" ]; then
  printf '%s\n' '{"type":"message_end","message":{"role":"assistant","content":[],"stopReason":"error","errorMessage":"missing child execution capability"}}'
  printf '%s\n' '{"type":"agent_settled"}'
  exit 10
fi
case "$1" in
  fail)
    printf '%s\n' '{"type":"message_end","message":{"role":"assistant","content":[],"stopReason":"error","errorMessage":"model failed"}}'
    printf '%s\n' '{"type":"agent_settled"}'
    exit 7
    ;;
  timeout)
    trap 'exit 0' TERM
    while :; do sleep 1; done
    ;;
  deadline)
    case "$AGENTSH_SUBAGENT_DEADLINE_EPOCH_MS" in
      ''|*[!0-9]*)
        printf '%s\n' '{"type":"message_end","message":{"role":"assistant","content":[],"stopReason":"error","errorMessage":"missing authoritative deadline"}}'
        printf '%s\n' '{"type":"agent_settled"}'
        exit 8
        ;;
    esac
    printf '%s\n' '{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"deadline present"}],"stopReason":"stop"}}'
    printf '%s\n' '{"type":"agent_settled"}'
    ;;
  large)
    i=0
    while [ "$i" -lt 2200 ]; do
      printf '{"type":"message_update","padding":"%01000d"}\n' 0
      i=$((i + 1))
    done
    printf '%s\n' '{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"complete"}],"stopReason":"stop"}}'
    printf '{"type":"agent_end","messages":"%03000000d"}\n' 0
    printf '%s\n' '{"type":"agent_settled"}'
    ;;
  artifact)
    printf '%s' '{"type":"message_end","message":{"role":"assistant","content":[{"type":"thinking","thinking":"HIDDEN-ARTIFACT-THINKING"},{"type":"text","text":"'
    i=0
    while [ "$i" -lt 5000 ]; do printf 'x'; i=$((i + 1)); done
    printf '%s\n' 'ARTIFACT-TAIL"}],"stopReason":"stop"}}'
    printf '%s\n' '{"type":"agent_settled"}'
    ;;
  *)
    printf '%s\n' '{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"complete"}],"stopReason":"stop"}}'
    printf '%s\n' '{"type":"agent_settled"}'
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
	runtimeHome := filepath.Join(root, "runtime-home")
	runtimeTmp := filepath.Join(root, "runtime-tmp")
	for _, dir := range []string{runtimeHome, runtimeTmp} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sess.SetRuntimePaths(runtimeHome, runtimeTmp, nil)
	if err := sess.ConfigureOutputArtifacts(16 * 1024 * 1024); err != nil {
		t.Fatal(err)
	}
	app := newTestApp(t, sessions, store)
	handler := app.Router()

	for _, tc := range []struct {
		name            string
		body            string
		wantState       string
		wantCause       string
		wantTimeoutMS   int64
		wantChildStates []string
	}{
		{name: "completed", body: `{"task":"complete","systemPrompt":"system-prompt-sentinel","stream":true}`, wantState: "completed", wantTimeoutMS: 7_200_000},
		{name: "child receives deadline", body: `{"task":"deadline","stream":true}`, wantState: "completed", wantTimeoutMS: 7_200_000},
		{name: "large progress retains final", body: `{"task":"large","stream":true}`, wantState: "completed", wantTimeoutMS: 7_200_000},
		{name: "long final gets remote artifact", body: `{"task":"artifact","stream":true,"result_artifact_threshold_bytes":4096}`, wantState: "completed", wantTimeoutMS: 7_200_000},
		{name: "failed task is protocol success", body: `{"task":"fail","stream":true}`, wantState: "failed", wantTimeoutMS: 7_200_000},
		{name: "timeout", body: `{"task":"timeout","stream":true,"timeout_ms":50}`, wantState: "timed_out", wantCause: "request_timeout", wantTimeoutMS: 50, wantChildStates: []string{"timed_out"}},
		{name: "parallel preserves completed sibling on timeout", body: `{"tasks":[{"task":"quick"},{"task":"timeout"}],"stream":true,"timeout_ms":250}`, wantState: "timed_out", wantCause: "request_timeout", wantTimeoutMS: 250, wantChildStates: []string{"completed", "timed_out"}},
		{name: "chain preserves completed step on timeout", body: `{"chain":[{"task":"quick"},{"task":"timeout"}],"stream":true,"timeout_ms":250}`, wantState: "timed_out", wantCause: "request_timeout", wantTimeoutMS: 250, wantChildStates: []string{"completed", "timed_out"}},
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
			var startEvent map[string]any
			var done map[string]any
			for index, event := range events {
				if event["event"] == "subagent_start" {
					startEvent = event
				}
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
			if got, _ := startEvent["timeout_ms"].(float64); int64(got) != tc.wantTimeoutMS {
				t.Fatalf("subagent_start timeout_ms = %v, want %d", startEvent["timeout_ms"], tc.wantTimeoutMS)
			}
			if ok, _ := done["ok"].(bool); !ok {
				t.Fatalf("executed child task must be a protocol success: %#v", done)
			}
			state, cause := terminalStateFromDone(t, done)
			if state != tc.wantState || cause != tc.wantCause {
				t.Fatalf("terminal state=%q cause=%q, want state=%q cause=%q", state, cause, tc.wantState, tc.wantCause)
			}
			if len(tc.wantChildStates) > 0 {
				result := done["result"].(map[string]any)
				children := result["results"].([]any)
				if len(children) != len(tc.wantChildStates) {
					t.Fatalf("child count = %d, want %d: %#v", len(children), len(tc.wantChildStates), children)
				}
				for index, want := range tc.wantChildStates {
					child := children[index].(map[string]any)
					terminal := child["terminal"].(map[string]any)
					if terminal["state"] != want {
						t.Fatalf("child %d terminal state = %v, want %s: %#v", index, terminal["state"], want, child)
					}
				}
			}
			if tc.name == "long final gets remote artifact" {
				result := done["result"].(map[string]any)
				children := result["results"].([]any)
				child := children[0].(map[string]any)
				path, _ := child["full_result_path"].(string)
				if path == "" || child["final_truncated"] != true || child["artifact_complete"] != true {
					t.Fatalf("long final artifact metadata = %#v", child)
				}
				artifact, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.HasSuffix(string(artifact), "ARTIFACT-TAIL") || len(artifact) <= 4096 {
					t.Fatalf("long final artifact content length=%d suffix=%q", len(artifact), string(artifact[max(0, len(artifact)-32):]))
				}
				if strings.Contains(string(artifact), "HIDDEN-ARTIFACT-THINKING") {
					t.Fatal("subagent thinking leaked into remote artifact")
				}
			}
			if tc.name == "large progress retains final" {
				result := done["result"].(map[string]any)
				children, ok := result["results"].([]any)
				if !ok || len(children) != 1 {
					t.Fatalf("large result children = %#v", result["results"])
				}
				child, ok := children[0].(map[string]any)
				if !ok {
					t.Fatalf("large child type = %T", children[0])
				}
				if child["final"] != "complete" || child["protocol_settled"] != true || child["model_stop_reason"] != "stop" {
					t.Fatalf("large child lost final protocol state: %#v", child)
				}
				if child["stdout_truncated"] != true || child["stdout_total_bytes"].(float64) <= float64(maxSubagentTextBytes) {
					t.Fatalf("large child did not report raw ring truncation: %#v", child)
				}
				if _, exists := child["stdout"]; exists {
					t.Fatalf("streamed terminal result duplicated raw stdout: %#v", child)
				}
			}
		})
	}

	t.Run("explicit user cancellation is durable", func(t *testing.T) {
		const requestID = "subagent-request-user-cancel-test"
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/spawn_subagent", strings.NewReader(`{"request_id":"`+requestID+`","task":"timeout","stream":true}`))
		doneServing := make(chan struct{})
		go func() {
			defer close(doneServing)
			handler.ServeHTTP(rr, req)
		}()
		time.Sleep(50 * time.Millisecond)

		cancelRecorder := httptest.NewRecorder()
		cancelRequest := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/spawn_subagent/"+requestID+"/cancel", strings.NewReader(`{"cause":"user_cancelled"}`))
		handler.ServeHTTP(cancelRecorder, cancelRequest)
		if cancelRecorder.Code != http.StatusAccepted {
			t.Fatalf("cancel status=%d body=%s", cancelRecorder.Code, cancelRecorder.Body.String())
		}
		select {
		case <-doneServing:
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for explicitly cancelled stream handler")
		}
		events := decodeSubagentStreamEvents(t, rr.Body.String())
		var done map[string]any
		for _, event := range events {
			if event["event"] == "done" {
				done = event
			}
		}
		if done == nil {
			t.Fatalf("missing done event: %#v", events)
		}
		state, cause := terminalStateFromDone(t, done)
		if state != "cancelled" || cause != "user_cancelled" {
			t.Fatalf("terminal state=%q cause=%q", state, cause)
		}
		persisted, err := store.QueryEvents(context.Background(), types.EventQuery{CommandID: requestID, Types: []string{"tool_spawn_subagent_end"}, Limit: 10})
		if err != nil || len(persisted) != 1 {
			t.Fatalf("durable terminal events=%d err=%v", len(persisted), err)
		}
		if persisted[0].Fields["cancellation_cause"] != string(subagentCancelUser) || persisted[0].Fields["retryable"] != false {
			t.Fatalf("persisted terminal fields=%#v", persisted[0].Fields)
		}
	})

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
