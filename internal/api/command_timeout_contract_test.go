package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/commandtimeout"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestCommandTimeoutSessionCreateGetListMetadata(t *testing.T) {
	sqliteStore := newSQLiteStore(t)
	store := composite.New(sqliteStore, sqliteStore)
	manager := session.NewManager(10)
	app := newTestApp(t, manager, store)
	engine := commandTimeoutTestEngine(t, 4*time.Hour+500*time.Microsecond)
	app.SwapPolicy(engine)

	created, code, err := app.createSessionCore(context.Background(), types.CreateSessionRequest{Workspace: t.TempDir()})
	if err != nil || code != http.StatusCreated {
		t.Fatalf("createSessionCore = code %d err %v", code, err)
	}
	assertPolicySessionTimeout(t, created.CommandTimeout, 4*time.Hour+500*time.Microsecond)

	for name, path := range map[string]string{
		"get":  "/api/v1/sessions/" + created.ID,
		"list": "/api/v1/sessions",
	} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			app.Router().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
			}
			var snapshot types.Session
			if name == "list" {
				var snapshots []types.Session
				if err := json.NewDecoder(recorder.Body).Decode(&snapshots); err != nil || len(snapshots) != 1 {
					t.Fatalf("decode list = %d snapshots, err %v", len(snapshots), err)
				}
				snapshot = snapshots[0]
			} else if err := json.NewDecoder(recorder.Body).Decode(&snapshot); err != nil {
				t.Fatalf("decode get: %v", err)
			}
			assertPolicySessionTimeout(t, snapshot.CommandTimeout, 4*time.Hour+500*time.Microsecond)
			encoded, _ := json.Marshal(snapshot)
			if strings.Contains(string(encoded), "resource_limits") || strings.Contains(string(encoded), "session_timeout") {
				t.Fatalf("session snapshot leaked unrelated policy data: %s", encoded)
			}
		})
	}
}

func TestCommandTimeoutSessionReportsBoundedApprovalAllowance(t *testing.T) {
	app, sess, _ := newCommandTimeoutTestApp(t, time.Second)
	app.approvals = approvals.New("api", 275*time.Millisecond+time.Nanosecond, nil)
	metadata := app.sessionSnapshot(sess).CommandTimeout
	if metadata.ApprovalExtensionMS != 276 {
		t.Fatalf("session approval_extension_ms = %d, want 276", metadata.ApprovalExtensionMS)
	}
}

func TestCommandTimeoutSessionFallbackHasNoMaximum(t *testing.T) {
	manager := session.NewManager(1)
	sess, err := manager.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}
	metadata := sess.Snapshot().CommandTimeout
	if metadata.DefaultMS != defaultCommandTimeout.Milliseconds() || metadata.MaximumMS != nil || metadata.Source != types.SessionCommandTimeoutSourceFallback {
		t.Fatalf("fallback metadata = %+v", metadata)
	}
	encoded, _ := json.Marshal(sess.Snapshot())
	if strings.Contains(string(encoded), "maximum_ms") {
		t.Fatalf("fallback snapshot emitted a maximum: %s", encoded)
	}
}

func TestCommandTimeoutExecBashTopLevelMetadataAndValidation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("exec_bash requires bash")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is unavailable")
	}
	app, sess, store := newCommandTimeoutTestApp(t, 2*time.Second+500*time.Microsecond)

	recorder := httptest.NewRecorder()
	body := `{"command":"printf ok","timeout_ms":4000}`
	app.Router().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/exec_bash", strings.NewReader(body)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("exec_bash status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		OK     bool `json:"ok"`
		Result struct {
			ExitCode       int                  `json:"exit_code"`
			CommandTimeout types.CommandTimeout `json:"command_timeout"`
			ExecResponse   types.ExecResponse   `json:"exec_response"`
		} `json:"result"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.Result.ExitCode != 0 {
		t.Fatalf("exec_bash response = %+v", response)
	}
	assertCommandTimeoutMetadata(t, response.Result.CommandTimeout, 4000, 2001, types.CommandTimeoutSourcePolicyCap)
	if !equalCommandTimeout(response.Result.ExecResponse.Result.CommandTimeout, response.Result.CommandTimeout) {
		t.Fatalf("top-level metadata differs from ExecResult: top=%+v nested=%+v", response.Result.CommandTimeout, response.Result.ExecResponse.Result.CommandTimeout)
	}

	before := countCommandLifecycleEvents(t, store, sess.ID)
	for name, invalidBody := range map[string]string{
		"zero":     `{"command":"true","timeout_ms":0}`,
		"negative": `{"command":"true","timeout_ms":-1}`,
		"overflow": `{"command":"true","timeout_ms":9223372036854775807}`,
	} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			app.Router().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/exec_bash", strings.NewReader(invalidBody)))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
	if after := countCommandLifecycleEvents(t, store, sess.ID); after != before {
		t.Fatalf("invalid exec_bash requests emitted lifecycle events: before=%d after=%d", before, after)
	}
}

func TestCommandTimeoutPostResolutionRefusalsPreserveMetadata(t *testing.T) {
	app, sess, _ := newCommandTimeoutTestApp(t, 750*time.Millisecond)
	app.commandBoundarySetupErrorForTest = errors.New("forced boundary setup refusal")

	metadataByTransport := make(map[string]types.CommandTimeout)
	assertRefusal := func(t *testing.T, outcome *types.ExecOutcome, terminationReason string) {
		t.Helper()
		if outcome == nil || outcome.CommandStarted || outcome.FailureKind != types.ExecFailurePreExec || outcome.Code != "E_PRE_EXEC_BOUNDARY" {
			t.Fatalf("outcome = %+v, want pre-exec boundary refusal", outcome)
		}
		if terminationReason != "" {
			t.Fatalf("refusal termination_reason = %q, want empty", terminationReason)
		}
	}

	t.Run("buffered REST", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		body := `{"command":"true","timeout":"900ms"}`
		app.Router().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/exec", strings.NewReader(body)))
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
		}
		var response types.ExecResponse
		if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
			t.Fatal(err)
		}
		assertRefusal(t, response.Result.Outcome, response.Result.TerminationReason)
		metadataByTransport["buffered REST"] = response.Result.CommandTimeout
	})

	t.Run("exec_bash", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		body := `{"command":"true","timeout_ms":900}`
		app.Router().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/tools/exec_bash", strings.NewReader(body)))
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
		}
		var response struct {
			OK     bool `json:"ok"`
			Result struct {
				CommandTimeout    types.CommandTimeout `json:"command_timeout"`
				ExecResponse      types.ExecResponse   `json:"exec_response"`
				Outcome           *types.ExecOutcome   `json:"outcome"`
				TerminationReason string               `json:"termination_reason"`
			} `json:"result"`
		}
		if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
			t.Fatal(err)
		}
		if response.OK {
			t.Fatalf("exec_bash refusal reported ok: %+v", response)
		}
		assertRefusal(t, response.Result.Outcome, response.Result.TerminationReason)
		if !equalCommandTimeout(response.Result.CommandTimeout, response.Result.ExecResponse.Result.CommandTimeout) {
			t.Fatalf("exec_bash timeout metadata differs: top=%+v nested=%+v", response.Result.CommandTimeout, response.Result.ExecResponse.Result.CommandTimeout)
		}
		metadataByTransport["exec_bash"] = response.Result.CommandTimeout
	})

	t.Run("SSE endpoint", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		body := `{"command":"true","timeout":"900ms"}`
		app.Router().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/exec/stream", strings.NewReader(body)))
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
		}
		var response struct {
			CommandTimeout    types.CommandTimeout `json:"command_timeout"`
			Outcome           *types.ExecOutcome   `json:"outcome"`
			TerminationReason string               `json:"termination_reason"`
		}
		if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
			t.Fatal(err)
		}
		assertRefusal(t, response.Outcome, response.TerminationReason)
		metadataByTransport["SSE endpoint"] = response.CommandTimeout
	})

	t.Run("gRPC stream", func(t *testing.T) {
		request, err := structpb.NewStruct(map[string]any{"session_id": sess.ID, "command": "true", "timeout": "900ms"})
		if err != nil {
			t.Fatal(err)
		}
		stream := &commandTimeoutCaptureStream{ctx: context.Background()}
		execErr := (&grpcServer{app: app}).ExecStream(request, stream)
		if status.Code(execErr) != codes.FailedPrecondition {
			t.Fatalf("ExecStream error = %v", execErr)
		}
		refused := stream.event("refused")
		if refused == nil || stream.event("start") != nil || stream.event("done") != nil {
			t.Fatalf("gRPC refusal events = %#v", stream.messages)
		}
		outcomeWire, _ := json.Marshal(refused["outcome"])
		var outcome types.ExecOutcome
		if err := json.Unmarshal(outcomeWire, &outcome); err != nil {
			t.Fatal(err)
		}
		assertRefusal(t, &outcome, "")
		metadataByTransport["gRPC stream"] = decodeCommandTimeout(t, refused["command_timeout"])
	})

	t.Run("gRPC policy refusal", func(t *testing.T) {
		denyEngine := commandTimeoutPolicySnapshotEngine(t, "deny-refusal", "deny", 750*time.Millisecond, false)
		sess.SetPolicyEngine(denyEngine)
		app.SwapPolicy(denyEngine)
		app.commandBoundarySetupErrorForTest = nil

		request, err := structpb.NewStruct(map[string]any{"session_id": sess.ID, "command": "true", "timeout": "900ms"})
		if err != nil {
			t.Fatal(err)
		}
		stream := &commandTimeoutCaptureStream{ctx: context.Background()}
		execErr := (&grpcServer{app: app}).ExecStream(request, stream)
		if status.Code(execErr) != codes.PermissionDenied {
			t.Fatalf("ExecStream error = %v", execErr)
		}
		refused := stream.event("refused")
		if refused == nil || stream.event("start") != nil || stream.event("done") != nil {
			t.Fatalf("gRPC policy refusal events = %#v", stream.messages)
		}
		outcome, ok := refused["outcome"].(map[string]any)
		if !ok || outcome["failure_kind"] != string(types.ExecFailureDenied) || outcome["code"] != "E_POLICY_DENIED" {
			t.Fatalf("gRPC policy refusal outcome = %#v", refused["outcome"])
		}
		metadataByTransport["gRPC policy refusal"] = decodeCommandTimeout(t, refused["command_timeout"])
	})

	var baseline types.CommandTimeout
	for transport, metadata := range metadataByTransport {
		assertCommandTimeoutMetadata(t, metadata, 900, 750, types.CommandTimeoutSourcePolicyCap)
		if baseline.Source == "" {
			baseline = metadata
		} else if !equalCommandTimeout(metadata, baseline) {
			t.Fatalf("%s timeout metadata = %+v, want %+v", transport, metadata, baseline)
		}
	}
}

func TestCommandTimeoutBufferedTypedTerminationAndNatural124(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture requires POSIX")
	}
	app, sess, store := newCommandTimeoutTestApp(t, 500*time.Millisecond)

	response, code, err := app.execInSessionCore(context.Background(), sess.ID, types.ExecRequest{
		Command: "sh", Args: []string{"-c", "sleep 2"}, Timeout: "80.5ms",
	})
	if err != nil || code != http.StatusOK {
		t.Fatalf("exec = code %d err %v", code, err)
	}
	if response.Result.ExitCode != 124 || response.Result.TerminationReason != types.TerminationReasonCommandTimeout {
		t.Fatalf("timeout result = %+v", response.Result)
	}
	if response.Result.Error == nil || response.Result.Error.Code != "E_COMMAND_TIMEOUT" {
		t.Fatalf("timeout error = %+v", response.Result.Error)
	}
	assertCommandTimeoutMetadata(t, response.Result.CommandTimeout, 81, 81, types.CommandTimeoutSourceExplicit)
	assertLifecycleTimeoutMetadata(t, store, response.CommandID, response.Result.CommandTimeout, types.TerminationReasonCommandTimeout)

	natural, _, err := app.execInSessionCore(context.Background(), sess.ID, types.ExecRequest{
		Command: "sh", Args: []string{"-c", "exit 124"}, Timeout: "300ms",
	})
	if err != nil {
		t.Fatal(err)
	}
	if natural.Result.ExitCode != 124 || natural.Result.TerminationReason != "" || natural.Result.Error != nil {
		t.Fatalf("natural exit 124 was inferred as timeout: %+v", natural.Result)
	}
}

func TestCommandTimeoutBufferedCallerDeadlineIsDistinct(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture requires POSIX")
	}
	app, sess, store := newCommandTimeoutTestApp(t, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	response, code, err := app.execInSessionCore(ctx, sess.ID, types.ExecRequest{
		Command: "sh", Args: []string{"-c", "sleep 2"}, Timeout: "1s",
	})
	if err != nil || code != http.StatusOK {
		t.Fatalf("exec = code %d err %v", code, err)
	}
	if response.Result.ExitCode == 124 || response.Result.TerminationReason != types.TerminationReasonCallerDeadline {
		t.Fatalf("caller deadline result = %+v", response.Result)
	}
	if response.Result.Error == nil || response.Result.Error.Code == "E_COMMAND_TIMEOUT" {
		t.Fatalf("caller deadline error = %+v", response.Result.Error)
	}
	assertLifecycleTimeoutMetadata(t, store, response.CommandID, response.Result.CommandTimeout, types.TerminationReasonCallerDeadline)
	assertCommandOutputPersisted(t, store, response.CommandID)
}

func TestCommandTimeoutHTTPStreamStartDoneParity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture requires POSIX")
	}
	app, sess, store := newCommandTimeoutTestApp(t, 500*time.Millisecond)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/exec/stream", strings.NewReader(`{"command":"sh","args":["-c","sleep 2"],"timeout":"80.5ms"}`))
	app.Router().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("stream status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	events := decodeSSEEvents(t, recorder.Body.String())
	start := events["start"]
	done := events["done"]
	if start == nil || done == nil {
		t.Fatalf("stream events missing start/done: %s", recorder.Body.String())
	}
	startTimeout := decodeCommandTimeout(t, start["command_timeout"])
	doneTimeout := decodeCommandTimeout(t, done["command_timeout"])
	assertCommandTimeoutMetadata(t, startTimeout, 81, 81, types.CommandTimeoutSourceExplicit)
	if !equalCommandTimeout(doneTimeout, startTimeout) {
		t.Fatalf("stream timeout metadata differs: start=%+v done=%+v", startTimeout, doneTimeout)
	}
	if int(done["exit_code"].(float64)) != 124 || done["termination_reason"] != types.TerminationReasonCommandTimeout {
		t.Fatalf("stream done = %#v", done)
	}
	typedError, ok := done["error"].(map[string]any)
	if !ok || typedError["code"] != "E_COMMAND_TIMEOUT" {
		t.Fatalf("stream error = %#v", done["error"])
	}
	commandID, _ := start["command_id"].(string)
	assertLifecycleTimeoutMetadata(t, store, commandID, startTimeout, types.TerminationReasonCommandTimeout)
}

func TestCommandTimeoutHTTPStreamCallerDeadlinePersistsTerminalState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture requires POSIX")
	}
	app, sess, store := newCommandTimeoutTestApp(t, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/exec/stream", strings.NewReader(`{"command":"sh","args":["-c","sleep 2"],"timeout":"1s"}`)).WithContext(ctx)
	app.Router().ServeHTTP(recorder, request)

	events := decodeSSEEvents(t, recorder.Body.String())
	start := events["start"]
	done := events["done"]
	if start == nil || done == nil || done["termination_reason"] != types.TerminationReasonCallerDeadline {
		t.Fatalf("caller-deadline stream events = %#v", events)
	}
	commandID, _ := start["command_id"].(string)
	timeout := decodeCommandTimeout(t, start["command_timeout"])
	assertLifecycleTimeoutMetadata(t, store, commandID, timeout, types.TerminationReasonCallerDeadline)
	assertCommandOutputPersisted(t, store, commandID)
}

func TestCommandTimeoutGRPCStreamStartDoneParity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture requires POSIX")
	}
	app, sess, _ := newCommandTimeoutTestApp(t, 500*time.Millisecond)
	request, err := structpb.NewStruct(map[string]any{
		"session_id": sess.ID,
		"command":    "sh",
		"args":       []any{"-c", "sleep 2"},
		"timeout":    "80.5ms",
	})
	if err != nil {
		t.Fatal(err)
	}
	stream := &commandTimeoutCaptureStream{ctx: context.Background()}
	if err := (&grpcServer{app: app}).ExecStream(request, stream); err != nil {
		t.Fatalf("ExecStream: %v", err)
	}
	start := stream.event("start")
	done := stream.event("done")
	if start == nil || done == nil {
		t.Fatalf("gRPC stream missing start/done: %#v", stream.messages)
	}
	startTimeout := decodeCommandTimeout(t, start["command_timeout"])
	doneTimeout := decodeCommandTimeout(t, done["command_timeout"])
	assertCommandTimeoutMetadata(t, startTimeout, 81, 81, types.CommandTimeoutSourceExplicit)
	if !equalCommandTimeout(doneTimeout, startTimeout) || done["termination_reason"] != types.TerminationReasonCommandTimeout {
		t.Fatalf("gRPC stream parity mismatch: start=%#v done=%#v", start, done)
	}
	typedError, ok := done["error"].(map[string]any)
	if !ok || typedError["code"] != "E_COMMAND_TIMEOUT" {
		t.Fatalf("gRPC stream error = %#v", done["error"])
	}
}

func TestCommandTimeoutPolicyResolutionOccursAfterExecutionAdmission(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("command fixture requires POSIX")
	}
	if _, err := exec.LookPath("env"); err != nil {
		t.Skip("env is unavailable")
	}
	fixture := newCommandTimeoutPolicySnapshotFixture(t)
	admitted := make(chan struct{})
	proceed := make(chan struct{})
	result := make(chan *types.ExecResponse, 1)
	errs := make(chan error, 1)
	go func() {
		response, _, err := fixture.app.execInSessionCoreWithOptions(context.Background(), fixture.session.ID, fixture.request(), internalExecOptions{
			onAdmitted: func() {
				close(admitted)
				<-proceed
			},
		})
		result <- response
		errs <- err
	}()

	select {
	case <-admitted:
	case <-time.After(time.Second):
		t.Fatal("command was not admitted")
	}
	fixture.app.SwapPolicy(fixture.replacement)
	close(proceed)
	response := <-result
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if response == nil {
		t.Fatal("nil response")
	}
	assertCommandTimeoutMetadata(t, response.Result.CommandTimeout, 500, 50, types.CommandTimeoutSourcePolicyCap)
}

func TestCommandTimeoutPolicySnapshotIsSharedByLimitsAndBothChecks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture requires POSIX")
	}
	if _, err := exec.LookPath("env"); err != nil {
		t.Skip("env is unavailable")
	}

	t.Run("buffered REST core", func(t *testing.T) {
		fixture := newCommandTimeoutPolicySnapshotFixture(t)
		result := make(chan *types.ExecResponse, 1)
		errs := make(chan error, 1)
		go func() {
			response, _, err := fixture.app.execInSessionCore(context.Background(), fixture.session.ID, fixture.request())
			result <- response
			errs <- err
		}()

		fixture.swapWhileApprovalIsPending(t)
		response := <-result
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
		if response == nil {
			t.Fatal("nil buffered response")
		}
		assertCommandTimeoutMetadata(t, response.Result.CommandTimeout, 500, 500, types.CommandTimeoutSourceExplicit)
		if strings.Contains(response.Result.Stdout, "snapshot-marker-visible") {
			t.Fatalf("replacement policy leaked into second check; stdout = %q", response.Result.Stdout)
		}
	})

	t.Run("HTTP streaming", func(t *testing.T) {
		fixture := newCommandTimeoutPolicySnapshotFixture(t)
		body, err := json.Marshal(fixture.request())
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+fixture.session.ID+"/exec/stream", strings.NewReader(string(body)))
		done := make(chan struct{})
		go func() {
			fixture.app.Router().ServeHTTP(recorder, request)
			close(done)
		}()

		fixture.swapWhileApprovalIsPending(t)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("HTTP stream did not finish")
		}
		if recorder.Code != http.StatusOK {
			t.Fatalf("HTTP stream status = %d body=%s", recorder.Code, recorder.Body.String())
		}
		events := decodeSSEEvents(t, recorder.Body.String())
		start := events["start"]
		if start == nil {
			t.Fatalf("missing stream start event: %s", recorder.Body.String())
		}
		assertCommandTimeoutMetadata(t, decodeCommandTimeout(t, start["command_timeout"]), 500, 500, types.CommandTimeoutSourceExplicit)
		if strings.Contains(recorder.Body.String(), "snapshot-marker-visible") {
			t.Fatalf("replacement policy leaked into HTTP second check: %s", recorder.Body.String())
		}
	})

	t.Run("gRPC streaming", func(t *testing.T) {
		fixture := newCommandTimeoutPolicySnapshotFixture(t)
		request, err := structpb.NewStruct(map[string]any{
			"session_id": fixture.session.ID,
			"command":    fixture.command,
			"timeout":    "500ms",
			"env":        map[string]any{"SNAPSHOT_MARKER": "snapshot-marker-visible"},
		})
		if err != nil {
			t.Fatal(err)
		}
		stream := &commandTimeoutCaptureStream{ctx: context.Background()}
		done := make(chan error, 1)
		go func() { done <- (&grpcServer{app: fixture.app}).ExecStream(request, stream) }()

		fixture.swapWhileApprovalIsPending(t)
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("ExecStream: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("gRPC stream did not finish")
		}
		start := stream.event("start")
		if start == nil {
			t.Fatalf("missing gRPC start event: %#v", stream.messages)
		}
		assertCommandTimeoutMetadata(t, decodeCommandTimeout(t, start["command_timeout"]), 500, 500, types.CommandTimeoutSourceExplicit)
		encoded, _ := json.Marshal(stream.messages)
		if strings.Contains(string(encoded), "snapshot-marker-visible") {
			t.Fatalf("replacement policy leaked into gRPC second check: %s", encoded)
		}
	})
}

func TestCommandTimeoutGRPCStreamCallerDeadlinePersistsTerminalState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture requires POSIX")
	}
	app, sess, store := newCommandTimeoutTestApp(t, 2*time.Second)
	request, err := structpb.NewStruct(map[string]any{
		"session_id": sess.ID,
		"command":    "sh",
		"args":       []any{"-c", "sleep 2"},
		"timeout":    "1s",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	stream := &commandTimeoutCaptureStream{ctx: ctx}
	if err := (&grpcServer{app: app}).ExecStream(request, stream); err != nil {
		t.Fatalf("ExecStream: %v", err)
	}
	start := stream.event("start")
	done := stream.event("done")
	if start == nil || done == nil || done["termination_reason"] != types.TerminationReasonCallerDeadline {
		t.Fatalf("caller-deadline gRPC events = %#v", stream.messages)
	}
	commandID, _ := start["command_id"].(string)
	timeout := decodeCommandTimeout(t, start["command_timeout"])
	assertLifecycleTimeoutMetadata(t, store, commandID, timeout, types.TerminationReasonCallerDeadline)
	assertCommandOutputPersisted(t, store, commandID)
}

func TestCommandTimeoutWireEmptyIsCompatibleOmission(t *testing.T) {
	app, sess, _ := newCommandTimeoutTestApp(t, time.Second)

	recorder := httptest.NewRecorder()
	app.Router().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/exec", strings.NewReader(`{"command":"pwd","timeout":""}`)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("REST empty timeout status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var restResponse types.ExecResponse
	if err := json.NewDecoder(recorder.Body).Decode(&restResponse); err != nil {
		t.Fatal(err)
	}
	assertOmittedCommandTimeoutMetadata(t, restResponse.Result.CommandTimeout, time.Second)

	grpcBody, _ := json.Marshal(map[string]any{"session_id": sess.ID, "command": "pwd", "timeout": ""})
	grpcResponse, err := app.grpcExec(context.Background(), grpcBody)
	if err != nil {
		t.Fatalf("gRPC empty timeout: %v", err)
	}
	var decodedGRPCResponse types.ExecResponse
	if err := json.Unmarshal(mustProtoJSON(grpcResponse), &decodedGRPCResponse); err != nil {
		t.Fatal(err)
	}
	assertOmittedCommandTimeoutMetadata(t, decodedGRPCResponse.Result.CommandTimeout, time.Second)
}

func TestCommandTimeoutWireValidationBeforeLifecycle(t *testing.T) {
	app, sess, store := newCommandTimeoutTestApp(t, time.Second)
	invalid := []string{"bad", "0s", "-1ms", "500us", "0.5ms"}
	for _, value := range invalid {
		body, _ := json.Marshal(map[string]any{"command": "true", "timeout": value})
		recorder := httptest.NewRecorder()
		app.Router().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/exec", strings.NewReader(string(body))))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("REST timeout %q status = %d body=%s", value, recorder.Code, recorder.Body.String())
		}

		grpcBody, _ := json.Marshal(map[string]any{"session_id": sess.ID, "command": "true", "timeout": value})
		if _, err := app.grpcExec(context.Background(), grpcBody); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("gRPC timeout %q error = %v", value, err)
		}
	}

	streamRequest, err := structpb.NewStruct(map[string]any{"session_id": sess.ID, "command": "true", "timeout": "500us"})
	if err != nil {
		t.Fatal(err)
	}
	streamErr := (&grpcServer{app: app}).ExecStream(streamRequest, &captureServerStream{ctx: context.Background()})
	if status.Code(streamErr) != codes.InvalidArgument {
		t.Fatalf("gRPC stream invalid timeout error = %v", streamErr)
	}
	if got := countCommandLifecycleEvents(t, store, sess.ID); got != 0 {
		t.Fatalf("invalid wire requests emitted %d command lifecycle events", got)
	}
}

type commandTimeoutPolicySnapshotFixture struct {
	app         *App
	session     *session.Session
	approvals   *approvals.Manager
	replacement *policy.Engine
	command     string
}

func newCommandTimeoutPolicySnapshotFixture(t *testing.T) commandTimeoutPolicySnapshotFixture {
	t.Helper()
	manager := session.NewManager(2)
	sess, err := manager.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}
	sqliteStore := newSQLiteStore(t)
	store := composite.New(sqliteStore, sqliteStore)
	app := newTestApp(t, manager, store)
	command, err := exec.LookPath("env")
	if err != nil {
		t.Fatal(err)
	}
	approvalManager := approvals.New("api", 2*time.Second, nil)
	app.approvals = approvalManager
	app.SwapPolicy(commandTimeoutPolicySnapshotEngine(t, "admitted", "approve", time.Second, true))
	return commandTimeoutPolicySnapshotFixture{
		app:         app,
		session:     sess,
		approvals:   approvalManager,
		replacement: commandTimeoutPolicySnapshotEngine(t, "replacement", "allow", 50*time.Millisecond, false),
		command:     command,
	}
}

func (f commandTimeoutPolicySnapshotFixture) swapWhileApprovalIsPending(t *testing.T) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		pending := f.approvals.ListPending()
		if len(pending) > 0 {
			f.app.SwapPolicy(f.replacement)
			if !f.approvals.Resolve(pending[0].ID, true, "approved") {
				t.Fatal("approval was no longer pending")
			}
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("command did not request approval")
		case <-ticker.C:
		}
	}
}

func (f commandTimeoutPolicySnapshotFixture) request() types.ExecRequest {
	return types.ExecRequest{
		Command: f.command,
		Timeout: "500ms",
		Env:     map[string]string{"SNAPSHOT_MARKER": "snapshot-marker-visible"},
	}
}

func commandTimeoutPolicySnapshotEngine(t *testing.T, name, decision string, limit time.Duration, denyMarker bool) *policy.Engine {
	t.Helper()
	envPolicy := ""
	if denyMarker {
		envPolicy = "    env_deny: [\"SNAPSHOT_MARKER\"]\n"
	}
	document := []byte("version: 1\nname: " + name + "\ncommand_rules:\n  - name: " + name + "\n    commands: [\"*\"]\n    decision: " + decision + "\n" + envPolicy + "resource_limits:\n  command_timeout: " + limit.String() + "\n")
	loaded, err := policy.LoadFromBytes(document)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := policy.NewEngine(loaded, true, true)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func commandTimeoutTestEngine(t *testing.T, limit time.Duration) *policy.Engine {
	t.Helper()
	document := []byte("version: 1\nname: command-timeout-test\ncommand_rules:\n  - name: allow-all\n    commands: [\"*\"]\n    decision: allow\nresource_limits:\n  command_timeout: " + limit.String() + "\n")
	loaded, err := policy.LoadFromBytes(document)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := policy.NewEngine(loaded, false, true)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func newCommandTimeoutTestApp(t *testing.T, limit time.Duration) (*App, *session.Session, *composite.Store) {
	t.Helper()
	manager := session.NewManager(5)
	workspace := t.TempDir()
	sess, err := manager.Create(workspace, "default")
	if err != nil {
		t.Fatal(err)
	}
	engine := commandTimeoutTestEngine(t, limit)
	sess.SetPolicyEngine(engine)
	sqliteStore := newSQLiteStore(t)
	store := composite.New(sqliteStore, sqliteStore)
	app := newTestApp(t, manager, store)
	app.SwapPolicy(engine)
	return app, sess, store
}

func assertPolicySessionTimeout(t *testing.T, metadata types.SessionCommandTimeout, duration time.Duration) {
	t.Helper()
	milliseconds := commandtimeout.CeilMilliseconds(duration)
	if metadata.DefaultMS != milliseconds || metadata.MaximumMS == nil || *metadata.MaximumMS != milliseconds || metadata.Source != types.SessionCommandTimeoutSourcePolicy {
		t.Fatalf("session command_timeout = %+v, want policy %dms", metadata, milliseconds)
	}
}

func assertCommandTimeoutMetadata(t *testing.T, metadata types.CommandTimeout, requested, effective int64, source types.CommandTimeoutSource) {
	t.Helper()
	if metadata.RequestedMS == nil || *metadata.RequestedMS != requested || metadata.EffectiveMS != effective || metadata.Source != source {
		t.Fatalf("command_timeout = %+v, want requested=%d effective=%d source=%q", metadata, requested, effective, source)
	}
}

func assertOmittedCommandTimeoutMetadata(t *testing.T, metadata types.CommandTimeout, effective time.Duration) {
	t.Helper()
	if metadata.RequestedMS != nil || metadata.EffectiveMS != commandtimeout.CeilMilliseconds(effective) || metadata.Source != types.CommandTimeoutSourcePolicyDefault {
		t.Fatalf("command_timeout = %+v, want omitted policy default %s", metadata, effective)
	}
}

func countCommandLifecycleEvents(t *testing.T, store *composite.Store, sessionID string) int {
	t.Helper()
	events, err := store.QueryEvents(context.Background(), types.EventQuery{SessionID: sessionID, Limit: 500, Asc: true})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range events {
		if event.Type == "command_started" || event.Type == "command_finished" || event.Type == "command_policy" {
			count++
		}
	}
	return count
}

func assertCommandOutputPersisted(t *testing.T, store *composite.Store, commandID string) {
	t.Helper()
	if _, _, _, err := store.ReadOutputChunk(context.Background(), commandID, "stdout", 0, 1); err != nil {
		t.Fatalf("command output %s was not persisted: %v", commandID, err)
	}
}

func assertLifecycleTimeoutMetadata(t *testing.T, store *composite.Store, commandID string, timeout types.CommandTimeout, reason string) {
	t.Helper()
	events, err := store.QueryEvents(context.Background(), types.EventQuery{CommandID: commandID, Limit: 100, Asc: true})
	if err != nil {
		t.Fatal(err)
	}
	var started, finished *types.Event
	for i := range events {
		switch events[i].Type {
		case "command_started":
			started = &events[i]
		case "command_finished":
			finished = &events[i]
		}
	}
	if started == nil || finished == nil || started.CommandTimeout == nil || finished.CommandTimeout == nil {
		t.Fatalf("lifecycle timeout metadata missing: %#v", events)
	}
	if !equalCommandTimeout(*started.CommandTimeout, timeout) || !equalCommandTimeout(*finished.CommandTimeout, timeout) || finished.TerminationReason != reason {
		t.Fatalf("lifecycle metadata mismatch: start=%+v finish=%+v", started, finished)
	}
}

func equalCommandTimeout(left, right types.CommandTimeout) bool {
	return left.EffectiveMS == right.EffectiveMS &&
		left.ApprovalExtensionMS == right.ApprovalExtensionMS &&
		left.Source == right.Source &&
		equalInt64Pointers(left.RequestedMS, right.RequestedMS)
}

func decodeSSEEvents(t *testing.T, body string) map[string]map[string]any {
	t.Helper()
	result := make(map[string]map[string]any)
	for _, frame := range strings.Split(body, "\n\n") {
		var eventName, data string
		for _, line := range strings.Split(frame, "\n") {
			if strings.HasPrefix(line, "event: ") {
				eventName = strings.TrimPrefix(line, "event: ")
			}
			if strings.HasPrefix(line, "data: ") {
				data = strings.TrimPrefix(line, "data: ")
			}
		}
		if eventName == "" || data == "" {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(data), &payload); err != nil {
			t.Fatalf("decode %s event: %v", eventName, err)
		}
		result[eventName] = payload
	}
	return result
}

type commandTimeoutCaptureStream struct {
	ctx      context.Context
	messages []map[string]any
}

func (s *commandTimeoutCaptureStream) SetHeader(metadata.MD) error  { return nil }
func (s *commandTimeoutCaptureStream) SendHeader(metadata.MD) error { return nil }
func (s *commandTimeoutCaptureStream) SetTrailer(metadata.MD)       {}
func (s *commandTimeoutCaptureStream) Context() context.Context     { return s.ctx }
func (s *commandTimeoutCaptureStream) SendMsg(message any) error {
	encoded, err := json.Marshal(message)
	if err != nil {
		return err
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		return err
	}
	s.messages = append(s.messages, payload)
	return nil
}
func (s *commandTimeoutCaptureStream) RecvMsg(any) error { return nil }

func (s *commandTimeoutCaptureStream) event(name string) map[string]any {
	for _, message := range s.messages {
		if message["event"] == name {
			return message
		}
	}
	return nil
}

func decodeCommandTimeout(t *testing.T, value any) types.CommandTimeout {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var timeout types.CommandTimeout
	if err := json.Unmarshal(encoded, &timeout); err != nil {
		t.Fatal(err)
	}
	return timeout
}
