package composition

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestParseBubblewrapSupportedMatrix(t *testing.T) {
	plan, err := ParseBubblewrap([]string{
		"--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup",
		"--die-with-parent", "--dir", "/nix", "--ro-bind", "/nix/store", "/nix/store",
		"--tmpfs", "/tmp", "--proc", "/proc", "--dev", "/dev", "--dir", "/bin",
		"--symlink", "/nix/store/example/bin/sh", "/bin/sh", "--chdir", "/tmp",
		"--setenv", "HOME", "/tmp", "--", "/bin/sh", "-c", "true",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.UnsharePID || !plan.UnshareIPC || !plan.UnshareUTS || !plan.UnshareCgroup || !plan.DieWithParent {
		t.Fatalf("namespace plan incomplete: %+v", plan)
	}
	if len(plan.Operations) != 7 {
		t.Fatalf("operations=%d, want 7: %+v", len(plan.Operations), plan.Operations)
	}
	if plan.Command[0] != "/bin/sh" || plan.Cwd != "/tmp" || plan.SetEnv["HOME"] != "/tmp" {
		t.Fatalf("payload plan mismatch: %+v", plan)
	}
}

func TestBubblewrap0112OptionMatrixIsCompleteAndClassified(t *testing.T) {
	encoded, err := os.ReadFile(filepath.Join("testdata", "bubblewrap-0.11.2-option-matrix.json"))
	if err != nil {
		t.Fatal(err)
	}
	var matrix struct {
		Dialect string `json:"dialect"`
		Options []struct {
			Option         string `json:"option"`
			Operands       int    `json:"operands"`
			Classification string `json:"classification"`
			Code           string `json:"code"`
		} `json:"options"`
	}
	if err := json.Unmarshal(encoded, &matrix); err != nil {
		t.Fatal(err)
	}
	if matrix.Dialect != Dialect || len(matrix.Options) != 67 {
		t.Fatalf("matrix dialect=%q options=%d", matrix.Dialect, len(matrix.Options))
	}
	seen := make(map[string]struct{}, len(matrix.Options))
	for _, option := range matrix.Options {
		if len(option.Option) < 3 || option.Option[:2] != "--" || option.Operands < 0 {
			t.Fatalf("invalid matrix entry: %+v", option)
		}
		if _, duplicate := seen[option.Option]; duplicate {
			t.Fatalf("duplicate matrix option %q", option.Option)
		}
		seen[option.Option] = struct{}{}
		switch option.Classification {
		case "supported", "normalized", "conditional":
			if option.Code != "" {
				t.Fatalf("admitted option %q carries denial code %q", option.Option, option.Code)
			}
		case "denied":
			if option.Code == "" {
				t.Fatalf("denied option %q omits stable code", option.Option)
			}
		default:
			t.Fatalf("option %q has unknown classification %q", option.Option, option.Classification)
		}
	}
}

func TestParseCapturedQShellBubblewrap0112Invocation(t *testing.T) {
	encoded, err := os.ReadFile(filepath.Join("testdata", "qshell-bwrap-0.11.2-argv.json"))
	if err != nil {
		t.Fatal(err)
	}
	var argv []string
	if err := json.Unmarshal(encoded, &argv); err != nil {
		t.Fatal(err)
	}
	if len(argv) < 2 || filepath.Base(argv[0]) != "bwrap" {
		t.Fatalf("invalid captured argv identity: %v", argv)
	}
	plan, err := ParseBubblewrap(argv[1:])
	if err != nil {
		t.Fatalf("parse captured QShell invocation: %v", err)
	}
	if len(plan.Operations) != 65 {
		t.Fatalf("normalized mount operations = %d, want 65", len(plan.Operations))
	}
	counts := make(map[OperationType]int)
	for _, operation := range plan.Operations {
		counts[operation.Type]++
		if operation.Type == OperationBind && !operation.Recursive {
			t.Fatalf("captured bind was not normalized recursively: %+v", operation)
		}
	}
	want := map[OperationType]int{
		OperationDevBind:   1,
		OperationProc:      1,
		OperationBind:      23,
		OperationTmpfs:     3,
		OperationSymlink:   36,
		OperationRemountRO: 1,
	}
	for operation, count := range want {
		if counts[operation] != count {
			t.Fatalf("%s operations = %d, want %d (all=%v)", operation, counts[operation], count, counts)
		}
	}
	if plan.UnsharePID {
		t.Fatal("captured --proc unexpectedly requested an unobserved fresh PID namespace")
	}
	if plan.Cwd != "/scratch/theo/qshell-project/qshell" || len(plan.Command) != 3 || plan.Command[2] != "true" {
		t.Fatalf("captured payload mismatch: cwd=%q command=%v", plan.Cwd, plan.Command)
	}
	if err := ValidatePlan(plan, 256); err != nil {
		t.Fatalf("validate captured normalized plan: %v", err)
	}
	snapshot, err := SnapshotPlan(plan)
	if err != nil {
		t.Fatalf("snapshot captured normalized plan: %v", err)
	}
	if snapshot.Cwd != plan.Cwd || snapshot.OperationCount != len(plan.Operations) || len(snapshot.Operations) != len(plan.Operations) || len(snapshot.Digest) != 64 {
		t.Fatalf("normalized plan snapshot header mismatch: %+v", snapshot)
	}
	for index, operation := range plan.Operations {
		actual := snapshot.Operations[index]
		if actual.Index != index || actual.Type != operation.Type || actual.Source != operation.Source || actual.Target != operation.Target || actual.ReadOnly != operation.ReadOnly || actual.Recursive != operation.Recursive || actual.Try != operation.Try {
			t.Fatalf("normalized operation %d mismatch: got=%+v want=%+v", index, actual, operation)
		}
	}
	findOperation := func(operationType OperationType, source, target string) int {
		t.Helper()
		for index, operation := range snapshot.Operations {
			if operation.Type == operationType && operation.Source == source && operation.Target == target {
				return index
			}
		}
		return -1
	}
	nixBind := findOperation(OperationBind, "/nix", "/nix")
	scratchBind := findOperation(OperationBind, "/scratch", "/scratch")
	lastMask := findOperation(OperationTmpfs, "", "/tmp/.X11-unix")
	if nixBind != 2 || scratchBind <= nixBind || lastMask != len(snapshot.Operations)-1 {
		t.Fatalf("captured normalized operation order changed: nix=%d scratch=%d last-mask=%d digest=%s", nixBind, scratchBind, lastMask, snapshot.Digest)
	}
}

func TestParseBubblewrapAllowsRootWorkingDirectory(t *testing.T) {
	plan, err := ParseBubblewrap([]string{"--chdir", "/", "--", "/bin/true"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Cwd != "/" {
		t.Fatalf("cwd = %q, want /", plan.Cwd)
	}
}

func TestParseBubblewrapDangerousOptionsFailClosed(t *testing.T) {
	for _, option := range []string{
		"--overlay", "--ro-overlay", "--tmp-overlay", "--overlay-src",
		"--cap-add", "--unshare-net", "--userns", "--pidns", "--seccomp", "--dev-bind-try",
	} {
		t.Run(option, func(t *testing.T) {
			_, err := ParseBubblewrap([]string{option, "ignored", "--", "/bin/true"})
			var typed *Error
			if !errors.As(err, &typed) {
				t.Fatalf("error=%v, want typed fail-closed error", err)
			}
		})
	}
}

func TestValidatePlanRejectsMountBelowPlanSymlink(t *testing.T) {
	plan := Plan{
		Version: ProtocolVersion,
		Dialect: Dialect,
		Command: []string{"/bin/true"},
		Operations: []Operation{
			{Type: OperationSymlink, Source: "/outside", Target: "/alias"},
			{Type: OperationTmpfs, Target: "/alias/child"},
		},
	}
	if err := ValidatePlan(plan, 10); err == nil {
		t.Fatal("expected symlink traversal rejection")
	}
}
