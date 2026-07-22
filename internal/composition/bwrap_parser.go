package composition

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// ParseBubblewrap parses the explicitly supported Bubblewrap 0.11.2 dialect.
// Unknown options fail closed; this parser is a compatibility adapter, not a
// permissive command-line rewriter.
func ParseBubblewrap(args []string) (Plan, error) {
	plan := Plan{
		Version: ProtocolVersion,
		Dialect: Dialect,
		SetEnv:  make(map[string]string),
	}
	need := func(option string, count int) ([]string, error) {
		if len(args) < count+1 {
			return nil, typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "%s requires %d argument(s)", option, count)
		}
		values := append([]string(nil), args[1:count+1]...)
		args = args[count+1:]
		return values, nil
	}
	addPathOperation := func(operation Operation) error {
		if err := validateTarget(operation.Target); err != nil {
			return err
		}
		plan.Operations = append(plan.Operations, operation)
		return nil
	}

	for len(args) > 0 {
		option := args[0]
		if option == "--" {
			plan.Command = append([]string(nil), args[1:]...)
			args = nil
			break
		}
		if !strings.HasPrefix(option, "--") {
			plan.Command = append([]string(nil), args...)
			args = nil
			break
		}

		switch option {
		case "--unshare-user", "--unshare-user-try":
			args = args[1:]
		case "--unshare-pid":
			plan.UnsharePID = true
			args = args[1:]
		case "--unshare-ipc":
			plan.UnshareIPC = true
			args = args[1:]
		case "--unshare-uts":
			plan.UnshareUTS = true
			args = args[1:]
		case "--unshare-cgroup", "--unshare-cgroup-try":
			plan.UnshareCgroup = true
			args = args[1:]
		case "--share-net":
			args = args[1:]
		case "--unshare-net", "--unshare-all":
			return Plan{}, typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "%s would create a network namespace", option)
		case "--die-with-parent":
			plan.DieWithParent = true
			args = args[1:]
		case "--new-session":
			plan.NewSession = true
			args = args[1:]
		case "--as-pid-1":
			plan.UnsharePID = true
			plan.AsPID1 = true
			args = args[1:]
		case "--dir":
			values, err := need(option, 1)
			if err != nil {
				return Plan{}, err
			}
			if err := addPathOperation(Operation{Type: OperationDirectory, Target: values[0]}); err != nil {
				return Plan{}, err
			}
		case "--bind", "--bind-try", "--ro-bind", "--ro-bind-try":
			values, err := need(option, 2)
			if err != nil {
				return Plan{}, err
			}
			if !filepath.IsAbs(values[0]) {
				return Plan{}, typedError("E_COMPOSITION_SOURCE_DENIED", "%s source must be absolute", option)
			}
			op := Operation{
				Type:      OperationBind,
				Source:    filepath.Clean(values[0]),
				Target:    values[1],
				ReadOnly:  strings.HasPrefix(option, "--ro-"),
				Recursive: true,
				Try:       strings.HasSuffix(option, "-try"),
			}
			if err := addPathOperation(op); err != nil {
				return Plan{}, err
			}
		case "--tmpfs":
			values, err := need(option, 1)
			if err != nil {
				return Plan{}, err
			}
			if err := addPathOperation(Operation{Type: OperationTmpfs, Target: values[0]}); err != nil {
				return Plan{}, err
			}
		case "--proc":
			values, err := need(option, 1)
			if err != nil {
				return Plan{}, err
			}
			if err := addPathOperation(Operation{Type: OperationProc, Target: values[0]}); err != nil {
				return Plan{}, err
			}
			// The outer strict command jail already supplies a private PID
			// namespace. Preserve Bubblewrap semantics: --proc alone mounts that
			// verified current view, while --unshare-pid explicitly requests a
			// fresh descendant PID namespace.
		case "--dev":
			values, err := need(option, 1)
			if err != nil {
				return Plan{}, err
			}
			if err := addPathOperation(Operation{Type: OperationDev, Target: values[0]}); err != nil {
				return Plan{}, err
			}
		case "--symlink":
			values, err := need(option, 2)
			if err != nil {
				return Plan{}, err
			}
			if strings.IndexByte(values[0], 0) >= 0 {
				return Plan{}, typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "symlink source contains NUL")
			}
			if err := addPathOperation(Operation{Type: OperationSymlink, Source: values[0], Target: values[1]}); err != nil {
				return Plan{}, err
			}
		case "--remount-ro":
			values, err := need(option, 1)
			if err != nil {
				return Plan{}, err
			}
			if err := addPathOperation(Operation{Type: OperationRemountRO, Target: values[0], ReadOnly: true}); err != nil {
				return Plan{}, err
			}
		case "--chdir":
			values, err := need(option, 1)
			if err != nil {
				return Plan{}, err
			}
			if values[0] == "" || !filepath.IsAbs(values[0]) || filepath.Clean(values[0]) != values[0] {
				return Plan{}, typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "working directory must be a clean absolute path: %q", values[0])
			}
			plan.Cwd = values[0]
		case "--clearenv":
			plan.ClearEnv = true
			args = args[1:]
		case "--setenv":
			values, err := need(option, 2)
			if err != nil {
				return Plan{}, err
			}
			if !validEnvName(values[0]) {
				return Plan{}, typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "invalid environment name %q", values[0])
			}
			plan.SetEnv[values[0]] = values[1]
		case "--unsetenv":
			values, err := need(option, 1)
			if err != nil {
				return Plan{}, err
			}
			if !validEnvName(values[0]) {
				return Plan{}, typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "invalid environment name %q", values[0])
			}
			plan.UnsetEnv = append(plan.UnsetEnv, values[0])
		case "--hostname":
			values, err := need(option, 1)
			if err != nil {
				return Plan{}, err
			}
			if len(values[0]) == 0 || len(values[0]) > 64 || strings.ContainsAny(values[0], "\x00/\\") {
				return Plan{}, typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "invalid hostname")
			}
			plan.Hostname = values[0]
			plan.UnshareUTS = true
		case "--uid", "--gid":
			values, err := need(option, 1)
			if err != nil {
				return Plan{}, err
			}
			id, err := strconv.Atoi(values[0])
			if err != nil || id < 0 {
				return Plan{}, typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "invalid ID for %s", option)
			}
			if option == "--uid" {
				plan.UID = &id
			} else {
				plan.GID = &id
			}
		case "--cap-drop":
			if _, err := need(option, 1); err != nil {
				return Plan{}, err
			}
			// The adapter payload has no capabilities, so every cap-drop is an
			// already-satisfied reduction.
		case "--cap-add":
			return Plan{}, typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "--cap-add is prohibited")
		case "--overlay", "--ro-overlay", "--tmp-overlay", "--overlay-src", "--mqueue":
			return Plan{}, typedError("E_COMPOSITION_FILESYSTEM_UNSUPPORTED", "%s is prohibited", option)
		case "--dev-bind", "--dev-bind-try":
			values, err := need(option, 2)
			if err != nil {
				return Plan{}, err
			}
			if option != "--dev-bind" || values[0] != "/dev" || values[1] != "/dev" {
				return Plan{}, typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "%s is limited to the reviewed identity /dev -> /dev form", option)
			}
			if err := addPathOperation(Operation{Type: OperationDevBind, Source: "/dev", Target: "/dev", Recursive: true}); err != nil {
				return Plan{}, err
			}
		case "--userns", "--userns2", "--pidns", "--userns-block-fd", "--userns2-block-fd", "--sync-fd":
			return Plan{}, typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "%s namespace/control FD injection is prohibited", option)
		case "--seccomp", "--add-seccomp-fd":
			return Plan{}, typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "%s supplied seccomp is prohibited", option)
		case "--file", "--bind-data", "--ro-bind-data", "--args", "--perms", "--size", "--chmod", "--lock-file", "--info-fd", "--json-status-fd", "--disable-userns", "--assert-userns-disabled", "--argv0", "--level-prefix", "--bind-fd", "--ro-bind-fd", "--block-fd", "--exec-label", "--file-label", "--help", "--version":
			return Plan{}, typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "%s is not implemented by the 0.11.2 adapter", option)
		default:
			return Plan{}, typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "unknown Bubblewrap 0.11.2 option %q", option)
		}
	}

	if len(plan.Command) == 0 || strings.TrimSpace(plan.Command[0]) == "" {
		return Plan{}, typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "Bubblewrap payload command is required")
	}
	if plan.Cwd == "" {
		plan.Cwd = "/"
	}
	return plan, nil
}

func validateTarget(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "target must be a clean absolute path: %q", path)
	}
	if path == "/" {
		return typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "operations may not replace the staged root")
	}
	return nil
}

func validEnvName(name string) bool {
	if name == "" || strings.ContainsRune(name, '=') {
		return false
	}
	for i, r := range name {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func ValidatePlan(plan Plan, maxOperations int) error {
	if plan.Version != ProtocolVersion || plan.Dialect != Dialect {
		return typedError("E_COMPOSITION_DIALECT_MISMATCH", "protocol=%d dialect=%q", plan.Version, plan.Dialect)
	}
	if maxOperations <= 0 || len(plan.Operations) > maxOperations {
		return typedError("E_COMPOSITION_LIMIT_EXCEEDED", "mount plan has %d operations (maximum %d)", len(plan.Operations), maxOperations)
	}
	if len(plan.Command) == 0 {
		return typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "payload command is empty")
	}
	if plan.AsPID1 && !plan.UnsharePID {
		return typedError("E_COMPOSITION_NAMESPACE_INVALID", "--as-pid-1 requires a fresh PID namespace")
	}
	seenSymlinks := make([]string, 0)
	for i, operation := range plan.Operations {
		if err := validateTarget(operation.Target); err != nil {
			return fmt.Errorf("operation %d: %w", i, err)
		}
		switch operation.Type {
		case OperationBind:
			if !filepath.IsAbs(operation.Source) || filepath.Clean(operation.Source) != operation.Source || !operation.Recursive {
				return typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "operation %d has an invalid recursive bind source", i)
			}
		case OperationDevBind:
			if operation.Source != "/dev" || operation.Target != "/dev" || !operation.Recursive || operation.ReadOnly || operation.Try {
				return typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "operation %d is not the admitted identity device bind", i)
			}
		case OperationDirectory, OperationTmpfs, OperationProc, OperationDev:
			if operation.Source != "" || operation.ReadOnly || operation.Recursive || operation.Try {
				return typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "operation %d has invalid %s fields", i, operation.Type)
			}
		case OperationSymlink:
			if strings.IndexByte(operation.Source, 0) >= 0 || operation.ReadOnly || operation.Recursive || operation.Try {
				return typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "operation %d has invalid symlink fields", i)
			}
		case OperationRemountRO:
			if operation.Source != "" || !operation.ReadOnly || operation.Recursive || operation.Try {
				return typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "operation %d has invalid remount fields", i)
			}
		default:
			return typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "operation %d has unsupported type %q", i, operation.Type)
		}
		for _, symlink := range seenSymlinks {
			if operation.Target == symlink || strings.HasPrefix(operation.Target, symlink+string(filepath.Separator)) {
				return typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "operation target %q traverses plan-created symlink %q", operation.Target, symlink)
			}
		}
		if operation.Type == OperationSymlink {
			seenSymlinks = append(seenSymlinks, operation.Target)
		}
	}
	return nil
}
