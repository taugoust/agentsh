package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/nethelper"
)

// detachedSupervisorSystemdRunEnv opts into the NixOS-supported delegated
// user-service path. Unset keeps the explicitly degraded direct fork/exec path.
const detachedSupervisorSystemdRunEnv = "AGENTSH_DETACHED_SUPERVISOR_SYSTEMD_RUN"

type detachedSupervisorLaunchRequest struct {
	Exe            string
	Args           []string
	Env            []string
	Dir            string
	SessionID      string
	ServiceEnv     []string
	ServiceEnvFile string
	ServiceLogFile string
	GOOS           string
	LookPath       func(string) (string, error)
}

type detachedSupervisorLaunch struct {
	Path                string
	Args                []string
	Env                 []string
	Dir                 string
	UsesSystemd         bool
	SystemdUnit         string
	NethelperSocket     string
	OwnerPIDFromCommand bool
}

func detachedSupervisorRunArgs(stateDir, sockPath, configPath string) []string {
	return []string{"supervisor", "run", "--state-dir", stateDir, "--socket", sockPath, "--config", configPath}
}

func buildDetachedSupervisorLaunch(req detachedSupervisorLaunchRequest) detachedSupervisorLaunch {
	nethelperSocket, _ := lookupEnvAssignment(req.Env, nethelper.EnvSocket)
	directEnv := withoutEnvAssignments(req.Env, detached.EnvSupervisorLaunchMode)
	directEnv = append(directEnv, detached.EnvSupervisorLaunchMode+"=direct")
	launch := detachedSupervisorLaunch{
		Path:                req.Exe,
		Args:                append([]string(nil), req.Args...),
		Env:                 directEnv,
		Dir:                 req.Dir,
		NethelperSocket:     strings.TrimSpace(nethelperSocket),
		OwnerPIDFromCommand: true,
	}

	systemdRunPath, ok := chooseDetachedSupervisorSystemdRun(req)
	if !ok {
		return launch
	}

	unit := detachedSupervisorSystemdUnit(req.SessionID)
	launch.Path = systemdRunPath
	serviceEnv := withoutEnvAssignments(req.ServiceEnv, detached.EnvSupervisorLaunchMode)
	serviceEnv = append(serviceEnv, detached.EnvSupervisorLaunchMode+"=systemd-user-delegated")
	launch.Args = buildSystemdRunDetachedSupervisorArgs(unit, req.Dir, req.ServiceEnvFile, req.ServiceLogFile, serviceEnv, req.Exe, req.Args)
	// systemd-run needs the user's bus/runtime environment, but must never carry
	// either credential in its own inspectable environment. The service receives
	// secrets only through the protected EnvironmentFile.
	launch.Env = withoutEnvAssignments(
		req.Env,
		"AGENTSH_DETACHED_EVENT_TOKEN",
		nethelper.EnvHelperInstanceCredential,
		nethelper.EnvSessionNonce,
		detached.EnvSupervisorLaunchMode,
	)
	launch.UsesSystemd = true
	launch.SystemdUnit = unit
	launch.OwnerPIDFromCommand = false
	return launch
}

func chooseDetachedSupervisorSystemdRun(req detachedSupervisorLaunchRequest) (string, bool) {
	goos := req.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	if goos != "linux" {
		return "", false
	}
	if !detachedSupervisorSystemdRunRequested(req.Env) {
		return "", false
	}
	if !detachedSupervisorSystemdUserEnvAvailable(req.Env) {
		return "", false
	}

	lookPath := req.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	systemdRunPath, err := lookPath("systemd-run")
	if err != nil || strings.TrimSpace(systemdRunPath) == "" {
		return "", false
	}
	return systemdRunPath, true
}

func buildSystemdRunDetachedSupervisorArgs(unit, workDir, serviceEnvFile, serviceLogFile string, serviceEnv []string, exe string, supervisorArgs []string) []string {
	privateTmp := "yes"
	if detachedSupervisorNeedsHostTmp(serviceEnv) {
		// OpenSSH creates forwarded-agent sockets below the host /tmp. A private
		// tmp namespace would retain the path in the environment while hiding the
		// socket itself. Keep host /tmp visible only for this explicit lifecycle;
		// AgentSH and outer sandbox policies still grant connect access solely to
		// the exact SSH_AUTH_SOCK path.
		privateTmp = "no"
	}
	args := []string{
		"--user",
		"--collect",
		"--service-type=exec",
		"--unit=" + unit,
		"-p", "Delegate=yes",
		"-p", "KillMode=mixed",
		"-p", "TimeoutStopSec=10s",
		"-p", "UMask=0077",
		"-p", "NoNewPrivileges=yes",
		"-p", "PrivateTmp=" + privateTmp,
		"-p", "KeyringMode=private",
		"-p", "LimitCORE=0",
		"-p", "OOMPolicy=stop",
	}
	if strings.TrimSpace(workDir) != "" {
		args = append(args, "-p", "WorkingDirectory="+workDir)
	}
	if strings.TrimSpace(serviceLogFile) != "" {
		logFile := filepath.Clean(serviceLogFile)
		args = append(args,
			"-p", "StandardOutput=append:"+logFile,
			"-p", "StandardError=append:"+logFile,
		)
	}
	if strings.TrimSpace(serviceEnvFile) != "" {
		args = append(args, "-p", "EnvironmentFile="+filepath.Clean(serviceEnvFile))
	} else {
		// Compatibility for non-secret diagnostics only. Event/helper credential
		// values are never placed in systemd-run argv.
		for _, assignment := range serviceEnv {
			if isEnvAssignment(assignment) && !isSensitiveSupervisorAssignment(assignment) {
				args = append(args, "--setenv="+assignment)
			}
		}
	}
	args = append(args, "--", exe)
	args = append(args, supervisorArgs...)
	return args
}

func detachedSupervisorNeedsHostTmp(serviceEnv []string) bool {
	sock, ok := lookupEnvAssignment(serviceEnv, "SSH_AUTH_SOCK")
	if !ok || strings.TrimSpace(sock) == "" {
		return false
	}
	clean := filepath.Clean(strings.TrimSpace(sock))
	return strings.HasPrefix(clean, string(filepath.Separator)+"tmp"+string(filepath.Separator)) ||
		strings.HasPrefix(clean, string(filepath.Separator)+"var"+string(filepath.Separator)+"tmp"+string(filepath.Separator))
}

func isSensitiveSupervisorAssignment(assignment string) bool {
	name, _, ok := strings.Cut(assignment, "=")
	if !ok {
		return false
	}
	for _, sensitive := range []string{"AGENTSH_DETACHED_EVENT_TOKEN", nethelper.EnvHelperInstanceCredential, nethelper.EnvSessionNonce} {
		if strings.EqualFold(strings.TrimSpace(name), sensitive) {
			return true
		}
	}
	return false
}

func writeDetachedSupervisorEnvironmentFile(path string, assignments []string) error {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("supervisor environment file path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create supervisor environment directory: %w", err)
	}
	var content strings.Builder
	for _, assignment := range assignments {
		name, value, ok := strings.Cut(assignment, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" || strings.ContainsAny(name, " \t\r\n") {
			return fmt.Errorf("invalid supervisor environment assignment")
		}
		if strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("supervisor environment value for %s contains a newline", name)
		}
		value = strings.ReplaceAll(value, `\`, `\\`)
		value = strings.ReplaceAll(value, `"`, `\"`)
		fmt.Fprintf(&content, "%s=\"%s\"\n", name, value)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".supervisor-env-*")
	if err != nil {
		return fmt.Errorf("create supervisor environment file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod supervisor environment file: %w", err)
	}
	if _, err := tmp.WriteString(content.String()); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write supervisor environment file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close supervisor environment file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("install supervisor environment file: %w", err)
	}
	return nil
}

func detachedSupervisorSystemdRunRequested(env []string) bool {
	value, ok := lookupEnvAssignment(env, detachedSupervisorSystemdRunEnv)
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "auto":
		return true
	default:
		return false
	}
}

func detachedSupervisorSystemdUserEnvAvailable(env []string) bool {
	value, ok := lookupEnvAssignment(env, "XDG_RUNTIME_DIR")
	return ok && strings.TrimSpace(value) != ""
}

func lookupEnvAssignment(env []string, key string) (string, bool) {
	for _, entry := range env {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(name, key) {
			return value, true
		}
	}
	return "", false
}

func withoutEnvAssignments(env []string, keys ...string) []string {
	deny := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		deny[strings.ToLower(strings.TrimSpace(key))] = struct{}{}
	}
	out := make([]string, 0, len(env))
	for _, entry := range env {
		name, _, ok := strings.Cut(entry, "=")
		if ok {
			if _, drop := deny[strings.ToLower(strings.TrimSpace(name))]; drop {
				continue
			}
		}
		out = append(out, entry)
	}
	return out
}

func isEnvAssignment(value string) bool {
	name, _, ok := strings.Cut(value, "=")
	return ok && strings.TrimSpace(name) != ""
}

func detachedSupervisorSystemdUnit(sessionID string) string {
	id := strings.TrimSpace(sessionID)
	if id == "" {
		id = "session"
	}

	var cleaned strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
			cleaned.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			cleaned.WriteRune(r)
		case r >= '0' && r <= '9':
			cleaned.WriteRune(r)
		case r == '_' || r == '-' || r == '.':
			cleaned.WriteRune(r)
		default:
			cleaned.WriteByte('-')
		}
	}

	name := strings.Trim(cleaned.String(), "-")
	if name == "" {
		name = "session"
	}

	const prefix = "agentsh-supervisor-"
	const suffix = ".service"
	const maxUnitNameLen = 240
	maxNameLen := maxUnitNameLen - len(prefix) - len(suffix)
	if len(name) > maxNameLen {
		name = name[:maxNameLen]
	}
	return prefix + name + suffix
}

func stopDetachedSupervisorSystemdUnit(ctx context.Context, unit string) error {
	unit = strings.TrimSpace(unit)
	if unit == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", "--user", "stop", unit)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("systemctl --user stop %s: %w: %s", unit, err, msg)
		}
		return fmt.Errorf("systemctl --user stop %s: %w", unit, err)
	}
	return nil
}
