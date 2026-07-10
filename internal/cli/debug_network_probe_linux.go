//go:build linux

package cli

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// networkRuntimeProbeResult is an internal wire object consumed only by the
// trusted supervisor. It contains observations, paths, and endpoint IDs, never
// helper credentials or detached event tokens.
type networkRuntimeProbeResult struct {
	MarkerWritten               bool `json:"marker_written"`
	ProxyConnectProven          bool `json:"proxy_connect_proven"`
	LocalDirectTCPBlocked       bool `json:"local_direct_tcp_blocked"`
	UDPBlocked                  bool `json:"udp_blocked"`
	RawSocketsBlocked           bool `json:"raw_sockets_blocked"`
	PrivateProcProven           bool `json:"private_proc_proven"`
	CgroupFSHidden              bool `json:"cgroupfs_hidden"`
	HelperSocketHidden          bool `json:"helper_socket_hidden"`
	CredentialSourceHidden      bool `json:"credential_source_hidden"`
	ControlPathsHidden          bool `json:"control_paths_hidden"`
	ReservedEnvScrubbed         bool `json:"reserved_env_scrubbed"`
	InheritedDescriptorsClosed bool `json:"inherited_descriptors_closed"`
	NoNewPrivileges             bool `json:"no_new_privs"`
	CapabilitiesDropped         bool `json:"capabilities_dropped"`
	Detail                      string `json:"detail,omitempty"`
}

func newDebugNetworkRuntimeProbeCmd() *cobra.Command {
	var markerPath string
	var proxyEndpoint string
	var directTCPEndpoint string
	var udpEndpoint string
	var supervisorPID int
	var cgroupRoot string
	var helperSocket string
	var credentialFile string
	var controlPath string
	var inheritedFile string

	cmd := &cobra.Command{
		Use:    "network-runtime-probe",
		Short:  "Run the internal detached network boundary probe",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			result := runDebugNetworkRuntimeProbe(networkRuntimeProbeOptions{
				MarkerPath:        markerPath,
				ProxyEndpoint:     proxyEndpoint,
				DirectTCPEndpoint: directTCPEndpoint,
				UDPEndpoint:       udpEndpoint,
				SupervisorPID:     supervisorPID,
				CgroupRoot:        cgroupRoot,
				HelperSocket:      helperSocket,
				CredentialFile:    credentialFile,
				ControlPath:       controlPath,
				InheritedFile:     inheritedFile,
			})
			return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
		},
	}
	cmd.Flags().StringVar(&markerPath, "marker", "", "internal barrier marker")
	cmd.Flags().StringVar(&proxyEndpoint, "proxy", "", "exact AgentSH proxy endpoint")
	cmd.Flags().StringVar(&directTCPEndpoint, "direct-tcp", "", "local direct-bypass endpoint")
	cmd.Flags().StringVar(&udpEndpoint, "udp", "", "local unsupported UDP endpoint")
	cmd.Flags().IntVar(&supervisorPID, "supervisor-pid", 0, "host supervisor PID")
	cmd.Flags().StringVar(&cgroupRoot, "cgroup-root", "", "host cgroup root expected to be hidden")
	cmd.Flags().StringVar(&helperSocket, "helper-socket", "", "helper socket expected to be hidden")
	cmd.Flags().StringVar(&credentialFile, "credential-file", "", "credential source expected to be hidden")
	cmd.Flags().StringVar(&controlPath, "control-path", "", "supervisor control path expected to be hidden")
	cmd.Flags().StringVar(&inheritedFile, "inherited-file", "", "descriptor sentinel that must not be inherited")
	return cmd
}

type networkRuntimeProbeOptions struct {
	MarkerPath        string
	ProxyEndpoint     string
	DirectTCPEndpoint string
	UDPEndpoint       string
	SupervisorPID     int
	CgroupRoot        string
	HelperSocket      string
	CredentialFile    string
	ControlPath       string
	InheritedFile     string
}

func runDebugNetworkRuntimeProbe(opts networkRuntimeProbeOptions) networkRuntimeProbeResult {
	result := networkRuntimeProbeResult{}
	var failures []string

	if strings.TrimSpace(opts.MarkerPath) == "" {
		failures = append(failures, "marker path missing")
	} else if err := os.WriteFile(opts.MarkerPath, []byte("command-started\n"), 0o600); err != nil {
		failures = append(failures, "marker write failed: "+err.Error())
	} else {
		result.MarkerWritten = true
	}

	result.ProxyConnectProven = tcpConnectSucceeds(opts.ProxyEndpoint)
	if !result.ProxyConnectProven {
		failures = append(failures, "exact proxy endpoint was not reachable")
	}
	result.LocalDirectTCPBlocked = tcpConnectBlocked(opts.DirectTCPEndpoint)
	if !result.LocalDirectTCPBlocked {
		failures = append(failures, "local non-proxy TCP connect was not rejected")
	}
	result.UDPBlocked = udpWriteBlocked(opts.UDPEndpoint)
	if !result.UDPBlocked {
		failures = append(failures, "UDP connect/send was not rejected")
	}
	result.RawSocketsBlocked = rawSocketBlocked()
	if !result.RawSocketsBlocked {
		failures = append(failures, "raw IPv4 or packet socket creation was not rejected")
	}

	result.PrivateProcProven = privateProcObserved(opts.SupervisorPID)
	result.CgroupFSHidden = pathHidden(opts.CgroupRoot, false)
	result.HelperSocketHidden = pathHidden(opts.HelperSocket, true)
	result.CredentialSourceHidden = pathHidden(opts.CredentialFile, true)
	result.ControlPathsHidden = pathHidden(opts.ControlPath, true)
	result.ReservedEnvScrubbed = reservedNetworkRuntimeEnvAbsent()
	result.InheritedDescriptorsClosed = inheritedPathAbsent(opts.InheritedFile)
	result.NoNewPrivileges, result.CapabilitiesDropped = processPrivilegeState()

	boundaryChecks := []struct {
		ok   bool
		name string
	}{
		{result.PrivateProcProven, "private proc"},
		{result.CgroupFSHidden, "hidden cgroupfs"},
		{result.HelperSocketHidden, "hidden helper socket"},
		{result.CredentialSourceHidden, "hidden credential source"},
		{result.ControlPathsHidden, "hidden supervisor control path"},
		{result.ReservedEnvScrubbed, "reserved environment scrub"},
		{result.InheritedDescriptorsClosed, "descriptor closure"},
		{result.NoNewPrivileges, "no_new_privs"},
		{result.CapabilitiesDropped, "capability drop"},
	}
	for _, check := range boundaryChecks {
		if !check.ok {
			failures = append(failures, check.name+" not proven")
		}
	}
	result.Detail = strings.Join(failures, "; ")
	return result
}

func tcpConnectSucceeds(endpoint string) bool {
	if strings.TrimSpace(endpoint) == "" {
		return false
	}
	conn, err := net.DialTimeout("tcp", endpoint, time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func tcpConnectBlocked(endpoint string) bool {
	if strings.TrimSpace(endpoint) == "" {
		return false
	}
	conn, err := net.DialTimeout("tcp", endpoint, 500*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return false
	}
	// A timeout, reset, or listener error is not gate evidence. The disposable
	// listener is known-good; only the cgroup program's permission denial proves
	// that connect(2) itself was rejected.
	return gatePermissionDenied(err)
}

func udpWriteBlocked(endpoint string) bool {
	if strings.TrimSpace(endpoint) == "" {
		return false
	}
	conn, err := net.DialTimeout("udp", endpoint, 500*time.Millisecond)
	if err != nil {
		return gatePermissionDenied(err)
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = conn.Write([]byte("agentsh-network-preflight"))
	// UDP never needs a reply for Write to succeed. Requiring EPERM/EACCES here
	// prevents an absent reply or unrelated transport error from being reported
	// as sendmsg-gate evidence.
	return gatePermissionDenied(err)
}

func gatePermissionDenied(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}

func rawSocketBlocked() bool {
	blocked := func(family, protocol int) bool {
		fd, err := syscall.Socket(family, syscall.SOCK_RAW, protocol)
		if err == nil {
			_ = syscall.Close(fd)
			return false
		}
		return gatePermissionDenied(err)
	}
	// AF_PACKET (17) and IPPROTO_ICMPV6 (58) are stable Linux UAPI values.
	// Protocol zero is enough to prove AF_PACKET creation is denied; the strict
	// wrapper rejects that family before protocol-specific behavior can run.
	return blocked(syscall.AF_INET, syscall.IPPROTO_ICMP) &&
		blocked(syscall.AF_INET6, 58) &&
		blocked(17, 0)
}

func privateProcObserved(supervisorPID int) bool {
	if supervisorPID <= 0 {
		return false
	}
	// The supervisor is alive for the duration of this probe. Its host PID must
	// therefore exist in host proc and be absent only because the jail mounted a
	// procfs bound to the command PID namespace.
	if _, err := os.Stat(filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(supervisorPID))); err == nil || !errors.Is(err, os.ErrNotExist) {
		return false
	}
	if _, err := os.Stat(filepath.Join(string(filepath.Separator), "proc", "1", "status")); err != nil {
		return false
	}
	_, err := os.Stat(filepath.Join(string(filepath.Separator), "proc", "self", "status"))
	return err == nil
}

func pathHidden(path string, requireConfigured bool) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return !requireConfigured
	}
	info, err := os.Lstat(path)
	if err != nil {
		return errors.Is(err, os.ErrNotExist)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	// Individual control files are bind-masked with the jail's /dev/null.
	// Directories (helper/cgroup roots) disappear below read-only tmpfs masks.
	// Accept only those two explicit states, never a generic permission error.
	devNull := filepath.Join(string(filepath.Separator), "dev", "null")
	nullInfo, err := os.Stat(devNull)
	if err != nil || !os.SameFile(info, nullInfo) {
		return false
	}
	if requireConfigured {
		conn, dialErr := net.DialTimeout("unix", path, 200*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return false
		}
	}
	return true
}

func reservedNetworkRuntimeEnvAbsent() bool {
	reserved := []string{
		"AGENTSH_NOTIFY_SOCK_FD",
		"AGENTSH_SIGNAL_SOCK_FD",
		"AGENTSH_SECCOMP_CONFIG",
		"AGENTSH_PTRACE_SYNC",
		"AGENTSH_UNIXWRAP_ARGV0",
		"AGENTSH_WRAPPER_LOG_FD",
		"AGENTSH_APPROVAL_UI_SOCKET",
		"AGENTSH_INTERNAL_COMMAND_JAIL_STAGE",
		"AGENTSH_INTERNAL_COMMAND_JAIL_MOUNTS",
		"AGENTSH_INTERNAL_COMMAND_JAIL_EXEC_PATH",
		"AGENTSH_NETHELPER_SOCKET",
		"AGENTSH_NETHELPER_INSTANCE_CREDENTIAL",
		"AGENTSH_NETHELPER_SESSION_NONCE",
		"AGENTSH_NETHELPER_CREDENTIAL_FILE",
		"AGENTSH_DETACHED_EVENT_TOKEN",
		"AGENTSH_DETACHED_EVENT_URL",
		"AGENTSH_DETACHED_NETWORK_ENFORCEMENT_REQUESTED",
		"AGENTSH_DETACHED_SUPERVISOR_LAUNCH_MODE",
		"AGENTSH_API_KEY",
		"AGENTSH_SERVER",
	}
	for _, entry := range os.Environ() {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		for _, blocked := range reserved {
			if strings.EqualFold(strings.TrimSpace(name), blocked) {
				return false
			}
		}
	}
	return true
}

func inheritedPathAbsent(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	fdDir := filepath.Join(string(filepath.Separator), "proc", "self", "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}
		target = strings.TrimSuffix(target, " (deleted)")
		if target == path {
			return false
		}
	}
	return true
}

func processPrivilegeState() (noNewPrivileges bool, capabilitiesDropped bool) {
	status, err := os.ReadFile(filepath.Join(string(filepath.Separator), "proc", "self", "status"))
	if err != nil {
		return false, false
	}
	capabilityFields := map[string]bool{
		"CapInh": false,
		"CapPrm": false,
		"CapEff": false,
		"CapBnd": false,
		"CapAmb": false,
	}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimSuffix(fields[0], ":")
		switch name {
		case "NoNewPrivs":
			noNewPrivileges = fields[1] == "1"
		default:
			if _, required := capabilityFields[name]; required {
				capabilityFields[name] = strings.TrimLeft(fields[1], "0") == ""
			}
		}
	}
	capabilitiesDropped = true
	for _, empty := range capabilityFields {
		capabilitiesDropped = capabilitiesDropped && empty
	}
	return noNewPrivileges, capabilitiesDropped
}
