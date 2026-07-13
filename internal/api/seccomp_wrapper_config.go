package api

import (
	"log/slog"
	"os"

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	"github.com/agentsh/agentsh/internal/session"
)

// seccompWrapperConfig is passed to the agentsh-unixwrap wrapper via
// AGENTSH_SECCOMP_CONFIG environment variable to configure seccomp-bpf filtering.
type seccompWrapperConfig struct {
	UnixSocketEnabled   bool                      `json:"unix_socket_enabled"`
	SignalFilterEnabled bool                      `json:"signal_filter_enabled"`
	ExecveEnabled       bool                      `json:"execve_enabled"`
	FileMonitorEnabled  bool                      `json:"file_monitor_enabled"`
	BlockedSyscalls     []string                  `json:"blocked_syscalls"`
	BlockedFamilies     []seccompkg.BlockedFamily `json:"blocked_families,omitempty"`
	SocketRules         []seccompkg.SocketRule    `json:"socket_rules,omitempty"`
	OnBlock             string                    `json:"on_block,omitempty"`

	// File monitor sub-options
	InterceptMetadata bool `json:"intercept_metadata,omitempty"`
	WriteOnlyOpens    bool `json:"write_only_opens,omitempty"`
	BlockIOUring      bool `json:"block_io_uring,omitempty"`

	// WaitKillable forwards the server's decision (boot-time probe +
	// optional config override) to the wrapper, which uses it in place
	// of its own ProbeWaitKillable() fallback. nil means the server made
	// no decision and the wrapper should probe locally. Issue #369.
	WaitKillable *bool `json:"wait_killable,omitempty"`

	// WaitKillableSource records why the WaitKillable decision was made
	// ("config", "kernel_unsupported", "filter_composition_safe",
	// "behavioral_probe", "behavioral_probe_error"). Forwarded so the
	// wrapper's per-exec "seccomp: filter loaded" log line can record the
	// source — one grep tells an operator why this exec saw a given flag
	// value. Issue #369.
	WaitKillableSource string `json:"wait_killable_source,omitempty"`

	// Landlock filesystem restrictions
	LandlockEnabled bool     `json:"landlock_enabled,omitempty"`
	LandlockABI     int      `json:"landlock_abi,omitempty"`
	Workspace       string   `json:"workspace,omitempty"`
	AllowExecute    []string `json:"allow_execute,omitempty"`
	AllowRead       []string `json:"allow_read,omitempty"`
	AllowWrite      []string `json:"allow_write,omitempty"`
	DenyPaths       []string `json:"deny_paths,omitempty"`
	AllowNetwork    bool     `json:"allow_network,omitempty"`
	AllowBind       bool     `json:"allow_bind,omitempty"`

	// Server PID for PR_SET_PTRACER (Yama ptrace_scope=1 workaround)
	ServerPID int `json:"server_pid,omitempty"`

	// CommandJail is set only for strict Linux tool commands. The wrapper must
	// fail closed if it cannot establish every requested namespace/mount guard.
	CommandJail *commandJailConfig `json:"command_jail,omitempty"`
}

type commandJailConfig struct {
	Required        bool     `json:"required"`
	HideDirectories []string `json:"hide_directories,omitempty"`
	HidePaths       []string `json:"hide_paths,omitempty"`
}

type seccompWrapperParams struct {
	UnixSocketEnabled   bool
	SignalFilterEnabled bool
	ExecveEnabled       bool
}

func (a *App) buildSeccompWrapperConfig(s *session.Session, p seccompWrapperParams) seccompWrapperConfig {
	blockedSyscalls, onBlock, err := config.EffectiveSyscallBlock(a.cfg.Sandbox.Seccomp)
	if err != nil {
		slog.Warn("seccomp: failed to resolve effective syscall block list; syscall rules will not be blocked", "error", err)
	}
	seccompCfg := seccompWrapperConfig{
		UnixSocketEnabled:   p.UnixSocketEnabled,
		SignalFilterEnabled: p.SignalFilterEnabled,
		ExecveEnabled:       p.ExecveEnabled,
		FileMonitorEnabled:  config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.Enabled, false),
		BlockedSyscalls:     blockedSyscalls,
		OnBlock:             onBlock,
		ServerPID:           os.Getpid(),
	}

	// Resolve and forward blocked socket families.
	families, err := config.ResolveEffectiveBlockedFamilies(a.cfg.Sandbox.Seccomp)
	if err != nil {
		slog.Warn("seccomp: failed to resolve blocked_socket_families; families will not be blocked", "error", err)
	} else {
		seccompCfg.BlockedFamilies = families
	}

	if rules, err := config.ResolveSocketRules(a.cfg.Sandbox.Seccomp); err != nil {
		slog.Warn("seccomp: failed to resolve socket_rules; socket rules will not be blocked", "error", err)
	} else {
		seccompCfg.SocketRules = rules
	}
	if commandJailRequired(a.cfg) {
		appendProxyRequiredUnsupportedTrafficRules(&seccompCfg)
	}

	fmDefault := config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE, false)
	seccompCfg.InterceptMetadata = config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.InterceptMetadata, fmDefault)
	if seccompCfg.FileMonitorEnabled {
		seccompCfg.WriteOnlyOpens = config.FileMonitorBoolWithDefault(
			a.cfg.Sandbox.Seccomp.FileMonitor.WriteOnlyOpens,
			!seccompCfg.InterceptMetadata,
		)
	}
	seccompCfg.BlockIOUring = config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.BlockIOUring, fmDefault)

	// Pass the boot-time decision to every wrapper. The pointer is
	// per-exec; the bool storage is the server-process App field. Issue #369.
	seccompCfg.WaitKillable = &a.waitKillableDecision
	seccompCfg.WaitKillableSource = a.waitKillableSource

	if a.cfg.Landlock.Enabled {
		llResult := capabilities.DetectLandlock()
		if llResult.Available {
			workspace := s.WorkspaceMountPath()
			seccompCfg.LandlockEnabled = true
			seccompCfg.LandlockABI = llResult.ABI
			seccompCfg.Workspace = workspace

			seccompCfg.AllowExecute, seccompCfg.AllowRead, seccompCfg.AllowWrite = a.deriveLandlockAllowPaths(s)
			appendRuntimeLandlockPaths(&seccompCfg, s)
			seccompCfg.AllowExecute = append(seccompCfg.AllowExecute, a.cfg.Landlock.AllowExecute...)
			seccompCfg.AllowRead = append(seccompCfg.AllowRead, a.cfg.Landlock.AllowRead...)
			seccompCfg.AllowWrite = append(seccompCfg.AllowWrite, a.cfg.Landlock.AllowWrite...)
			seccompCfg.DenyPaths = append(seccompCfg.DenyPaths, a.cfg.Landlock.DenyPaths...)

			if a.cfg.Landlock.Network.AllowConnectTCP != nil {
				seccompCfg.AllowNetwork = *a.cfg.Landlock.Network.AllowConnectTCP
			}
			if a.cfg.Landlock.Network.AllowBindTCP != nil {
				seccompCfg.AllowBind = *a.cfg.Landlock.Network.AllowBindTCP
			}
		}
	}

	return seccompCfg
}

// appendProxyRequiredUnsupportedTrafficRules closes protocol paths that the
// four cgroup connect/sendmsg hooks do not themselves cover. These kernel-side
// errno rules are inherited by the jailed command. Together with the exact TCP
// proxy map they define proxy-required behavior: direct TCP and UDP/QUIC are
// denied by eBPF, while raw IP, packet, ICMP datagram, CAN, and Bluetooth socket
// creation is denied by seccomp before untrusted code can use it.
func appendProxyRequiredUnsupportedTrafficRules(cfg *seccompWrapperConfig) {
	if cfg == nil {
		return
	}
	const (
		afINET       = 2
		afINET6      = 10
		afPACKET     = 17
		afCAN        = 29
		afBLUETOOTH  = 31
		sockDGRAM    = 2
		sockRAW      = 3
		ipprotoICMP  = 1
		ipprotoICMP6 = 58
	)

	ensureFamilyDenied := func(family int, name string) {
		found := false
		for i := range cfg.BlockedFamilies {
			if cfg.BlockedFamilies[i].Family != family {
				continue
			}
			// Strict proxy-required rules override a weaker operator/audit action.
			// Merely noticing an existing `log` rule here would report raw-socket
			// prevention while the userspace handler still allowed the socket.
			cfg.BlockedFamilies[i].Action = seccompkg.OnBlockErrno
			if cfg.BlockedFamilies[i].Name == "" {
				cfg.BlockedFamilies[i].Name = name
			}
			found = true
		}
		if !found {
			cfg.BlockedFamilies = append(cfg.BlockedFamilies, seccompkg.BlockedFamily{
				Family: family,
				Name:   name,
				Action: seccompkg.OnBlockErrno,
			})
		}
	}
	for _, family := range []struct {
		number int
		name   string
	}{
		{afPACKET, "AF_PACKET"},
		{afCAN, "AF_CAN"},
		{afBLUETOOTH, "AF_BLUETOOTH"},
	} {
		ensureFamilyDenied(family.number, family.name)
	}

	addRule := func(name, familyName string, family, socketType int, typeName string, protocol *int, protocolName string) {
		found := false
		for i := range cfg.SocketRules {
			existing := &cfg.SocketRules[i]
			if existing.Family != family || existing.Type == nil || *existing.Type != socketType {
				continue
			}
			protocolMatches := protocol == nil && existing.Protocol == nil
			if protocol != nil && existing.Protocol != nil && *existing.Protocol == *protocol {
				protocolMatches = true
			}
			if !protocolMatches {
				continue
			}
			existing.Action = seccompkg.OnBlockErrno
			found = true
		}
		if found {
			return
		}
		typ := socketType
		rule := seccompkg.SocketRule{
			Name:       name,
			Family:     family,
			FamilyName: familyName,
			Type:       &typ,
			TypeName:   typeName,
			Action:     seccompkg.OnBlockErrno,
		}
		if protocol != nil {
			proto := *protocol
			rule.Protocol = &proto
			rule.ProtocolName = protocolName
		}
		cfg.SocketRules = append(cfg.SocketRules, rule)
	}

	addRule("agentsh-proxy-required-raw-ipv4", "AF_INET", afINET, sockRAW, "SOCK_RAW", nil, "")
	addRule("agentsh-proxy-required-raw-ipv6", "AF_INET6", afINET6, sockRAW, "SOCK_RAW", nil, "")
	icmp := ipprotoICMP
	icmp6 := ipprotoICMP6
	addRule("agentsh-proxy-required-icmp-dgram-ipv4", "AF_INET", afINET, sockDGRAM, "SOCK_DGRAM", &icmp, "IPPROTO_ICMP")
	addRule("agentsh-proxy-required-icmp-dgram-ipv6", "AF_INET6", afINET6, sockDGRAM, "SOCK_DGRAM", &icmp6, "IPPROTO_ICMPV6")
}

// proxyRequiredRawSocketRulesConfigured verifies the fixed kernel-side
// creation denials that complement the cgroup connect/sendmsg gate. This is
// checked before disposable preflight execution so RawSocketBlockConfigured is
// never inferred merely from a socket(2) probe failing for some other reason.
func proxyRequiredRawSocketRulesConfigured(cfg *seccompWrapperConfig) bool {
	if cfg == nil {
		return false
	}
	const (
		afINET   = 2
		afINET6  = 10
		afPACKET = 17
		sockRAW  = 3
	)
	packetDenied := false
	for _, family := range cfg.BlockedFamilies {
		if family.Family == afPACKET && family.Action == seccompkg.OnBlockErrno {
			packetDenied = true
			break
		}
	}
	rawDenied := func(family int) bool {
		for _, rule := range cfg.SocketRules {
			if rule.Family == family && rule.Type != nil && *rule.Type == sockRAW && rule.Protocol == nil && rule.Action == seccompkg.OnBlockErrno {
				return true
			}
		}
		return false
	}
	return packetDenied && rawDenied(afINET) && rawDenied(afINET6)
}

func appendRuntimeLandlockPaths(seccompCfg *seccompWrapperConfig, s *session.Session) {
	if seccompCfg == nil || s == nil {
		return
	}
	// Runtime state can live outside the accepted project workspace (shadow home,
	// detached direct-mode runtime dirs, etc.). The policy engine can authorize
	// these paths, but Landlock must receive concrete per-session paths up front;
	// otherwise startup writes like $PI_CODING_AGENT_DIR/sessions fail with EACCES
	// before user-space file policy can help.
	if home := s.RuntimeHomePath(); home != "" {
		seccompCfg.AllowRead = append(seccompCfg.AllowRead, home)
		seccompCfg.AllowWrite = append(seccompCfg.AllowWrite, home)
	}
	if tmp := s.RuntimeTmpPath(); tmp != "" {
		seccompCfg.AllowRead = append(seccompCfg.AllowRead, tmp)
		seccompCfg.AllowWrite = append(seccompCfg.AllowWrite, tmp)
	}
}
