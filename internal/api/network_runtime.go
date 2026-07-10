package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/limits"
	"github.com/agentsh/agentsh/internal/nethelper"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func isNetworkPolicyTestOperation(op string) bool {
	op = strings.ToLower(strings.TrimSpace(op))
	return strings.HasPrefix(op, "net_") || op == "connect"
}

func probeLoopbackProxy(endpoint string) bool {
	conn, err := net.DialTimeout("tcp", endpoint, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func requestedNetworkEnforcement(cfgStrict bool, cfgNetwork bool) types.NetworkEnforcementRequest {
	if requested := strings.TrimSpace(os.Getenv(detached.EnvNetworkEnforcementRequested)); requested != "" {
		switch types.NetworkEnforcementRequest(requested) {
		case types.NetworkEnforcementRequestNone, types.NetworkEnforcementRequestBestEffort, types.NetworkEnforcementRequestStrict:
			return types.NetworkEnforcementRequest(requested)
		}
	}
	if cfgStrict {
		return types.NetworkEnforcementRequestStrict
	}
	if cfgNetwork {
		return types.NetworkEnforcementRequestBestEffort
	}
	return types.NetworkEnforcementRequestNone
}

// observedNetworkEnforcement builds a report from runtime objects that already
// exist. It deliberately does not infer helper authentication, direct-bypass
// blocking, or the same-UID tool boundary from launch flags or environment
// variables.
func (a *App) observedNetworkEnforcement(sessionID string) *types.NetworkEnforcement {
	now := time.Now().UTC()
	report := &types.NetworkEnforcement{
		Readiness: types.NetworkEnforcementStatusNone,
		Status:    types.NetworkEnforcementStatusNone,
		Tier:      types.NetworkEnforcementTierNone,
		CheckedAt: now,
	}
	if a == nil || a.cfg == nil {
		report.Status = types.NetworkEnforcementStatusDegraded
		report.Detail = "app configuration is unavailable"
		report.Warning = "runtime network enforcement cannot be proven"
		report.Normalize()
		return report
	}

	ebpfCfg := a.cfg.Sandbox.Network.EBPF
	strict := ebpfCfg.Enforce || ebpfCfg.Required
	configured := a.cfg.Sandbox.Network.Enabled || ebpfCfg.Enabled || strict
	report.Requested = requestedNetworkEnforcement(strict, configured)
	if report.Requested != types.NetworkEnforcementRequestNone {
		report.Readiness = types.NetworkEnforcementStatusDegraded
	}
	// A strict config requests the stopped-child barrier, but configuration is
	// not evidence that the barrier ran. FailClosedSetup is set only by a
	// preflight or per-command transition below.
	report.FailClosedSetup = false

	if a.cgroupMgr != nil {
		if probe := a.cgroupMgr.Probe(); probe != nil {
			report.CgroupMode = string(probe.Mode)
			report.CgroupRoot = strings.TrimSpace(probe.OwnCgroup)
			report.CgroupDelegated = probe.Mode != "" && probe.Mode != limits.ModeUnavailable && report.CgroupRoot != ""
		}
	}

	helperSocket := strings.TrimSpace(os.Getenv(nethelper.EnvSocket))
	if helperSocket != "" {
		if info, err := os.Stat(helperSocket); err == nil && info.Mode()&os.ModeSocket != 0 {
			report.HelperConfigured = true
		}
	}

	var sess *session.Session
	if a.sessions != nil && strings.TrimSpace(sessionID) != "" {
		sess, _ = a.sessions.Get(sessionID)
	}
	if sess != nil {
		if proxyURL := strings.TrimSpace(sess.ProxyURL()); proxyURL != "" {
			if endpoint, err := exactLoopbackProxyAddrPort(proxyURL); err == nil {
				report.ProxyEndpointID = endpoint.String()
				report.ProxyReady = probeLoopbackProxy(endpoint.String())
				if !report.ProxyReady {
					report.Warning = "the configured AgentSH proxy endpoint did not accept a loopback readiness connection"
				}
			} else {
				report.ProxyReady = false
				report.Warning = "configured proxy endpoint is not an exact loopback IP address and port"
			}
		}
		if previous := sess.NetworkEnforcement(); previous != nil {
			// These fields are retained only after an explicit preflight, helper
			// response, or per-command setup transition.
			report.HelperAuthenticated = previous.HelperAuthenticated
			report.Preflight = previous.Preflight
			if previous.Readiness != "" {
				report.Readiness = previous.Readiness
			}
			if previous.Status == types.NetworkEnforcementStatusActive && previous.Attachment != nil {
				report.Status = previous.Status
				report.Tier = previous.Tier
				report.CgroupDelegated = previous.CgroupDelegated
				report.HelperConfigured = previous.HelperConfigured
				report.ToolBoundaryActive = previous.ToolBoundaryActive
				report.ProxyRequired = previous.ProxyRequired
				report.ExactProxyOnly = previous.ExactProxyOnly
				report.AllowedTransport = previous.AllowedTransport
				report.DirectBypassBlocked = previous.DirectBypassBlocked
				report.DirectTCPBlocked = previous.DirectTCPBlocked
				report.LocalNonProxyTCPBlocked = previous.LocalNonProxyTCPBlocked
				report.UDPBlocked = previous.UDPBlocked
				report.QUICBlocked = previous.QUICBlocked
				report.CommandDNSRequired = previous.CommandDNSRequired
				report.RawSocketBlockConfigured = previous.RawSocketBlockConfigured
				report.RawSocketsBlocked = previous.RawSocketsBlocked
				report.UnsupportedTrafficAction = previous.UnsupportedTrafficAction
				report.BlockedTrafficClasses = append([]string(nil), previous.BlockedTrafficClasses...)
				report.UnsupportedTrafficBlocked = previous.UnsupportedTrafficBlocked
				report.FailClosedSetup = previous.FailClosedSetup
				report.Attachment = previous.Attachment
				report.Detail = previous.Detail
				report.Warning = previous.Warning
				report.Normalize()
				return report
			}
			if previous.Status == types.NetworkEnforcementStatusFailed {
				report.Status = previous.Status
				report.Readiness = types.NetworkEnforcementStatusFailed
				report.Tier = previous.Tier
				report.FailClosedSetup = previous.FailClosedSetup
				report.Attachment = previous.Attachment
				report.Detail = previous.Detail
				report.Warning = previous.Warning
				report.Normalize()
				return report
			}
			if previous.Status == types.NetworkEnforcementStatusReady && previous.Proven() && report.CgroupDelegated && report.HelperConfigured && report.ProxyReady {
				report.Status = types.NetworkEnforcementStatusReady
				report.Readiness = types.NetworkEnforcementStatusReady
				report.Tier = previous.Tier
				report.HelperAuthenticated = previous.HelperAuthenticated
				report.ToolBoundaryActive = previous.ToolBoundaryActive
				report.ProxyRequired = previous.ProxyRequired
				report.ExactProxyOnly = previous.ExactProxyOnly
				report.AllowedTransport = previous.AllowedTransport
				report.DirectBypassBlocked = previous.DirectBypassBlocked
				report.DirectTCPBlocked = previous.DirectTCPBlocked
				report.LocalNonProxyTCPBlocked = previous.LocalNonProxyTCPBlocked
				report.UDPBlocked = previous.UDPBlocked
				report.QUICBlocked = previous.QUICBlocked
				report.CommandDNSRequired = previous.CommandDNSRequired
				report.RawSocketBlockConfigured = previous.RawSocketBlockConfigured
				report.RawSocketsBlocked = previous.RawSocketsBlocked
				report.UnsupportedTrafficAction = previous.UnsupportedTrafficAction
				report.BlockedTrafficClasses = append([]string(nil), previous.BlockedTrafficClasses...)
				report.UnsupportedTrafficBlocked = previous.UnsupportedTrafficBlocked
				report.FailClosedSetup = previous.FailClosedSetup
				report.Detail = previous.Detail
				report.Warning = previous.Warning
				report.Normalize()
				return report
			}
		}
	}

	switch {
	case report.HelperConfigured && report.ProxyReady && strict:
		report.Status = types.NetworkEnforcementStatusDegraded
		report.Tier = types.NetworkEnforcementTierHelperEBPFProxyRequired
		report.Detail = "delegated cgroup, helper socket, and proxy are available; readiness is withheld because helper attachment, direct-bypass behavior, and the same-UID tool boundary are not all proven"
	case report.CgroupDelegated:
		report.Status = types.NetworkEnforcementStatusDegraded
		report.Tier = types.NetworkEnforcementTierCgroupDelegated
		report.Detail = "the runtime cgroup probe succeeded, but no authenticated helper/proxy command gate is active"
	case report.Requested != types.NetworkEnforcementRequestNone:
		report.Status = types.NetworkEnforcementStatusDegraded
		report.Detail = "network enforcement was requested but runtime prerequisites are unavailable"
	default:
		report.Status = types.NetworkEnforcementStatusNone
		report.Detail = "no runtime network gate was requested"
		report.Warning = "no runtime network gate is active; policy decisions do not imply traffic enforcement"
	}
	if report.Requested != types.NetworkEnforcementRequestNone {
		report.Warning = "network policy decisions are informational until status is ready; autonomous strict startup must refuse this report"
	}
	report.Normalize()
	return report
}

func (a *App) refreshNetworkEnforcement(sessionID string) *types.NetworkEnforcement {
	report := a.observedNetworkEnforcement(sessionID)
	if a != nil && a.sessions != nil {
		if sess, ok := a.sessions.Get(sessionID); ok {
			sess.SetNetworkEnforcement(report)
		}
	}
	return report
}

func networkEndpointPresent(endpoints []string, endpoint string) bool {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return false
	}
	for _, candidate := range endpoints {
		if strings.TrimSpace(candidate) == endpoint {
			return true
		}
	}
	return false
}

func (a *App) recordNetworkAttachment(sessionID, commandID, cgroupPath string, cgroupID uint64, tier types.NetworkEnforcementTier, registrationID string, helperAuthenticated bool, proxyEndpoints []string, allowEntries, denyEntries int, defaultDeny, proxyRequired, pinned, reloaded bool) {
	if a == nil || a.sessions == nil {
		return
	}
	sess, ok := a.sessions.Get(sessionID)
	if !ok {
		return
	}
	report := a.observedNetworkEnforcement(sessionID)
	preflightReady := report.Preflight != nil && report.Preflight.Proven()
	if preflightReady && !networkEndpointPresent(proxyEndpoints, report.Preflight.ProxyEndpointID) {
		preflightReady = false
	}
	directBlocked := proxyRequired && defaultDeny
	unsupportedTrafficAction := "policy-map"
	var blockedTraffic []string
	if proxyRequired {
		unsupportedTrafficAction = "deny"
		blockedTraffic = []string{"direct-tcp", "local-non-proxy-tcp", "udp", "quic", "command-dns"}
		if preflightReady {
			blockedTraffic = append(blockedTraffic, "raw-ip", "packet")
		}
	}
	report.Status = types.NetworkEnforcementStatusActive
	report.Tier = tier
	report.CgroupDelegated = true
	report.HelperConfigured = true
	report.HelperAuthenticated = helperAuthenticated
	report.ToolBoundaryActive = preflightReady
	report.FailClosedSetup = true
	report.ProxyRequired = proxyRequired
	report.ExactProxyOnly = proxyRequired
	report.AllowedTransport = "policy-map"
	if proxyRequired {
		report.AllowedTransport = "tcp"
	}
	report.DirectBypassBlocked = directBlocked
	report.DirectTCPBlocked = directBlocked
	report.LocalNonProxyTCPBlocked = directBlocked
	report.UDPBlocked = directBlocked
	report.QUICBlocked = directBlocked
	report.CommandDNSRequired = !proxyRequired
	report.RawSocketBlockConfigured = proxyRequired
	// Raw and unsupported classes are command-scoped only after the disposable
	// command-jail probe proved the installed filter and boundary. Attachment
	// success by itself must not manufacture these observations.
	report.RawSocketsBlocked = preflightReady && proxyRequired
	report.UnsupportedTrafficAction = unsupportedTrafficAction
	report.BlockedTrafficClasses = blockedTraffic
	report.UnsupportedTrafficBlocked = preflightReady && proxyRequired
	proxyEndpoint := ""
	if preflightReady {
		proxyEndpoint = report.Preflight.ProxyEndpointID
	} else if len(proxyEndpoints) > 0 {
		proxyEndpoint = proxyEndpoints[0]
	}
	if proxyEndpoint != "" {
		report.ProxyEndpointID = proxyEndpoint
	}
	report.Attachment = &types.NetworkAttachmentEvidence{
		Status:                    types.NetworkEnforcementStatusActive,
		Tier:                      tier,
		Mode:                      string(nethelper.BuiltinModeCgroupConnectGate),
		CommandID:                 commandID,
		CgroupPath:                cgroupPath,
		CgroupID:                  cgroupID,
		RegistrationID:            registrationID,
		HelperAuthenticated:       helperAuthenticated,
		ProxyEndpointID:           proxyEndpoint,
		ProxyEndpointIDs:          append([]string(nil), proxyEndpoints...),
		AllowEntries:              allowEntries,
		DenyEntries:               denyEntries,
		DefaultDeny:               defaultDeny,
		InitialPolicyLocked:       true,
		PolicyUpdateFailClosed:    true,
		ChildStoppedDuringSetup:   true,
		ProxyRequired:             proxyRequired,
		ExactProxyOnly:            proxyRequired,
		AllowedTransport:          report.AllowedTransport,
		DirectBypassBlocked:       directBlocked,
		DirectTCPBlocked:          directBlocked,
		LocalNonProxyTCPBlocked:   directBlocked,
		UDPBlocked:                directBlocked,
		QUICBlocked:               directBlocked,
		CommandDNSRequired:        !proxyRequired,
		RawSocketBlockConfigured:  proxyRequired,
		RawSocketsBlocked:         preflightReady && proxyRequired,
		UnsupportedTrafficAction:  unsupportedTrafficAction,
		BlockedTrafficClasses:     append([]string(nil), blockedTraffic...),
		UnsupportedTrafficBlocked: preflightReady && proxyRequired,
		TransparentRedirect:       false,
		Pinned:                    pinned,
		Reloaded:                  reloaded,
		CheckedAt:                 time.Now().UTC(),
		Detail:                    "helper registration, locked initial state, and exact proxy default-deny map update succeeded before command resume",
	}
	if preflightReady {
		report.Detail = "a per-command helper proxy-required gate is active after the disposable boundary and bypass preflight passed"
		report.Warning = ""
	} else {
		report.Detail = "a per-command helper proxy-required gate is active; full session enforcement is not claimed without the installed same-UID boundary and unsupported-traffic preflight"
		report.Warning = "active attachment evidence does not by itself prove the installed tool boundary or raw-socket denial"
	}
	report.Normalize()
	sess.SetNetworkEnforcement(report)
	a.emitNetworkEnforcementEvidence("network_enforcement_active", sessionID, commandID, report)
}

func (a *App) recordDirectNetworkAttachment(sessionID, commandID, cgroupPath string, cgroupID uint64, proxyEndpoints []string, allowEntries, denyEntries int, defaultDeny, proxyRequired bool) {
	if a == nil || a.sessions == nil {
		return
	}
	sess, ok := a.sessions.Get(sessionID)
	if !ok {
		return
	}
	report := a.observedNetworkEnforcement(sessionID)
	directBlocked := proxyRequired && defaultDeny
	blockedTraffic := []string{"direct-tcp", "local-non-proxy-tcp", "udp", "quic", "command-dns"}
	report.Status = types.NetworkEnforcementStatusActive
	report.Tier = types.NetworkEnforcementTierCgroupDelegated
	report.CgroupDelegated = true
	report.HelperAuthenticated = false
	report.FailClosedSetup = true
	report.ProxyRequired = proxyRequired
	report.ExactProxyOnly = proxyRequired
	report.AllowedTransport = "policy-map"
	if proxyRequired {
		report.AllowedTransport = "tcp"
	}
	report.DirectBypassBlocked = directBlocked
	report.DirectTCPBlocked = directBlocked
	report.LocalNonProxyTCPBlocked = directBlocked
	report.UDPBlocked = directBlocked
	report.QUICBlocked = directBlocked
	report.CommandDNSRequired = !proxyRequired
	report.RawSocketBlockConfigured = proxyRequired
	report.RawSocketsBlocked = false
	report.UnsupportedTrafficAction = "deny"
	report.BlockedTrafficClasses = blockedTraffic
	report.UnsupportedTrafficBlocked = false
	proxyEndpoint := ""
	if len(proxyEndpoints) > 0 {
		proxyEndpoint = proxyEndpoints[0]
		report.ProxyEndpointID = proxyEndpoint
	}
	report.Attachment = &types.NetworkAttachmentEvidence{
		Status:                    types.NetworkEnforcementStatusActive,
		Tier:                      types.NetworkEnforcementTierCgroupDelegated,
		Mode:                      string(nethelper.BuiltinModeCgroupConnectGate),
		CommandID:                 commandID,
		CgroupPath:                cgroupPath,
		CgroupID:                  cgroupID,
		HelperAuthenticated:       false,
		ProxyEndpointID:           proxyEndpoint,
		ProxyEndpointIDs:          append([]string(nil), proxyEndpoints...),
		AllowEntries:              allowEntries,
		DenyEntries:               denyEntries,
		DefaultDeny:               defaultDeny,
		InitialPolicyLocked:       true,
		PolicyUpdateFailClosed:    true,
		ChildStoppedDuringSetup:   true,
		ProxyRequired:             proxyRequired,
		ExactProxyOnly:            proxyRequired,
		AllowedTransport:          report.AllowedTransport,
		DirectBypassBlocked:       directBlocked,
		DirectTCPBlocked:          directBlocked,
		LocalNonProxyTCPBlocked:   directBlocked,
		UDPBlocked:                directBlocked,
		QUICBlocked:               directBlocked,
		CommandDNSRequired:        !proxyRequired,
		RawSocketBlockConfigured:  proxyRequired,
		RawSocketsBlocked:         false,
		UnsupportedTrafficAction:  "deny",
		BlockedTrafficClasses:     append([]string(nil), blockedTraffic...),
		UnsupportedTrafficBlocked: false,
		TransparentRedirect:       false,
		CheckedAt:                 time.Now().UTC(),
		Detail:                    "in-process locked initial state, exact proxy map update, and fixed-program attachment succeeded before command resume",
	}
	report.Detail = "a per-command in-process proxy-required cgroup eBPF gate is active; helper crash persistence and the installed same-UID boundary are not proven"
	report.Warning = "in-process attachment is degraded and cannot claim full network policy enforcement"
	report.Normalize()
	sess.SetNetworkEnforcement(report)
	a.emitNetworkEnforcementEvidence("network_enforcement_active_degraded", sessionID, commandID, report)
}

func (a *App) recordNetworkAttachmentEnded(sessionID, commandID string) {
	if a == nil || a.sessions == nil {
		return
	}
	sess, ok := a.sessions.Get(sessionID)
	if !ok {
		return
	}
	previous := sess.NetworkEnforcement()
	if previous == nil || previous.Attachment == nil || previous.Attachment.CommandID != commandID {
		return
	}
	report := a.observedNetworkEnforcement(sessionID)
	report.Attachment = nil
	if report.Preflight != nil && report.Preflight.Proven() {
		// Readiness is session-scoped. Ending one command removes only the active
		// attachment; it must not erase the disposable preflight or turn ready
		// into a misleading degraded state.
		report.Status = types.NetworkEnforcementStatusReady
		report.Readiness = types.NetworkEnforcementStatusReady
		report.Detail = "session preflight remains ready; the completed command attachment was cleaned successfully"
		report.Warning = ""
	} else {
		report.Status = types.NetworkEnforcementStatusDegraded
		report.Readiness = types.NetworkEnforcementStatusDegraded
		report.ProxyRequired = false
		report.ExactProxyOnly = false
		report.AllowedTransport = ""
		report.DirectBypassBlocked = false
		report.DirectTCPBlocked = false
		report.LocalNonProxyTCPBlocked = false
		report.UDPBlocked = false
		report.QUICBlocked = false
		report.CommandDNSRequired = false
		report.RawSocketBlockConfigured = false
		report.RawSocketsBlocked = false
		report.UnsupportedTrafficAction = ""
		report.BlockedTrafficClasses = nil
		report.UnsupportedTrafficBlocked = false
		report.FailClosedSetup = report.Preflight != nil && report.Preflight.FailClosedBarrierProven
		report.Detail = "a disposable or completed command attachment was observed; no proven session preflight is available"
		report.Warning = "network policy enforcement is not ready for strict autonomous startup"
	}
	report.Normalize()
	sess.SetNetworkEnforcement(report)
	a.emitNetworkEnforcementEvidence("network_enforcement_inactive", sessionID, commandID, report)
}

func isNetworkPreExecFailure(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, marker := range []string{
		"post-start hook",
		"post-start cleanup",
		"pre-exec",
		"command jail",
		"command-jail",
		"command boundary",
		"command-boundary",
		"resume traced process",
		"wrapper ready",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func (a *App) recordNetworkEnforcementFailure(sessionID, commandID string, err error) {
	if a == nil || a.sessions == nil {
		return
	}
	sess, ok := a.sessions.Get(sessionID)
	if !ok {
		return
	}
	report := a.observedNetworkEnforcement(sessionID)
	report.Status = types.NetworkEnforcementStatusFailed
	report.Readiness = types.NetworkEnforcementStatusFailed
	report.FailClosedSetup = true
	report.ProxyRequired = false
	report.ExactProxyOnly = false
	report.AllowedTransport = ""
	report.DirectBypassBlocked = false
	report.DirectTCPBlocked = false
	report.LocalNonProxyTCPBlocked = false
	report.UDPBlocked = false
	report.QUICBlocked = false
	report.CommandDNSRequired = false
	report.RawSocketBlockConfigured = false
	report.RawSocketsBlocked = false
	report.UnsupportedTrafficAction = "deny"
	report.BlockedTrafficClasses = nil
	report.UnsupportedTrafficBlocked = false
	report.Attachment = &types.NetworkAttachmentEvidence{
		Status:    types.NetworkEnforcementStatusFailed,
		CommandID: commandID,
		CheckedAt: time.Now().UTC(),
	}
	if err != nil {
		report.Detail = "command network setup failed before resume: " + err.Error()
	} else {
		report.Detail = "command network setup failed before resume"
	}
	report.Warning = "command execution was refused because required runtime network setup failed"
	report.Normalize()
	sess.SetNetworkEnforcement(report)
	a.emitNetworkEnforcementEvidence("network_enforcement_failed", sessionID, commandID, report)
}

func (a *App) recordNetworkCleanupFailure(sessionID, commandID string, err error) {
	if a == nil || a.sessions == nil {
		return
	}
	sess, ok := a.sessions.Get(sessionID)
	if !ok {
		return
	}
	report := a.observedNetworkEnforcement(sessionID)
	report.Status = types.NetworkEnforcementStatusFailed
	report.Readiness = types.NetworkEnforcementStatusFailed
	report.ProxyRequired = false
	report.ExactProxyOnly = false
	report.AllowedTransport = ""
	report.DirectBypassBlocked = false
	report.DirectTCPBlocked = false
	report.LocalNonProxyTCPBlocked = false
	report.UDPBlocked = false
	report.QUICBlocked = false
	report.CommandDNSRequired = false
	report.RawSocketBlockConfigured = false
	report.RawSocketsBlocked = false
	report.UnsupportedTrafficAction = "deny"
	report.BlockedTrafficClasses = nil
	report.UnsupportedTrafficBlocked = false
	if report.Attachment == nil || report.Attachment.CommandID != commandID {
		report.Attachment = &types.NetworkAttachmentEvidence{
			Status:    types.NetworkEnforcementStatusFailed,
			CommandID: commandID,
			CheckedAt: time.Now().UTC(),
		}
	} else {
		report.Attachment.Status = types.NetworkEnforcementStatusFailed
		report.Attachment.CheckedAt = time.Now().UTC()
	}
	if err != nil {
		report.Detail = "command network cleanup failed: " + err.Error()
	} else {
		report.Detail = "command network cleanup failed"
	}
	report.Warning = "helper or cgroup resources may remain pinned fail closed; operator cleanup may be required"
	report.Normalize()
	sess.SetNetworkEnforcement(report)
	a.emitNetworkEnforcementEvidence("network_enforcement_cleanup_failed", sessionID, commandID, report)
}

func (a *App) emitNetworkEnforcementEvidence(eventType, sessionID, commandID string, report *types.NetworkEnforcement) {
	if a == nil || report == nil {
		return
	}
	fields := networkEnforcementMap(report)
	if fields == nil {
		fields = map[string]any{"network_policy_enforced": false}
	}
	// The report schema has no credential fields. Registration IDs are already
	// one-way evidence IDs, never the helper-selected opaque handle.
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      eventType,
		SessionID: sessionID,
		CommandID: commandID,
		Fields:    fields,
	}
	if a.store != nil {
		_ = a.store.AppendEvent(context.Background(), ev)
	}
	if a.broker != nil {
		a.broker.Publish(ev)
	}
}

func networkEnforcementMap(report *types.NetworkEnforcement) map[string]any {
	if report == nil {
		return nil
	}
	data, err := json.Marshal(report)
	if err != nil {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	return out
}

type networkRuntimeProbeResult struct {
	MarkerWritten              bool   `json:"marker_written"`
	ProxyConnectProven         bool   `json:"proxy_connect_proven"`
	LocalDirectTCPBlocked      bool   `json:"local_direct_tcp_blocked"`
	UDPBlocked                 bool   `json:"udp_blocked"`
	RawSocketsBlocked          bool   `json:"raw_sockets_blocked"`
	PrivateProcProven          bool   `json:"private_proc_proven"`
	CgroupFSHidden             bool   `json:"cgroupfs_hidden"`
	HelperSocketHidden         bool   `json:"helper_socket_hidden"`
	CredentialSourceHidden     bool   `json:"credential_source_hidden"`
	ControlPathsHidden         bool   `json:"control_paths_hidden"`
	ReservedEnvScrubbed        bool   `json:"reserved_env_scrubbed"`
	InheritedDescriptorsClosed bool   `json:"inherited_descriptors_closed"`
	NoNewPrivileges            bool   `json:"no_new_privs"`
	CapabilitiesDropped        bool   `json:"capabilities_dropped"`
	Detail                     string `json:"detail,omitempty"`
}

type networkRuntimeProbeOptions struct {
	MarkerPath        string
	ProxyEndpoint     string
	DirectTCPEndpoint string
	UDPEndpoint       string
	CgroupRoot        string
	HelperSocket      string
	CredentialFile    string
	ControlPath       string
	InheritedFile     string
}

// runNetworkEnforcementPreflight executes two disposable stopped children. The
// first is intentionally refused and proves that the release barrier leaves
// user code stopped. The second traverses the production command-jail and
// cgroup hook, causing real helper registration, fixed-program attachment,
// locked default-deny map update, local-only bypass probes, and helper cleanup.
func (a *App) runNetworkEnforcementPreflight(ctx context.Context, sessionID string) *types.NetworkEnforcement {
	report := a.observedNetworkEnforcement(sessionID)
	if report.Requested == types.NetworkEnforcementRequestNone {
		report.Readiness = types.NetworkEnforcementStatusNone
		report.Status = types.NetworkEnforcementStatusNone
		report.Preflight = nil
		report.Normalize()
		if a != nil && a.sessions != nil {
			if sess, ok := a.sessions.Get(sessionID); ok {
				sess.SetNetworkEnforcement(report)
			}
		}
		return report
	}

	checkedAt := time.Now().UTC()
	preflight := &types.NetworkPreflightEvidence{
		Status:    types.NetworkEnforcementStatusDegraded,
		CheckedAt: checkedAt,
	}
	if a == nil || a.cfg == nil || a.sessions == nil {
		return a.finishNetworkEnforcementPreflight(sessionID, nil, report, preflight, "runtime preflight dependencies are unavailable", false)
	}
	sess, ok := a.sessions.Get(sessionID)
	if !ok {
		return a.finishNetworkEnforcementPreflight(sessionID, nil, report, preflight, "session is unavailable", false)
	}

	// Invalidate any older ready object before touching disposable resources. A
	// failed or interrupted recheck must never leave a stale true claim behind.
	report.Readiness = types.NetworkEnforcementStatusDegraded
	report.Status = types.NetworkEnforcementStatusDegraded
	report.NetworkPolicyEnforced = false
	report.Preflight = preflight
	report.Attachment = nil
	report.Warning = "runtime network preflight is in progress; previous readiness is invalid"
	report.Normalize()
	sess.SetNetworkEnforcement(report)

	unlock := sess.LockExec()
	defer unlock()

	if runtime.GOOS != "linux" {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "proxy-required preflight is only available on Linux", false)
	}
	if launchMode := strings.TrimSpace(os.Getenv(detached.EnvSupervisorLaunchMode)); launchMode != "systemd-user-delegated" {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "the supervisor was not launched through the supported delegated systemd user-service path", false)
	}
	if !supportedDelegatedSupervisorCgroup(report.CgroupRoot) {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "the observed cgroup root is not the delegated AgentSH transient supervisor unit", false)
	}
	if !commandJailRequired(a.cfg) {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "the strict command jail is not required by this runtime configuration", false)
	}
	if !a.cfg.Approvals.Enabled || a.approvals == nil {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "the synchronous AgentSH approval resolver is unavailable", false)
	}
	if a.ptraceTracer != nil {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "strict command-jail preflight cannot run with ptrace execution", false)
	}
	if strings.TrimSpace(a.nethelperCredential) == "" {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "the trusted supervisor has no in-memory nethelper instance credential", false)
	}
	if strings.TrimSpace(a.nethelperCredentialFile) == "" {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "the installed protected nethelper credential source was not supplied", false)
	}
	helperSocket := strings.TrimSpace(os.Getenv(nethelper.EnvSocket))
	if helperSocket == "" {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "the privileged nethelper socket is not configured", false)
	}

	proxyURL := strings.TrimSpace(sess.ProxyURL())
	proxyAddr, err := exactLoopbackProxyAddrPort(proxyURL)
	if err != nil {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "resolve exact AgentSH proxy listener: "+err.Error(), false)
	}
	preflight.ProxyEndpointID = proxyAddr.String()
	preflight.ProxyListenerProven = probeLoopbackProxy(proxyAddr.String())
	if !preflight.ProxyListenerProven {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "the actual AgentSH proxy listener did not accept a readiness connection", false)
	}

	tcpListener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", "0"))
	if err != nil {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "start local direct-bypass TCP listener: "+err.Error(), false)
	}
	defer tcpListener.Close()
	tcpAccepted := make(chan bool, 1)
	go func() {
		conn, acceptErr := tcpListener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
			tcpAccepted <- true
			return
		}
		tcpAccepted <- false
	}()

	udpAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort("127.0.0.1", "0"))
	if err != nil {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "resolve local UDP probe listener: "+err.Error(), false)
	}
	udpListener, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "start local UDP probe listener: "+err.Error(), false)
	}
	defer udpListener.Close()

	probeDir := strings.TrimSpace(sess.RuntimeTmpPath())
	if probeDir == "" {
		probeDir = os.TempDir()
	}
	if err := os.MkdirAll(probeDir, 0o700); err != nil {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "prepare disposable preflight directory: "+err.Error(), false)
	}
	probeID := "network-preflight-" + uuid.NewString()
	refusalMarker := filepath.Join(probeDir, probeID+"-refusal-marker")
	runtimeMarker := filepath.Join(probeDir, probeID+"-runtime-marker")
	inheritedPath := filepath.Join(probeDir, probeID+"-inherited-fd")
	defer os.Remove(refusalMarker)
	defer os.Remove(runtimeMarker)
	defer os.Remove(inheritedPath)

	probeOpts := networkRuntimeProbeOptions{
		ProxyEndpoint:     proxyAddr.String(),
		DirectTCPEndpoint: tcpListener.Addr().String(),
		UDPEndpoint:       udpListener.LocalAddr().String(),
		CgroupRoot:        report.CgroupRoot,
		HelperSocket:      helperSocket,
		CredentialFile:    a.nethelperCredentialFile,
		ControlPath:       a.cfg.Server.UnixSocket.Path,
	}
	if strings.TrimSpace(probeOpts.ControlPath) == "" {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "the detached supervisor control socket path is unavailable for boundary probing", false)
	}

	barrierProven, barrierDetail := a.proveNetworkPreExecRefusal(ctx, sess, sessionID, probeID+"-refusal", refusalMarker, probeOpts)
	preflight.FailClosedBarrierProven = barrierProven
	preflight.RefusalLeftChildStopped = barrierProven
	if !barrierProven {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, barrierDetail, false)
	}

	inheritedFile, err := os.OpenFile(inheritedPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "create inherited-descriptor sentinel: "+err.Error(), false)
	}
	defer inheritedFile.Close()
	probeOpts.MarkerPath = runtimeMarker
	probeOpts.InheritedFile = inheritedPath

	commandID := "cmd-" + probeID
	preflight.CommandID = commandID
	sess.SetCurrentCommandID(commandID)
	wrappedReq, extra, err := a.prepareNetworkRuntimeProbe(sessionID, sess, commandID, probeOpts)
	if err != nil {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, err.Error(), false)
	}
	if !commandBoundaryRequired(extra) {
		closePreStartProcessFiles(extra)
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "strict wrapper did not select the command-jail boundary", false)
	}
	extra.extraFiles = append(extra.extraFiles, inheritedFile)

	var attachment *types.NetworkAttachmentEvidence
	var cleanupProven bool
	var childStoppedDuringSetup bool
	baseHook := a.cgroupHook(sessionID, commandID, policy.Limits{})
	if baseHook == nil {
		closePreStartProcessFiles(extra)
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "runtime cgroup hook is unavailable", false)
	}
	probeHook := func(pid int) (func() error, error) {
		_, beforeErr := os.Lstat(runtimeMarker)
		stoppedBefore := errors.Is(beforeErr, os.ErrNotExist)
		cleanup, setupErr := baseHook(pid)
		wrapCleanup := func() error {
			if cleanup == nil {
				return fmt.Errorf("preflight cgroup/helper cleanup callback is missing")
			}
			cleanupErr := cleanup()
			cleanupProven = cleanupErr == nil
			return cleanupErr
		}
		if setupErr != nil {
			return wrapCleanup, setupErr
		}
		active := sess.NetworkEnforcement()
		if active == nil || active.Attachment == nil {
			return wrapCleanup, fmt.Errorf("helper setup returned without per-command attachment evidence")
		}
		attachmentCopy := *active.Attachment
		attachmentCopy.ProxyEndpointIDs = append([]string(nil), active.Attachment.ProxyEndpointIDs...)
		attachmentCopy.BlockedTrafficClasses = append([]string(nil), active.Attachment.BlockedTrafficClasses...)
		attachment = &attachmentCopy
		_, afterErr := os.Lstat(runtimeMarker)
		childStoppedDuringSetup = stoppedBefore && errors.Is(afterErr, os.ErrNotExist)
		if !childStoppedDuringSetup {
			return wrapCleanup, fmt.Errorf("disposable user code ran before helper setup completed")
		}
		if !cgroupContainsPID(attachment.CgroupPath, pid) {
			return wrapCleanup, fmt.Errorf("disposable child PID was not observed in the attached command cgroup")
		}
		return wrapCleanup, nil
	}

	exitCode, stdout, _, _, _, _, _, _, runErr := runCommandWithResources(
		ctx,
		sess,
		commandID,
		wrappedReq,
		a.cfg,
		policy.ResolvedEnvPolicy{},
		0,
		probeHook,
		extra,
		nil,
		sessionID,
	)
	if runErr != nil {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "disposable runtime probe failed: "+runErr.Error(), false)
	}
	if exitCode != 0 {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, fmt.Sprintf("disposable runtime probe exited %d", exitCode), false)
	}
	var runtimeProbe networkRuntimeProbeResult
	if err := json.Unmarshal(bytes.TrimSpace(stdout), &runtimeProbe); err != nil {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "decode disposable runtime probe evidence: "+err.Error(), false)
	}

	directListenerUnreached := true
	select {
	case accepted := <-tcpAccepted:
		directListenerUnreached = !accepted
	case <-time.After(200 * time.Millisecond):
	}
	udpListenerUnreached := false
	_ = udpListener.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	udpBuffer := make([]byte, 64)
	if _, _, readErr := udpListener.ReadFromUDP(udpBuffer); readErr != nil {
		var netErr net.Error
		udpListenerUnreached = errors.As(readErr, &netErr) && netErr.Timeout()
	}

	if attachment == nil {
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "disposable helper attachment evidence is missing", false)
	}
	preflight.CgroupPath = attachment.CgroupPath
	preflight.CgroupID = attachment.CgroupID
	preflight.RegistrationID = attachment.RegistrationID
	preflight.CgroupPlacementProven = childStoppedDuringSetup && attachment.CgroupID != 0 && strings.TrimSpace(attachment.CgroupPath) != ""
	preflight.HelperAuthenticated = attachment.HelperAuthenticated
	preflight.HelperAttachProven = attachment.Status == types.NetworkEnforcementStatusActive && attachment.Tier == types.NetworkEnforcementTierHelperEBPFProxyRequired
	preflight.DefaultDenyMapProven = attachment.DefaultDeny && attachment.AllowEntries > 0
	preflight.InitialPolicyLocked = attachment.InitialPolicyLocked
	preflight.PolicyUpdateFailClosed = attachment.PolicyUpdateFailClosed
	preflight.HelperCleanupProven = cleanupProven
	preflight.Pinned = attachment.Pinned
	preflight.Reloaded = attachment.Reloaded
	preflight.ProxyConnectProven = runtimeProbe.ProxyConnectProven
	preflight.ToolBoundaryProven = runtimeProbe.PrivateProcProven && runtimeProbe.CgroupFSHidden && runtimeProbe.HelperSocketHidden && runtimeProbe.CredentialSourceHidden && runtimeProbe.ControlPathsHidden && runtimeProbe.ReservedEnvScrubbed && runtimeProbe.InheritedDescriptorsClosed && runtimeProbe.NoNewPrivileges && runtimeProbe.CapabilitiesDropped
	preflight.PrivateProcProven = runtimeProbe.PrivateProcProven
	preflight.CgroupFSHidden = runtimeProbe.CgroupFSHidden
	preflight.HelperSocketHidden = runtimeProbe.HelperSocketHidden
	preflight.CredentialSourceHidden = runtimeProbe.CredentialSourceHidden
	preflight.ControlPathsHidden = runtimeProbe.ControlPathsHidden
	preflight.ReservedEnvScrubbed = runtimeProbe.ReservedEnvScrubbed
	preflight.InheritedDescriptorsClosed = runtimeProbe.InheritedDescriptorsClosed
	preflight.NoNewPrivileges = runtimeProbe.NoNewPrivileges
	preflight.CapabilitiesDropped = runtimeProbe.CapabilitiesDropped
	preflight.LocalDirectTCPBlocked = runtimeProbe.LocalDirectTCPBlocked && directListenerUnreached
	preflight.DirectBypassProven = preflight.LocalDirectTCPBlocked
	preflight.UDPBlocked = runtimeProbe.UDPBlocked && udpListenerUnreached
	preflight.RawSocketsBlocked = runtimeProbe.RawSocketsBlocked
	preflight.UnsupportedTrafficProven = preflight.UDPBlocked && preflight.RawSocketsBlocked
	preflight.ChildStoppedDuringSetup = childStoppedDuringSetup && runtimeProbe.MarkerWritten
	preflight.Status = types.NetworkEnforcementStatusReady

	if !preflight.Proven() {
		detail := "disposable preflight completed but one or more required observations were not proven"
		if strings.TrimSpace(runtimeProbe.Detail) != "" {
			detail += ": " + runtimeProbe.Detail
		}
		return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, detail, false)
	}
	return a.finishNetworkEnforcementPreflight(sessionID, sess, report, preflight, "disposable cgroup/helper/proxy/command-jail/bypass/cleanup preflight passed", true)
}

func (a *App) prepareNetworkRuntimeProbe(sessionID string, sess *session.Session, commandID string, opts networkRuntimeProbeOptions) (types.ExecRequest, *extraProcConfig, error) {
	executable, err := os.Executable()
	if err != nil {
		return types.ExecRequest{}, nil, fmt.Errorf("locate AgentSH preflight executable: %w", err)
	}
	args := []string{
		"debug", "network-runtime-probe",
		"--marker", opts.MarkerPath,
		"--proxy", opts.ProxyEndpoint,
		"--direct-tcp", opts.DirectTCPEndpoint,
		"--udp", opts.UDPEndpoint,
		"--supervisor-pid", strconv.Itoa(os.Getpid()),
		"--cgroup-root", opts.CgroupRoot,
		"--helper-socket", opts.HelperSocket,
		"--credential-file", opts.CredentialFile,
		"--control-path", opts.ControlPath,
		"--inherited-file", opts.InheritedFile,
	}
	req := types.ExecRequest{
		Command: executable,
		Args:    args,
		Timeout: "10s",
		Env: map[string]string{
			"agentsh_nethelper_instance_credential": "preflight-must-be-scrubbed",
			"AGENTSH_DETACHED_EVENT_TOKEN":          "preflight-must-be-scrubbed",
			"Agentsh_Server":                        "preflight-must-be-scrubbed",
		},
	}
	wrapper := a.setupSeccompWrapper(req, sessionID, sess)
	if wrapper.setupErr != nil {
		return types.ExecRequest{}, nil, fmt.Errorf("prepare strict command-jail probe: %w", wrapper.setupErr)
	}
	if !commandBoundaryRequired(wrapper.extraCfg) {
		closePreStartProcessFiles(wrapper.extraCfg)
		return types.ExecRequest{}, nil, fmt.Errorf("strict command-jail probe did not receive a command boundary")
	}
	configJSON := wrapper.wrappedReq.Env["AGENTSH_SECCOMP_CONFIG"]
	var wrapperConfig seccompWrapperConfig
	if err := json.Unmarshal([]byte(configJSON), &wrapperConfig); err != nil {
		closePreStartProcessFiles(wrapper.extraCfg)
		return types.ExecRequest{}, nil, fmt.Errorf("decode strict command-jail probe config: %w", err)
	}
	if wrapperConfig.CommandJail == nil || !wrapperConfig.CommandJail.Required {
		closePreStartProcessFiles(wrapper.extraCfg)
		return types.ExecRequest{}, nil, fmt.Errorf("strict command-jail probe config omitted the required jail")
	}
	if !proxyRequiredRawSocketRulesConfigured(&wrapperConfig) {
		closePreStartProcessFiles(wrapper.extraCfg)
		return types.ExecRequest{}, nil, fmt.Errorf("strict command-jail probe config omitted fixed raw/packet socket creation denials")
	}
	// The probe is infrastructure evidence, not a policy operation. Keep the
	// wrapper ACK and strict socket rules, while disabling file/exec policy and
	// Landlock so an unrelated command policy cannot manufacture a preflight
	// failure before the boundary checks execute.
	wrapperConfig.UnixSocketEnabled = true
	wrapperConfig.SignalFilterEnabled = false
	wrapperConfig.ExecveEnabled = false
	wrapperConfig.FileMonitorEnabled = false
	wrapperConfig.InterceptMetadata = false
	wrapperConfig.WriteOnlyOpens = false
	wrapperConfig.BlockIOUring = false
	wrapperConfig.LandlockEnabled = false
	encoded, err := json.Marshal(wrapperConfig)
	if err != nil {
		closePreStartProcessFiles(wrapper.extraCfg)
		return types.ExecRequest{}, nil, fmt.Errorf("encode strict command-jail probe config: %w", err)
	}
	wrapper.wrappedReq.Env["AGENTSH_SECCOMP_CONFIG"] = string(encoded)
	wrapper.extraCfg.env["AGENTSH_SECCOMP_CONFIG"] = string(encoded)
	return wrapper.wrappedReq, wrapper.extraCfg, nil
}

func (a *App) proveNetworkPreExecRefusal(ctx context.Context, sess *session.Session, sessionID, commandID, markerPath string, opts networkRuntimeProbeOptions) (bool, string) {
	_ = os.Remove(markerPath)
	opts.MarkerPath = markerPath
	wrappedReq, extra, err := a.prepareNetworkRuntimeProbe(sessionID, sess, commandID, opts)
	if err != nil {
		return false, err.Error()
	}
	forcedRefusal := errors.New("intentional network preflight barrier refusal")
	hookSawStoppedChild := false
	hook := func(int) (func() error, error) {
		_, markerErr := os.Lstat(markerPath)
		hookSawStoppedChild = errors.Is(markerErr, os.ErrNotExist)
		return nil, forcedRefusal
	}
	exitCode, _, _, _, _, _, _, _, runErr := runCommandWithResources(
		ctx,
		sess,
		commandID,
		wrappedReq,
		a.cfg,
		policy.ResolvedEnvPolicy{},
		0,
		hook,
		extra,
		nil,
		sessionID,
	)
	_, markerErr := os.Lstat(markerPath)
	markerAbsent := errors.Is(markerErr, os.ErrNotExist)
	if !hookSawStoppedChild || !markerAbsent || !errors.Is(runErr, forcedRefusal) || exitCode != 127 {
		return false, "forced setup failure did not prove that the disposable child remained stopped"
	}
	return true, ""
}

func supportedDelegatedSupervisorCgroup(cgroupRoot string) bool {
	cgroupRoot = filepath.Clean(strings.TrimSpace(cgroupRoot))
	if cgroupRoot == "." || cgroupRoot == string(filepath.Separator) {
		return false
	}
	if filepath.Base(cgroupRoot) == "agentsh.leaf" {
		cgroupRoot = filepath.Dir(cgroupRoot)
	}
	unit := filepath.Base(cgroupRoot)
	return strings.HasPrefix(unit, "agentsh-supervisor-") && strings.HasSuffix(unit, ".service")
}

func cgroupContainsPID(cgroupPath string, pid int) bool {
	if strings.TrimSpace(cgroupPath) == "" || pid <= 0 {
		return false
	}
	data, err := os.ReadFile(filepath.Join(cgroupPath, "cgroup.procs"))
	if err != nil {
		return false
	}
	want := strconv.Itoa(pid)
	for _, field := range strings.Fields(string(data)) {
		if field == want {
			return true
		}
	}
	return false
}

func (a *App) finishNetworkEnforcementPreflight(sessionID string, sess *session.Session, report *types.NetworkEnforcement, preflight *types.NetworkPreflightEvidence, detail string, ready bool) *types.NetworkEnforcement {
	if report == nil {
		report = &types.NetworkEnforcement{}
	}
	if preflight == nil {
		preflight = &types.NetworkPreflightEvidence{}
	}
	preflight.CheckedAt = time.Now().UTC()
	preflight.Detail = strings.TrimSpace(detail)
	if ready {
		preflight.Status = types.NetworkEnforcementStatusReady
		if !preflight.Proven() {
			ready = false
			preflight.Detail = "ready preflight was rejected because required evidence was incomplete"
			detail = preflight.Detail
		}
	}
	report.Preflight = preflight
	report.CheckedAt = preflight.CheckedAt
	report.Attachment = nil
	report.NetworkPolicyEnforced = false

	if ready {
		preflight.Status = types.NetworkEnforcementStatusReady
		report.Readiness = types.NetworkEnforcementStatusReady
		report.Status = types.NetworkEnforcementStatusReady
		report.Tier = types.NetworkEnforcementTierHelperEBPFProxyRequired
		report.CgroupDelegated = preflight.CgroupPlacementProven
		report.HelperConfigured = true
		report.HelperAuthenticated = preflight.HelperAuthenticated
		report.ToolBoundaryActive = preflight.ToolBoundaryProven
		report.ProxyReady = preflight.ProxyListenerProven && preflight.ProxyConnectProven
		report.ProxyRequired = true
		report.ExactProxyOnly = true
		report.AllowedTransport = "tcp"
		report.ProxyEndpointID = preflight.ProxyEndpointID
		report.DirectBypassBlocked = preflight.DirectBypassProven
		report.DirectTCPBlocked = preflight.LocalDirectTCPBlocked
		report.LocalNonProxyTCPBlocked = preflight.LocalDirectTCPBlocked
		report.UDPBlocked = preflight.UDPBlocked
		report.QUICBlocked = preflight.UDPBlocked
		report.CommandDNSRequired = false
		report.RawSocketBlockConfigured = true
		report.RawSocketsBlocked = preflight.RawSocketsBlocked
		report.UnsupportedTrafficAction = "deny"
		report.BlockedTrafficClasses = []string{"direct-tcp", "local-non-proxy-tcp", "udp", "quic", "command-dns", "raw-ip", "packet"}
		report.UnsupportedTrafficBlocked = preflight.UnsupportedTrafficProven
		report.FailClosedSetup = preflight.FailClosedBarrierProven
		report.TransparentRedirect = false
		report.Detail = detail
		report.Warning = ""
	} else {
		preflight.Status = types.NetworkEnforcementStatusDegraded
		report.Readiness = types.NetworkEnforcementStatusDegraded
		report.Status = types.NetworkEnforcementStatusDegraded
		if report.Requested == types.NetworkEnforcementRequestStrict {
			preflight.Status = types.NetworkEnforcementStatusFailed
			report.Readiness = types.NetworkEnforcementStatusFailed
			report.Status = types.NetworkEnforcementStatusFailed
		}
		report.HelperAuthenticated = false
		report.ToolBoundaryActive = false
		report.ProxyRequired = false
		report.ExactProxyOnly = false
		report.AllowedTransport = ""
		report.DirectBypassBlocked = false
		report.DirectTCPBlocked = false
		report.LocalNonProxyTCPBlocked = false
		report.UDPBlocked = false
		report.QUICBlocked = false
		report.CommandDNSRequired = false
		report.RawSocketBlockConfigured = false
		report.RawSocketsBlocked = false
		report.UnsupportedTrafficAction = ""
		report.BlockedTrafficClasses = nil
		report.UnsupportedTrafficBlocked = false
		report.FailClosedSetup = preflight.FailClosedBarrierProven
		report.Detail = detail
		report.Warning = "runtime network preflight did not prove every required property; strict autonomous startup must refuse and best-effort operation remains degraded"
	}
	report.Normalize()
	if sess != nil {
		sess.SetNetworkEnforcement(report)
	}

	eventType := "network_enforcement_preflight_degraded"
	if report.Status == types.NetworkEnforcementStatusReady {
		eventType = "network_enforcement_preflight_ready"
	} else if report.Status == types.NetworkEnforcementStatusFailed {
		eventType = "network_enforcement_preflight_failed"
	}
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      eventType,
		SessionID: sessionID,
		Fields: map[string]any{
			"requested":                       report.Requested,
			"readiness":                       report.Readiness,
			"status":                          report.Status,
			"tier":                            report.Tier,
			"network_policy_enforced":         report.NetworkPolicyEnforced,
			"strict_startup_refusal_required": report.Requested == types.NetworkEnforcementRequestStrict && !report.Ready(),
			"preflight":                       preflight,
		},
	}
	if a != nil && a.store != nil {
		_ = a.store.AppendEvent(context.Background(), ev)
	}
	if a != nil && a.broker != nil {
		a.broker.Publish(ev)
	}
	return report
}

func (a *App) getSessionNetworkEnforcement(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	if a == nil || a.sessions == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "session manager unavailable"})
		return
	}
	if _, ok := a.sessions.Get(sessionID); !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}
	writeJSON(w, http.StatusOK, a.refreshNetworkEnforcement(sessionID))
}

func (a *App) preflightSessionNetworkEnforcement(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	if a == nil || a.sessions == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "session manager unavailable"})
		return
	}
	sess, ok := a.sessions.Get(sessionID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}
	if sess.Snapshot().State == types.SessionStateBusy {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "network enforcement preflight requires an idle session"})
		return
	}
	writeJSON(w, http.StatusOK, a.runNetworkEnforcementPreflight(r.Context(), sessionID))
}

func (a *App) policyTestRuntimeEnforcement(sessionID, op string) map[string]any {
	if !isNetworkPolicyTestOperation(op) {
		return nil
	}
	report := networkEnforcementMap(a.refreshNetworkEnforcement(sessionID))
	if report == nil {
		report = map[string]any{
			"requested":               string(types.NetworkEnforcementRequestNone),
			"readiness":               string(types.NetworkEnforcementStatusDegraded),
			"status":                  string(types.NetworkEnforcementStatusDegraded),
			"tier":                    string(types.NetworkEnforcementTierNone),
			"network_policy_enforced": false,
			"detail":                  "runtime enforcement evidence is unavailable",
		}
	}
	report["operation_executed"] = false
	report["policy_test_note"] = "policy-test evaluates a decision only; it does not execute or attach a gate for the tested operation"
	return report
}
