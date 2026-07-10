package detachedreport

import (
	"fmt"
	"strings"

	"github.com/agentsh/agentsh/internal/detached"
)

// NetworkReport is a consumer-facing, read-only rendering of detached runtime
// evidence. It never upgrades configuration or launch intent into readiness.
type NetworkReport struct {
	Requested string
	Readiness string
	Status    string
	Tier      string

	Label            string
	Summary          string
	Detail           string
	Warning          string
	PolicyEnforced   bool
	CgroupDelegated  bool
	RuntimeDivergent bool
}

const (
	unknownNetworkSummary = "Network enforcement: unknown (metadata does not report runtime evidence)"
	unknownNetworkWarning = "WARNING: Detached session metadata is missing network enforcement evidence; do not assume policy approvals are enforced."

	noNetworkSummary = "Network enforcement: none (network policy is not enforced at runtime)"
	noNetworkWarning = "WARNING: Detached policy checks may report approvals or denials, but commands can still connect because no runtime network gate is active."

	cgroupDelegatedSummary = "Network enforcement: cgroup-delegated-only (degraded; helper/proxy gate not ready)"
	cgroupDelegatedWarning = "WARNING: Cgroup readiness alone does not enforce policy; network traffic is not approval-gated."

	helperGateSummary = "Network enforcement: helper-ebpf-gate (degraded; proxy approval path not proven)"
	helperGateWarning = "WARNING: A helper gate without a proven AgentSH proxy path cannot service hostname-aware approvals."

	helperProxySummary = "Network enforcement: helper-ebpf-proxy-required (degraded; deployment prerequisites are incomplete)"
	helperProxyWarning = "WARNING: Helper/proxy availability, same-UID tool isolation, direct-bypass controls, and crash persistence are not all proven active."

	readyNetworkSummary = "Network enforcement: ready (helper+eBPF proxy-required tier proven)"
	readyNetworkDetail  = "Proxy-aware HTTP(S) is synchronously policy-gated; direct and unsupported command traffic is fail-closed."

	activeNetworkSummary = "Network enforcement: active (per-command fail-closed gate attached)"
	failedNetworkSummary = "Network enforcement: failed (required runtime setup was refused)"
)

// NetworkEnforcement formats detached network enforcement metadata for humans.
func NetworkEnforcement(meta *detached.NetworkEnforcement) NetworkReport {
	if meta == nil {
		return NetworkReport{
			Label:            "unknown",
			Summary:          unknownNetworkSummary,
			Warning:          unknownNetworkWarning,
			RuntimeDivergent: true,
		}
	}

	normalized := *meta
	normalized.Normalize()
	proven := normalized.Proven()
	report := NetworkReport{
		Requested:       string(normalized.Requested),
		Readiness:       string(normalized.Readiness),
		Status:          string(normalized.Status),
		Tier:            string(normalized.Tier),
		PolicyEnforced:  proven,
		CgroupDelegated: normalized.CgroupDelegated,
	}

	switch {
	case normalized.Status == detached.NetworkEnforcementStatusFailed:
		report.Label = "failed"
		report.Summary = failedNetworkSummary
		report.Warning = "WARNING: Required network setup failed before command resume or strict session startup."
		report.RuntimeDivergent = true
	case normalized.Status == detached.NetworkEnforcementStatusActive && proven:
		report.Label = "active"
		report.Summary = activeNetworkSummary
		report.Detail = readyNetworkDetail
	case normalized.Status == detached.NetworkEnforcementStatusReady && proven:
		report.Label = "ready"
		report.Summary = readyNetworkSummary
		report.Detail = readyNetworkDetail
	case normalized.Status == detached.NetworkEnforcementStatusActive:
		report.Label = "active-unproven"
		report.Summary = activeNetworkSummary + " (deployment prerequisites remain unproven)"
		report.Warning = helperProxyWarning
		report.RuntimeDivergent = true
	case normalized.Tier == detached.NetworkEnforcementTierCgroupDelegated:
		report.Label = "cgroup-delegated-only"
		report.Summary = cgroupDelegatedSummary
		report.Warning = cgroupDelegatedWarning
		report.RuntimeDivergent = true
	case normalized.Tier == detached.NetworkEnforcementTierHelperEBPFGate:
		report.Label = "helper-ebpf-gate-degraded"
		report.Summary = helperGateSummary
		report.Warning = helperGateWarning
		report.RuntimeDivergent = true
	case normalized.Tier == detached.NetworkEnforcementTierHelperEBPFProxy || normalized.Tier == detached.NetworkEnforcementTierHelperEBPFProxyRequired:
		report.Label = "helper-ebpf-proxy-required-degraded"
		report.Summary = helperProxySummary
		report.Warning = helperProxyWarning
		report.RuntimeDivergent = true
	default:
		report.Label = "none"
		report.Summary = noNetworkSummary
		report.Warning = noNetworkWarning
		report.RuntimeDivergent = true
	}

	if detail := strings.TrimSpace(normalized.Detail); detail != "" {
		report.Detail = detail
	}
	if warning := strings.TrimSpace(normalized.Warning); warning != "" {
		report.Warning = warning
	}
	if !proven {
		report.RuntimeDivergent = true
	}
	return report
}

// HumanLines returns a stable multi-line rendering suitable for command output.
func HumanLines(meta *detached.NetworkEnforcement, prefix string) []string {
	report := NetworkEnforcement(meta)
	lines := []string{report.Summary}
	if report.Requested != "" && report.Requested != string(detached.NetworkEnforcementRequestNone) {
		lines = append(lines, fmt.Sprintf("Requested: %s; readiness: %s; status: %s", report.Requested, report.Readiness, report.Status))
	}
	if report.Detail != "" {
		lines = append(lines, report.Detail)
	}
	if report.Warning != "" {
		lines = append(lines, report.Warning)
	}
	if prefix == "" {
		return lines
	}
	prefixed := make([]string, 0, len(lines))
	for _, line := range lines {
		prefixed = append(prefixed, prefix+line)
	}
	return prefixed
}

// OneLine returns the primary summary line without detail/warning text.
func OneLine(meta *detached.NetworkEnforcement) string {
	return NetworkEnforcement(meta).Summary
}
