package detachedreport

import (
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/detached"
)

func TestNetworkEnforcementUnknown(t *testing.T) {
	report := NetworkEnforcement(nil)
	if report.Label != "unknown" {
		t.Fatalf("Label = %q, want unknown", report.Label)
	}
	if report.PolicyEnforced {
		t.Fatal("PolicyEnforced = true, want false")
	}
	if !report.RuntimeDivergent {
		t.Fatal("RuntimeDivergent = false, want true")
	}
	if !strings.Contains(report.Warning, "do not assume") {
		t.Fatalf("Warning = %q, want missing-metadata warning", report.Warning)
	}
}

func TestNetworkEnforcementNone(t *testing.T) {
	report := NetworkEnforcement(&detached.NetworkEnforcement{
		Status:                detached.NetworkEnforcementStatusDegraded,
		Tier:                  detached.NetworkEnforcementTierNone,
		NetworkPolicyEnforced: false,
	})
	if report.Label != "none" {
		t.Fatalf("Label = %q, want none", report.Label)
	}
	if !strings.Contains(report.Summary, "not enforced") {
		t.Fatalf("Summary = %q, want not enforced", report.Summary)
	}
	if !strings.Contains(report.Warning, "commands can still connect") {
		t.Fatalf("Warning = %q, want runtime bypass warning", report.Warning)
	}
	if !report.RuntimeDivergent {
		t.Fatal("RuntimeDivergent = false, want true")
	}
}

func TestNetworkEnforcementCgroupDelegatedOnly(t *testing.T) {
	report := NetworkEnforcement(&detached.NetworkEnforcement{
		Status:                detached.NetworkEnforcementStatusDegraded,
		Tier:                  detached.NetworkEnforcementTierCgroupDelegated,
		NetworkPolicyEnforced: false,
		CgroupDelegated:       true,
	})
	if report.Label != "cgroup-delegated-only" {
		t.Fatalf("Label = %q, want cgroup-delegated-only", report.Label)
	}
	if !report.CgroupDelegated {
		t.Fatal("CgroupDelegated = false, want true")
	}
	if !strings.Contains(report.Summary, "cgroup-delegated-only") {
		t.Fatalf("Summary = %q, want cgroup-delegated-only", report.Summary)
	}
	if !strings.Contains(report.Warning, "not approval-gated") {
		t.Fatalf("Warning = %q, want approval-gated warning", report.Warning)
	}
}

func TestNetworkEnforcementHelperGateDegradedIsDistinct(t *testing.T) {
	report := NetworkEnforcement(&detached.NetworkEnforcement{
		Status:                detached.NetworkEnforcementStatusDegraded,
		Tier:                  detached.NetworkEnforcementTierHelperEBPFGate,
		NetworkPolicyEnforced: false,
	})
	if report.Label != "helper-ebpf-gate-degraded" {
		t.Fatalf("Label = %q, want helper-ebpf-gate-degraded", report.Label)
	}
	if !strings.Contains(report.Summary, "helper-ebpf-gate") {
		t.Fatalf("Summary = %q, want helper-ebpf-gate", report.Summary)
	}
	if !strings.Contains(report.Warning, "proxy path") {
		t.Fatalf("Warning = %q, want proxy path caveat", report.Warning)
	}
}

func TestNetworkEnforcementHelperProxyDegradedDoesNotClaimFull(t *testing.T) {
	report := NetworkEnforcement(&detached.NetworkEnforcement{
		Status:                detached.NetworkEnforcementStatusDegraded,
		Tier:                  detached.NetworkEnforcementTierHelperEBPFProxy,
		NetworkPolicyEnforced: false,
	})
	if report.Label != "helper-ebpf-proxy-required-degraded" {
		t.Fatalf("Label = %q, want helper-ebpf-proxy-required-degraded", report.Label)
	}
	if report.PolicyEnforced {
		t.Fatal("PolicyEnforced = true, want false")
	}
	if !report.RuntimeDivergent {
		t.Fatal("RuntimeDivergent = false, want true")
	}
	if !strings.Contains(report.Warning, "not all proven active") && !strings.Contains(report.Warning, "not claimed") {
		t.Fatalf("Warning = %q, want helper caveat", report.Warning)
	}
}

func TestNetworkEnforcementFullHelperProxy(t *testing.T) {
	checkedAt := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	report := NetworkEnforcement(&detached.NetworkEnforcement{
		Requested:                 detached.NetworkEnforcementRequestStrict,
		Readiness:                 detached.NetworkEnforcementStatusReady,
		Status:                    detached.NetworkEnforcementStatusReady,
		Tier:                      detached.NetworkEnforcementTierHelperEBPFProxyRequired,
		NetworkPolicyEnforced:     true,
		CgroupDelegated:           true,
		CgroupMode:                "attach-only",
		CgroupRoot:                "/sys/fs/cgroup/supervisor",
		HelperConfigured:          true,
		HelperAuthenticated:       true,
		ToolBoundaryActive:        true,
		ProxyReady:                true,
		ProxyRequired:             true,
		ExactProxyOnly:            true,
		AllowedTransport:          "tcp",
		ProxyEndpointID:           "127.0.0.1:18080",
		DirectBypassBlocked:       true,
		DirectTCPBlocked:          true,
		LocalNonProxyTCPBlocked:   true,
		UDPBlocked:                true,
		QUICBlocked:               true,
		CommandDNSRequired:        false,
		RawSocketBlockConfigured:  true,
		RawSocketsBlocked:         true,
		UnsupportedTrafficAction: "deny",
		UnsupportedTrafficBlocked: true,
		FailClosedSetup:           true,
		CheckedAt:                 checkedAt,
		Preflight: &detached.NetworkPreflightEvidence{
			Status:                     detached.NetworkEnforcementStatusReady,
			CommandID:                  "cmd-preflight",
			CgroupPath:                 "/sys/fs/cgroup/preflight",
			CgroupID:                   42,
			RegistrationID:             "sha256:evidence",
			CgroupPlacementProven:      true,
			HelperAuthenticated:        true,
			HelperAttachProven:         true,
			DefaultDenyMapProven:       true,
			InitialPolicyLocked:        true,
			PolicyUpdateFailClosed:     true,
			HelperCleanupProven:        true,
			Pinned:                     true,
			ProxyListenerProven:        true,
			ProxyConnectProven:         true,
			ProxyEndpointID:            "127.0.0.1:18080",
			ToolBoundaryProven:         true,
			PrivateProcProven:          true,
			CgroupFSHidden:             true,
			HelperSocketHidden:         true,
			CredentialSourceHidden:     true,
			ReservedEnvScrubbed:        true,
			InheritedDescriptorsClosed: true,
			NoNewPrivileges:            true,
			CapabilitiesDropped:        true,
			DirectBypassProven:         true,
			LocalDirectTCPBlocked:      true,
			UDPBlocked:                 true,
			RawSocketsBlocked:          true,
			UnsupportedTrafficProven:  true,
			FailClosedBarrierProven:    true,
			ChildStoppedDuringSetup:    true,
			RefusalLeftChildStopped:    true,
			CheckedAt:                  checkedAt,
		},
	})
	if report.Label != "ready" {
		t.Fatalf("Label = %q, want ready", report.Label)
	}
	if !report.PolicyEnforced {
		t.Fatal("PolicyEnforced = false, want true")
	}
	if report.RuntimeDivergent {
		t.Fatal("RuntimeDivergent = true, want false")
	}
	if report.Warning != "" {
		t.Fatalf("Warning = %q, want empty", report.Warning)
	}
	if !strings.Contains(report.Detail, "synchronously policy-gated") {
		t.Fatalf("Detail = %q, want proxy detail", report.Detail)
	}
}

func TestNetworkEnforcementDoesNotClaimFullForHelperTierWithoutPolicyEnforced(t *testing.T) {
	report := NetworkEnforcement(&detached.NetworkEnforcement{
		Status:                detached.NetworkEnforcementStatusDegraded,
		Tier:                  detached.NetworkEnforcementTierHelperEBPFProxy,
		NetworkPolicyEnforced: false,
	})
	if report.Label == "full" || report.PolicyEnforced {
		t.Fatalf("report = %+v, must not claim full helper enforcement", report)
	}
	if !report.RuntimeDivergent {
		t.Fatalf("report = %+v, want runtime divergent", report)
	}
}

func TestNetworkEnforcementPreservesMetadataText(t *testing.T) {
	report := NetworkEnforcement(&detached.NetworkEnforcement{
		Status:                detached.NetworkEnforcementStatusDegraded,
		Tier:                  detached.NetworkEnforcementTierNone,
		NetworkPolicyEnforced: false,
		Warning:               "custom warning",
		Detail:                "custom detail",
	})
	if report.Warning != "custom warning" {
		t.Fatalf("Warning = %q, want custom warning", report.Warning)
	}
	if report.Detail != "custom detail" {
		t.Fatalf("Detail = %q, want custom detail", report.Detail)
	}
}

func TestHumanLinesPrefixesOutput(t *testing.T) {
	lines := HumanLines(&detached.NetworkEnforcement{
		Status:                detached.NetworkEnforcementStatusDegraded,
		Tier:                  detached.NetworkEnforcementTierNone,
		NetworkPolicyEnforced: false,
	}, "  ")
	if len(lines) != 2 {
		t.Fatalf("len(lines) = %d, want 2: %#v", len(lines), lines)
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "  ") {
			t.Fatalf("line %q missing prefix", line)
		}
	}
}
