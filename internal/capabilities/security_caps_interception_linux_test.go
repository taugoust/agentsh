//go:build linux

package capabilities

import (
	"testing"

	"github.com/agentsh/agentsh/internal/limits"
)

func TestDetectInterceptionCapabilitiesDoesNotProbeCgroups(t *testing.T) {
	oldSeccomp := checkSeccompUserNotify
	oldPtrace := checkPtrace
	oldCgroupProbe := cgroupProbeCache
	defer func() {
		checkSeccompUserNotify = oldSeccomp
		checkPtrace = oldPtrace
		cgroupProbeCache = oldCgroupProbe
	}()

	checkSeccompUserNotify = func() CheckResult { return CheckResult{Available: true} }
	checkPtrace = func() CheckResult { return CheckResult{Available: false} }
	sentinel := &limits.CgroupProbeResult{Mode: limits.ModeAttachOnly, OwnCgroup: "/delegated"}
	cgroupProbeCache = sentinel

	caps := DetectInterceptionCapabilities()
	if !caps.Seccomp {
		t.Fatal("Seccomp = false, want true")
	}
	if caps.Ptrace {
		t.Fatal("Ptrace = true, want false")
	}
	if LastCgroupProbe() != sentinel {
		t.Fatal("focused interception detection replaced the established cgroup probe")
	}
}
