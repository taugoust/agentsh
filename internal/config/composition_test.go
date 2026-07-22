package config

import (
	"strings"
	"testing"
)

func TestBubblewrapCompositionDefaultsAndValidation(t *testing.T) {
	cfg, err := loadFromString(t, `
landlock:
  enabled: true
sandbox:
  network:
    ebpf:
      enforce: true
  seccomp:
    execve:
      enabled: true
    file_monitor:
      enabled: true
      enforce_without_fuse: true
      intercept_metadata: true
      write_only_opens: false
      block_io_uring: true
  composition:
    bubblewrap:
      enabled: true
      scratch_root: /agentsh-composition-scratch
`)
	if err != nil {
		t.Fatal(err)
	}
	bubblewrap := cfg.Sandbox.Composition.Bubblewrap
	if bubblewrap.Dialect != "0.11.2" || bubblewrap.MaxPlanOperations != 256 || bubblewrap.MaxNamespaceDepth != 4 {
		t.Fatalf("unexpected composition defaults: %+v", bubblewrap)
	}
}

func TestBubblewrapCompositionDeviceIOCTLPathsAreExact(t *testing.T) {
	cfg, err := loadFromString(t, `
sandbox:
  composition:
    bubblewrap:
      device_ioctl_paths:
        - /dev/null
`)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Sandbox.Composition.Bubblewrap.DeviceIOCTLPaths
	if len(got) != 1 || got[0] != "/dev/null" {
		t.Fatalf("device ioctl paths = %#v", got)
	}

	for _, path := range []string{"dev/null", "/dev/*", "/dev/../dev/null"} {
		_, err := loadFromString(t, "sandbox:\n  composition:\n    bubblewrap:\n      device_ioctl_paths:\n        - "+path+"\n")
		if err == nil {
			t.Errorf("device ioctl path %q unexpectedly accepted", path)
		}
	}
}

func TestBubblewrapCompositionRequiresHostBoundary(t *testing.T) {
	_, err := loadFromString(t, `
sandbox:
  composition:
    bubblewrap:
      enabled: true
      scratch_root: /agentsh-composition-scratch
`)
	if err == nil {
		t.Fatal("expected missing Landlock/exec/command-jail validation error")
	}
}

func TestBubblewrapCompositionRequiresCompleteSourceAwareFileMonitor(t *testing.T) {
	_, err := loadFromString(t, `
landlock:
  enabled: true
sandbox:
  network:
    ebpf:
      enforce: true
  seccomp:
    execve:
      enabled: true
    file_monitor:
      enabled: true
      enforce_without_fuse: true
      intercept_metadata: false
      write_only_opens: false
      block_io_uring: true
  composition:
    bubblewrap:
      enabled: true
      scratch_root: /agentsh-composition-scratch
`)
	if err == nil || !strings.Contains(err.Error(), "metadata file interception") {
		t.Fatalf("metadata-disabled composition config error = %v", err)
	}
}

func TestBubblewrapCompositionRequiresDedicatedTopLevelScratch(t *testing.T) {
	for _, scratch := range []string{"", "/", "/run/agentsh-composition", "/tmp/agentsh-composition", "/agentsh-composition/../scratch"} {
		_, err := loadFromString(t, `
landlock:
  enabled: true
sandbox:
  network:
    ebpf:
      enforce: true
  seccomp:
    execve:
      enabled: true
  composition:
    bubblewrap:
      enabled: true
      scratch_root: `+scratch+`
`)
		if err == nil {
			t.Errorf("scratch root %q unexpectedly accepted", scratch)
		}
	}
}
