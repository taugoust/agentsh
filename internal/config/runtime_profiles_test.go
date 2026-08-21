package config

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/runtimeprovider"
)

func TestRuntimeProfilesDefaultToNative(t *testing.T) {
	cfg, err := loadFromString(t, "")
	if err != nil {
		t.Fatal(err)
	}
	name, profile, err := cfg.Sessions.Runtime.ResolveProfile("")
	if err != nil {
		t.Fatal(err)
	}
	if name != runtimeprovider.DefaultProfile || profile.Provider != runtimeprovider.NativeProvider {
		t.Fatalf("default runtime profile = %q %+v", name, profile)
	}
}

func TestRuntimeProfilesResolveOperatorNamedNativeProfile(t *testing.T) {
	cfg, err := loadFromString(t, `
sessions:
  runtime:
    default_profile: workstation
    profiles:
      workstation:
        provider: native
      compatibility:
        provider: native
`)
	if err != nil {
		t.Fatal(err)
	}
	for requested, want := range map[string]string{"": "workstation", "compatibility": "compatibility"} {
		name, profile, err := cfg.Sessions.Runtime.ResolveProfile(requested)
		if err != nil {
			t.Fatalf("ResolveProfile(%q): %v", requested, err)
		}
		if name != want || profile.Provider != runtimeprovider.NativeProvider {
			t.Fatalf("ResolveProfile(%q) = %q %+v", requested, name, profile)
		}
	}
	if _, _, err := cfg.Sessions.Runtime.ResolveProfile("project-selected"); err == nil {
		t.Fatal("unconfigured runtime profile was selected")
	}
}

func TestRuntimeProfilesRejectUnsupportedProviderAndMissingDefault(t *testing.T) {
	for name, input := range map[string]struct {
		yaml string
		want string
	}{
		"unsupported provider": {
			yaml: `
sessions:
  runtime:
    profiles:
      native:
        provider: project-hypervisor
`,
			want: "is unsupported",
		},
		"missing default": {
			yaml: `
sessions:
  runtime:
    profiles:
      workstation:
        provider: native
`,
			want: "default_profile \"native\" is not present",
		},
		"invalid profile name": {
			yaml: `
sessions:
  runtime:
    default_profile: "../escape"
    profiles:
      "../escape":
        provider: native
`,
			want: "invalid runtime name",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadFromString(t, input.yaml)
			if err == nil || !strings.Contains(err.Error(), input.want) {
				t.Fatalf("runtime config error = %v, want %q", err, input.want)
			}
		})
	}
}

func TestRuntimeProfilesAcceptDisabledExternalProfile(t *testing.T) {
	cfg, err := loadFromString(t, `
sessions:
  runtime:
    default_profile: native
    enable_external_runners: false
    profiles:
      native:
        provider: native
      pi-linux-qemu-v1:
        provider: microvm-external-runner
        profile_file: /nix/store/example-profile/profile.json
`)
	if err != nil {
		t.Fatal(err)
	}
	profile := cfg.Sessions.Runtime.Profiles["pi-linux-qemu-v1"]
	if cfg.Sessions.Runtime.EnableExternalRunners || profile.Provider != "microvm-external-runner" || profile.ProfileFile == "" {
		t.Fatalf("external runtime profile = %+v, ceiling=%t", profile, cfg.Sessions.Runtime.EnableExternalRunners)
	}
}

func TestRuntimeProfilesRejectExternalDefault(t *testing.T) {
	_, err := loadFromString(t, `
sessions:
  runtime:
    default_profile: pi-linux-qemu-v1
    profiles:
      pi-linux-qemu-v1:
        provider: microvm-external-runner
        profile_file: /nix/store/example-profile/profile.json
`)
	if err == nil || !strings.Contains(err.Error(), "cannot be the default") {
		t.Fatalf("external default error = %v", err)
	}
}

func TestRuntimeProfilesRejectUnknownProviderOptions(t *testing.T) {
	for name, input := range map[string]struct {
		yaml string
		want string
	}{
		"runtime key": {
			yaml: `
sessions:
  runtime:
    raw_qemu_args: ["--device", "host-path"]
`,
			want: "unknown sessions.runtime key",
		},
		"profile key": {
			yaml: `
sessions:
  runtime:
    profiles:
      native:
        provider: native
        runner: /tmp/project-selected-runner
`,
			want: "unknown sessions.runtime.profiles.native key",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadFromString(t, input.yaml)
			if err == nil || !strings.Contains(err.Error(), input.want) {
				t.Fatalf("runtime option error = %v, want %q", err, input.want)
			}
		})
	}
}
