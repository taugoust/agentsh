{
  pkgs,
  self,
}:
let
  inherit (pkgs) lib;
  vendorHash = "sha256-SnrqSrkgeH/jOiLV71h3a2q9OZj5ISru042kVjhrGRE=";

  mkGoFixture =
    {
      pname,
      subPackage,
      tags ? [ ],
    }:
    pkgs.buildGoModule {
      inherit pname tags vendorHash;
      version = "unstable-2026-07-20";
      src = self;
      subPackages = [ subPackage ];
      nativeBuildInputs = [
        pkgs.gnumake
        pkgs.llvmPackages.clang-unwrapped
        pkgs.pkg-config
      ];
      buildInputs = [
        pkgs.libbpf
        pkgs.libseccomp
        pkgs.linuxHeaders
      ];
      env = {
        CGO_ENABLED = "1";
        GOTELEMETRY = "off";
      };
      preBuild = ''
        make -C internal/netmonitor/ebpf clean all \
          BPF_CLANG=${pkgs.llvmPackages.clang-unwrapped}/bin/clang \
          BPF_INCLUDE="-I${pkgs.libbpf}/include -I${pkgs.linuxHeaders}/include"
      '';
      doCheck = false;
    };

  feasibilityWrapper = mkGoFixture {
    pname = "agentsh-unixwrap-nested-namespace-feasibility";
    subPackage = "cmd/agentsh-unixwrap";
    tags = [ "agentsh_nested_namespace_feasibility" ];
  };

  feasibilityProbe = mkGoFixture {
    pname = "agentsh-nested-namespace-feasibility";
    subPackage = "nix/checks/fixtures/namespace-composition-probe";
  };

  allowedFixture = pkgs.runCommand "agentsh-nested-namespace-allowed-fixture" { } ''
    mkdir -p "$out"
    printf '%s\n' 'allowed-source-object' > "$out/message"
  '';

  mockHelper = pkgs.writeShellApplication {
    name = "agentsh-nested-namespace-mock-helper";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      set -euo pipefail
      mode="''${1:?missing helper mode}"
      test "$(cat /allowed/message)" = allowed-source-object
      test -r /proc/self/status
      test ! -e /run/agentsh-feasibility-control/secret
      printf '%s\n' "$mode" > /tmp/helper-mode
      /bin/sh -c 'test -s /tmp/helper-mode'
      printf 'stage=mock-helper mode=%s result=pass\n' "$mode"
    '';
  };

  bwrapArgs = ''
    --unshare-user
    --unshare-pid
    --unshare-ipc
    --unshare-uts
    --unshare-cgroup
    --die-with-parent
    --dir /nix
    --ro-bind /nix/store /nix/store
    --tmpfs /tmp
    --proc /proc
    --dev /dev
    --dir /bin
    --symlink ${pkgs.bash}/bin/bash /bin/sh
  '';

  recursiveDriver = pkgs.writeShellApplication {
    name = "agentsh-nested-namespace-recursive-driver";
    runtimeInputs = [ pkgs.bubblewrap ];
    text = ''
      set -euo pipefail
      exec bwrap \
        ${lib.replaceStrings [ "\n" ] [ " \\\n        " ] bwrapArgs} \
        --ro-bind /allowed /allowed \
        -- ${mockHelper}/bin/agentsh-nested-namespace-mock-helper recursive-inner
    '';
  };

  bubblewrapMatrix = pkgs.writeShellApplication {
    name = "agentsh-nested-namespace-bubblewrap-matrix";
    runtimeInputs = [ pkgs.bubblewrap ];
    text = ''
      set -euo pipefail

      run_fixture() {
        mode="$1"
        shift
        bwrap \
          ${lib.replaceStrings [ "\n" ] [ " \\\n          " ] bwrapArgs} \
          --ro-bind ${allowedFixture} /allowed \
          -- "$@"
        printf 'stage=bubblewrap mode=%s result=pass\n' "$mode"
      }

      printf '%s\n' 'stage=bubblewrap-command-line result=evidence executable=${pkgs.bubblewrap}/bin/bwrap flags=user,mount,pid,ipc,uts,cgroup,bind,tmpfs,proc,dev,symlink,pivot'
      run_fixture single ${mockHelper}/bin/agentsh-nested-namespace-mock-helper single
      run_fixture sequential-a ${mockHelper}/bin/agentsh-nested-namespace-mock-helper sequential-a
      run_fixture sequential-b ${mockHelper}/bin/agentsh-nested-namespace-mock-helper sequential-b
      run_fixture recursive ${recursiveDriver}/bin/agentsh-nested-namespace-recursive-driver
      printf '%s\n' 'stage=bubblewrap-matrix result=pass'
    '';
  };
in
pkgs.testers.runNixOSTest {
  name = "agentsh-nested-namespace-feasibility";

  nodes.machine =
    { ... }:
    {
      security.unprivilegedUsernsClone = true;
      boot.kernel.sysctl."user.max_user_namespaces" = 1024;
      users.users.tester = {
        isNormalUser = true;
        uid = 1000;
      };
      environment.systemPackages = [
        pkgs.bubblewrap
        pkgs.util-linux
        feasibilityProbe
        feasibilityWrapper
        bubblewrapMatrix
      ];
      virtualisation = {
        memorySize = 2048;
        cores = 2;
      };
      system.stateVersion = "25.11";
    };

  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("install -d -m 0755 /run/agentsh-feasibility-control")
    machine.succeed("printf '%s\\n' supervisor-secret > /run/agentsh-feasibility-control/secret")

    with subtest("Bubblewrap works outside AgentSH"):
        outside = machine.succeed(
            "runuser -u tester -- ${bubblewrapMatrix}/bin/agentsh-nested-namespace-bubblewrap-matrix 2>&1"
        )
        assert "stage=bubblewrap-matrix result=pass" in outside, outside
        assert "mode=recursive-inner result=pass" in outside, outside

    with subtest("the current outer UID 0 mapping blocks nested user namespaces"):
        current_outer = machine.succeed(
            "runuser -u tester -- ${feasibilityProbe}/bin/namespace-composition-probe run "
            "--wrapper ${feasibilityWrapper}/bin/agentsh-unixwrap "
            "--matrix ${bubblewrapMatrix}/bin/agentsh-nested-namespace-bubblewrap-matrix "
            "--control-dir /run/agentsh-feasibility-control "
            "--outer-namespace-id 0 --expect-root-map-block 2>&1"
        )
        assert '"stage":"outer_root_nested_user_namespace"' in current_outer, current_outer
        assert '"result":"blocked"' in current_outer, current_outer
        assert '"errno_class":"EPERM"' in current_outer, current_outer
        assert '"selected_branch":"nonroot_outer_identity_required"' in current_outer, current_outer

    with subtest("an adjusted outer identity and seccomp monitoring compose before Landlock"):
        monitored = machine.succeed(
            "runuser -u tester -- ${feasibilityProbe}/bin/namespace-composition-probe run "
            "--wrapper ${feasibilityWrapper}/bin/agentsh-unixwrap "
            "--matrix ${bubblewrapMatrix}/bin/agentsh-nested-namespace-bubblewrap-matrix "
            "--control-dir /run/agentsh-feasibility-control 2>&1"
        )
        for stage in [
            "outer_privileges",
            "hidden_control_paths_and_fds",
            "outer_namespaces",
            "outer_mount_after_capability_drop",
            "external_setns",
            "seccomp_without_landlock",
        ]:
            marker = f'"stage":"{stage}"'
            assert marker in monitored, (marker, monitored)
        assert monitored.count('"errno_class":"EPERM"') >= 2, monitored
        assert "stage=bubblewrap-matrix result=pass" in monitored, monitored

    with subtest("the current Landlock domain blocks descendant mount composition"):
        landlock = machine.succeed(
            "runuser -u tester -- ${feasibilityProbe}/bin/namespace-composition-probe run "
            "--wrapper ${feasibilityWrapper}/bin/agentsh-unixwrap "
            "--matrix ${bubblewrapMatrix}/bin/agentsh-nested-namespace-bubblewrap-matrix "
            "--control-dir /run/agentsh-feasibility-control "
            "--landlock --expect-landlock-block 2>&1"
        )
        assert '"stage":"landlock_nested_mount"' in landlock, landlock
        assert '"result":"blocked"' in landlock, landlock
        assert '"errno_class":"EPERM"' in landlock, landlock
        assert '"landlock_composes":false' in landlock, landlock
        assert '"selected_branch":"alternate_backend_required"' in landlock, landlock
        assert "landlock: restrictions applied" in landlock, landlock
  '';
}
