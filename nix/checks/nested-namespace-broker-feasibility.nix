{
  pkgs,
  self,
}:
let
  vendorHash = "sha256-SnrqSrkgeH/jOiLV71h3a2q9OZj5ISru042kVjhrGRE=";

  mkGoFixture =
    {
      pname,
      subPackage,
      tags ? [ ],
      needsEBPF ? false,
    }:
    pkgs.buildGoModule {
      inherit pname tags vendorHash;
      version = "unstable-2026-07-20";
      src = self;
      subPackages = [ subPackage ];
      nativeBuildInputs = [
        pkgs.pkg-config
      ]
      ++ pkgs.lib.optionals needsEBPF [
        pkgs.gnumake
        pkgs.llvmPackages.clang-unwrapped
      ];
      buildInputs = [
        pkgs.libseccomp
      ]
      ++ pkgs.lib.optionals needsEBPF [
        pkgs.libbpf
        pkgs.linuxHeaders
      ];
      env = {
        CGO_ENABLED = "1";
        GOTELEMETRY = "off";
      };
      preBuild = pkgs.lib.optionalString needsEBPF ''
        make -C internal/netmonitor/ebpf clean all \
          BPF_CLANG=${pkgs.llvmPackages.clang-unwrapped}/bin/clang \
          BPF_INCLUDE="-I${pkgs.libbpf}/include -I${pkgs.linuxHeaders}/include"
      '';
      doCheck = false;
    };

  genericWrapper = mkGoFixture {
    pname = "agentsh-unixwrap-mount-broker-feasibility";
    subPackage = "cmd/agentsh-unixwrap";
    tags = [ "agentsh_mount_broker_feasibility" ];
    needsEBPF = true;
  };

  semanticWrapper = mkGoFixture {
    pname = "agentsh-unixwrap-semantic-broker-feasibility";
    subPackage = "cmd/agentsh-unixwrap";
    tags = [ "agentsh_nested_namespace_feasibility" ];
    needsEBPF = true;
  };

  compositionProbe = mkGoFixture {
    pname = "agentsh-namespace-composition-probe";
    subPackage = "nix/checks/fixtures/namespace-composition-probe";
    needsEBPF = true;
  };

  brokerProbe = mkGoFixture {
    pname = "agentsh-namespace-broker-probe";
    subPackage = "nix/checks/fixtures/namespace-broker-probe";
  };

  mountHelper = pkgs.stdenv.mkDerivation {
    pname = "agentsh-mount-broker-helper";
    version = "unstable-2026-07-20";
    dontUnpack = true;
    strictDeps = true;
    buildPhase = ''
      runHook preBuild
      $CC -std=c11 -O2 -Wall -Wextra -Werror \
        ${./fixtures/mount-broker-helper/main.c} -o mount-broker-helper
      runHook postBuild
    '';
    installPhase = ''
      runHook preInstall
      install -D -m 0755 mount-broker-helper "$out/bin/mount-broker-helper"
      runHook postInstall
    '';
  };

  sourceFixture = pkgs.runCommand "agentsh-broker-read-only-source" { } ''
    mkdir -p "$out"
    printf '%s\n' broker-source > "$out/marker"
  '';

  brokerRoot = "/tmp/agentsh-broker-root";
  brokerSocket = "/tmp/agentsh-semantic-broker.sock";
  brokerReady = "/tmp/agentsh-semantic-broker.ready";

  genericDriver = pkgs.writeShellApplication {
    name = "agentsh-generic-mount-broker-driver";
    text = ''
      exec ${brokerProbe}/bin/namespace-broker-probe generic \
        --source ${sourceFixture} --root ${brokerRoot}
    '';
  };

  semanticDriver = pkgs.writeShellApplication {
    name = "agentsh-semantic-bwrap-broker-driver";
    text = ''
      exec ${brokerProbe}/bin/namespace-broker-probe semantic \
        --socket ${brokerSocket} -- \
        --ro-bind ${sourceFixture} ${brokerRoot}/bind \
        --tmpfs ${brokerRoot}/tmpfs \
        --proc ${brokerRoot}/proc \
        -- ${brokerProbe}/bin/namespace-broker-probe verify \
          --mode semantic --source ${sourceFixture} --root ${brokerRoot}
    '';
  };
in
pkgs.testers.runNixOSTest {
  name = "agentsh-nested-namespace-broker-feasibility";

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
        compositionProbe
        brokerProbe
        genericWrapper
        semanticWrapper
        mountHelper
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
    machine.succeed(
        "install -d -o tester -g users -m 0700 ${brokerRoot} "
        "${brokerRoot}/bind ${brokerRoot}/tmpfs ${brokerRoot}/proc ${brokerRoot}/forbidden"
    )

    with subtest("generic seccomp-notify mount broker keeps the requester Landlocked"):
        generic = machine.succeed(
            "runuser -u tester -- ${compositionProbe}/bin/namespace-composition-probe run "
            "--wrapper ${genericWrapper}/bin/agentsh-unixwrap "
            "--matrix ${genericDriver}/bin/agentsh-generic-mount-broker-driver "
            "--control-dir /run/agentsh-feasibility-control "
            "--landlock --landlock-write-root ${brokerRoot} "
            "--mount-broker-helper ${mountHelper}/bin/mount-broker-helper "
            "--broker-source ${sourceFixture} --broker-root ${brokerRoot} 2>&1"
        )
        assert '"mode":"generic"' in generic, generic
        assert '"stage":"landlock_brokered_mount"' in generic, generic
        assert '"selected_branch":"generic_mount_syscall_broker"' in generic, generic
        assert '"bind_preserved_readonly":true' in generic, generic
        assert '"raw_mount_denied":true' in generic, generic
        assert '"landlock_composes":true' in generic, generic

    with subtest("semantic bwrap-argv broker keeps the child Landlocked across exec"):
        machine.succeed("rm -f ${brokerSocket} ${brokerReady} /tmp/agentsh-semantic-broker.log")
        machine.succeed(
            "runuser -u tester -- sh -c '"
            "${brokerProbe}/bin/namespace-broker-probe semantic-server "
            "--socket ${brokerSocket} --helper ${mountHelper}/bin/mount-broker-helper "
            "--source ${sourceFixture} --root ${brokerRoot} --ready ${brokerReady} "
            ">/tmp/agentsh-semantic-broker.log 2>&1 & echo $! >/tmp/agentsh-semantic-broker.pid'"
        )
        machine.wait_until_succeeds("test -s ${brokerReady}")
        semantic = machine.succeed(
            "runuser -u tester -- ${compositionProbe}/bin/namespace-composition-probe run "
            "--wrapper ${semanticWrapper}/bin/agentsh-unixwrap "
            "--matrix ${semanticDriver}/bin/agentsh-semantic-bwrap-broker-driver "
            "--control-dir /run/agentsh-feasibility-control "
            "--landlock --landlock-write-root ${brokerRoot} "
            "--success-stage landlock_semantic_broker "
            "--success-branch bwrap_semantic_broker 2>&1"
        )
        machine.wait_until_succeeds("! kill -0 $(cat /tmp/agentsh-semantic-broker.pid) 2>/dev/null")
        assert '"mode":"semantic"' in semantic, semantic
        assert '"stage":"landlock_semantic_broker"' in semantic, semantic
        assert '"selected_branch":"bwrap_semantic_broker"' in semantic, semantic
        assert '"bind_preserved_readonly":true' in semantic, semantic
        assert '"raw_mount_denied":true' in semantic, semantic
        assert '"landlock_composes":true' in semantic, semantic
  '';
}
