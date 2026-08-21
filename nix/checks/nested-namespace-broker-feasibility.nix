{ pkgs, self }:
let
  vendorHash = "sha256-ZLvA36nIEbrBnxeAriL35syM2yhQEKvi1n6wuB8boGk=";

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

  productionPackage = self.packages.${pkgs.stdenv.hostPlatform.system}.agentsh;

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
    mkdir -p "$out/descendant"
    printf '%s\n' broker-source > "$out/marker"
    printf '%s\n' broker-descendant > "$out/descendant/marker"
  '';

  deniedCommand = pkgs.writeShellApplication {
    name = "agentsh-composition-denied-command";
    text = ''
      echo "source-attribution command policy was bypassed" >&2
      exit 0
    '';
  };

  qshellPathFixture = pkgs.runCommand "agentsh-qshell-dynamic-store-path" { } ''
    mkdir -p "$out/etc"
  '';
  qshellArgvFixture = ../../internal/composition/testdata/qshell-bwrap-0.11.2-argv.json;

  brokerRoot = "/tmp/agentsh-broker-root";
  brokerSocket = "/tmp/agentsh-semantic-broker.sock";
  brokerReady = "/tmp/agentsh-semantic-broker.ready";
  recursiveSource = "/tmp/agentsh-recursive-source";

  genericDriver = pkgs.writeShellApplication {
    name = "agentsh-generic-mount-broker-driver";
    text = ''
      exec ${brokerProbe}/bin/namespace-broker-probe generic \
        --source ${sourceFixture} --root ${brokerRoot}
    '';
  };

  productionMockHelper = pkgs.writeShellApplication {
    name = "agentsh-composition-runtime-helper";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      set -euo pipefail
      mode="''${1:?missing mode}"
      test "$(cat /allowed/marker)" = broker-source
      test "$(cat /allowed-descendant/marker)" = broker-descendant
      test "$(cat /recursive-source/hidden/marker)" = recursive-submount
      test -r /proc/1/status
      if [ "$mode" = current-pid-proc ]; then
        test -n "$2"
        if [ "$(readlink /proc/self/ns/pid)" != "$2" ]; then
          echo "--proc unexpectedly created a fresh PID namespace" >&2
          exit 1
        fi
      fi
      test ! -e /run/agentsh-feasibility-control/secret
      if /alias-command >/dev/null 2>&1; then
        echo "bind alias bypassed source command policy" >&2
        exit 1
      fi
      printf 'stage=production-composition mode=%s result=pass\\n' "$mode"
    '';
  };

  productionQShellHelper = pkgs.writeShellApplication {
    name = "agentsh-composition-qshell-contract-helper";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      set -euo pipefail
      test "$(pwd)" = /scratch/theo/qshell-project/qshell
      printf '%s\n' project-write > .agentsh-composition-project-write
      test "$(cat .agentsh-composition-project-write)" = project-write
      rm .agentsh-composition-project-write
      if printf denied > /scratch/theo/outside/agentsh-composition-write 2>/dev/null; then
        echo "heterogeneous /scratch bind broadened write authority" >&2
        exit 1
      fi
      if printf denied > /nix/agentsh-composition-write 2>/dev/null; then
        echo "/nix bind gained write authority" >&2
        exit 1
      fi
      if printf denied > /nix/store/agentsh-composition-write 2>/dev/null; then
        echo "/nix/store bind gained write authority" >&2
        exit 1
      fi
      test "$(cat /nix-support/marker)" = broker-source
      test "$(cat ${qshellPathFixture}/etc/rpc)" = broker-source
      test -r /.host-etc/os-release
      if test -e /.host-etc/hosts; then
        echo "bind alias bypassed source metadata policy" >&2
        exit 1
      fi
      if cat /.host-etc/hosts >/dev/null 2>&1; then
        echo "bind alias bypassed source file policy" >&2
        exit 1
      fi
      test -d /tmp/.X11-unix
      test -c /dev/null
      test -r /proc/1/status
      test "$(readlink /proc/self/ns/pid)" = "''${1:?missing parent PID namespace}"
      test ! -e /run/agentsh-feasibility-control/secret
      printf 'stage=production-composition mode=qshell-captured-contract result=pass\n'
    '';
  };

  productionQShellDriver = pkgs.writeShellApplication {
    name = "agentsh-composition-qshell-contract-driver";
    runtimeInputs = [
      pkgs.bubblewrap
      pkgs.python3
    ];
    text = ''
      exec python3 - <<'PY'
      import json
      import os

      with open("${qshellArgvFixture}", encoding="utf-8") as stream:
          argv = json.load(stream)

      captured_glibc = "/nix/store/57iz36553175g3178pvxjij8z5rcsd4n-glibc-2.42-61"
      captured_rootfs = "/nix/store/gvqxs0s79g83bd2906wa91smhqcypbr5-xilinx-shell-fhsenv-rootfs"
      dynamic_glibc = "${qshellPathFixture}"
      source_directory = "${sourceFixture}"
      source_file = "${sourceFixture}/marker"

      argv[0] = "${pkgs.bubblewrap}/bin/bwrap"
      index = 1
      while index < len(argv):
          option = argv[index]
          if option in {"--ro-bind", "--bind", "--dev-bind"}:
              original_source = argv[index + 1]
              if option == "--ro-bind" and original_source == captured_glibc + "/etc/rpc":
                  argv[index + 1] = source_file
              elif option == "--ro-bind" and original_source.startswith(captured_rootfs + "/"):
                  argv[index + 1] = source_directory
              index += 3
              continue
          if option in {"--tmpfs", "--proc", "--chdir", "--remount-ro"}:
              index += 2
              continue
          if option == "--symlink":
              index += 3
              continue
          if option == "--die-with-parent":
              index += 1
              continue
          break

      argv = [
          argument.replace(captured_glibc, dynamic_glibc)
          for argument in argv
      ]
      payload = argv.index("/nix/store/bf1n8hy1zs7lwyhv282kh9y575iziyk6-container-init")
      argv[payload:] = [
          "${productionQShellHelper}/bin/agentsh-composition-qshell-contract-helper",
          os.readlink("/proc/self/ns/pid"),
      ]
      os.execv(argv[0], argv)
      PY
    '';
  };

  productionMissingCWDDriver = pkgs.writeShellApplication {
    name = "agentsh-composition-missing-cwd-driver";
    runtimeInputs = [ pkgs.bubblewrap ];
    text = ''
      exec bwrap \
        --bind /scratch /scratch \
        --chdir /scratch/theo/qshell-project/missing-cwd/leaf \
        -- ${pkgs.coreutils}/bin/true
    '';
  };

  productionRecursiveDriver = pkgs.writeShellApplication {
    name = "agentsh-composition-runtime-recursive-driver";
    runtimeInputs = [ pkgs.bubblewrap ];
    text = ''
      set -euo pipefail
      exec bwrap \
        --unshare-user --unshare-pid --unshare-ipc --unshare-uts --unshare-cgroup \
        --die-with-parent --dir /nix --ro-bind /nix/store /nix/store \
        --tmpfs /tmp --proc /proc --dev /dev --dir /bin \
        --symlink ${pkgs.bash}/bin/bash /bin/sh \
        --ro-bind /allowed /allowed \
        --ro-bind /allowed-descendant /allowed-descendant \
        --ro-bind /recursive-source /recursive-source \
        --ro-bind /alias-command /alias-command \
        -- ${productionMockHelper}/bin/agentsh-composition-runtime-helper recursive-inner
    '';
  };

  productionMatrix = pkgs.writeShellApplication {
    name = "agentsh-composition-runtime-matrix";
    runtimeInputs = [ pkgs.bubblewrap ];
    text = ''
      set -euo pipefail
      run() {
        mode="$1"
        shift
        bwrap \
          --unshare-user --unshare-pid --unshare-ipc --unshare-uts --unshare-cgroup \
          --die-with-parent --dir /nix --ro-bind /nix/store /nix/store \
          --tmpfs /tmp --proc /proc --dev /dev --dir /bin \
          --symlink ${pkgs.bash}/bin/bash /bin/sh \
          --ro-bind ${sourceFixture} /allowed \
          --ro-bind ${sourceFixture}/descendant /allowed-descendant \
          --ro-bind ${recursiveSource} /recursive-source \
          --ro-bind ${deniedCommand}/bin/agentsh-composition-denied-command /alias-command \
          -- "$@"
        printf 'stage=production-composition mode=%s result=pass\\n' "$mode"
      }
      bwrap \
        --unshare-user --unshare-ipc --unshare-uts --unshare-cgroup \
        --die-with-parent --dir /nix --ro-bind /nix/store /nix/store \
        --tmpfs /tmp --proc /proc --dev /dev --dir /bin \
        --symlink ${pkgs.bash}/bin/bash /bin/sh \
        --ro-bind ${sourceFixture} /allowed \
        --ro-bind ${sourceFixture}/descendant /allowed-descendant \
        --ro-bind ${recursiveSource} /recursive-source \
        --ro-bind ${deniedCommand}/bin/agentsh-composition-denied-command /alias-command \
        -- ${productionMockHelper}/bin/agentsh-composition-runtime-helper current-pid-proc "$(readlink /proc/self/ns/pid)"
      printf 'stage=production-composition mode=current-pid-proc result=pass\n'
      run single ${productionMockHelper}/bin/agentsh-composition-runtime-helper single
      run sequential-a ${productionMockHelper}/bin/agentsh-composition-runtime-helper sequential-a
      run sequential-b ${productionMockHelper}/bin/agentsh-composition-runtime-helper sequential-b
      run recursive ${productionRecursiveDriver}/bin/agentsh-composition-runtime-recursive-driver
      ${productionQShellDriver}/bin/agentsh-composition-qshell-contract-driver
      missing_cwd=/scratch/theo/qshell-project/missing-cwd/leaf
      if missing_output="$(${productionMissingCWDDriver}/bin/agentsh-composition-missing-cwd-driver 2>&1)"; then
        echo "completed-root cwd validation unexpectedly accepted $missing_cwd" >&2
        exit 1
      fi
      case "$missing_output" in
        *E_COMPOSITION_CWD_UNRESOLVED*) ;;
        *) printf 'missing typed cwd diagnostic:\n%s\n' "$missing_output" >&2; exit 1 ;;
      esac
      case "$missing_output" in
        *'first unresolved component "/scratch/theo/qshell-project/missing-cwd"'*) ;;
        *) printf 'missing first unresolved cwd component:\n%s\n' "$missing_output" >&2; exit 1 ;;
      esac
      printf 'stage=completed-root-cwd-rejection component=/scratch/theo/qshell-project/missing-cwd result=pass\n'
      printf 'stage=production-composition-matrix result=pass\\n'
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

  nodes.machine = { ... }: {
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
    machine.succeed("install -d -o root -g root -m 1733 /agentsh-composition-scratch")
    machine.succeed("install -d -o tester -g users -m 0755 /scratch/theo/qshell-project/qshell /scratch/theo/outside /boot /mnt /opt /share /srv /zokelmannvms /zroot")
    machine.succeed("printf '%s\\n' supervisor-secret > /run/agentsh-feasibility-control/secret")
    machine.succeed(
        "install -d -o tester -g users -m 0700 ${brokerRoot} "
        "${brokerRoot}/bind ${brokerRoot}/tmpfs ${brokerRoot}/proc ${brokerRoot}/forbidden"
    )
    machine.succeed("install -d -o tester -g users -m 0755 ${recursiveSource} ${recursiveSource}/hidden")
    machine.succeed("mount -t tmpfs -o nosuid,nodev,noexec,size=1m tmpfs ${recursiveSource}/hidden")
    machine.succeed("printf '%s\\n' recursive-submount > ${recursiveSource}/hidden/marker")
    machine.succeed("mount -o remount,ro,nosuid,nodev,noexec ${recursiveSource}/hidden")

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

    def run_production(topology):
        production = machine.succeed(
            "runuser -u tester -- ${compositionProbe}/bin/namespace-composition-probe run "
            "--wrapper ${productionPackage}/bin/agentsh-unixwrap "
            "--matrix ${productionMatrix}/bin/agentsh-composition-runtime-matrix "
            "--control-dir /run/agentsh-feasibility-control --landlock "
            "--landlock-write-root /scratch/theo/qshell-project/qshell "
            "--landlock-exact-read-root ${sourceFixture} "
            "--composition-adapter ${productionPackage}/bin/agentsh-bwrap-adapter "
            "--composition-helper ${productionPackage}/bin/agentsh-composition-mount-helper "
            "--composition-scratch-root /agentsh-composition-scratch 2>&1"
        )
        assert "stage=production-composition-matrix result=pass" in production, production
        assert "mode=current-pid-proc result=pass" in production, production
        assert "mode=recursive-inner result=pass" in production, production
        assert "mode=qshell-captured-contract result=pass" in production, production
        assert "stage=normalized-qshell-plan operations=65 cwd=/scratch/theo/qshell-project/qshell" in production, production
        assert "stage=completed-root-cwd-rejection component=/scratch/theo/qshell-project/missing-cwd result=pass" in production, production
        assert '"stage":"landlock_semantic_composition_runtime"' in production, production
        assert '"selected_branch":"bubblewrap_semantic_adapter"' in production, production
        assert '"landlock_composes":true' in production, production
        return production

    with subtest("production semantic adapter preserves an ordinary deep /scratch cwd"):
        run_production("ordinary")

    with subtest("production semantic adapter preserves a symlinked /scratch cwd"):
        machine.succeed(
            "rm -rf /scratch && "
            "install -d -o tester -g users -m 0755 /zroot/scratch-real/theo/qshell-project/qshell /zroot/scratch-real/theo/outside && "
            "ln -s /zroot/scratch-real /scratch"
        )
        run_production("symlink")

    with subtest("production semantic adapter preserves a separate project submount cwd"):
        machine.succeed(
            "rm /scratch && rm -rf /zroot/scratch-real && "
            "install -d -o tester -g users -m 0755 /scratch/theo/qshell-project /scratch/theo/outside && "
            "mount -t tmpfs -o nosuid,nodev,size=16m tmpfs /scratch/theo/qshell-project && "
            "install -d -o tester -g users -m 0755 /scratch/theo/qshell-project/qshell"
        )
        run_production("separate-mount")
  '';
}
