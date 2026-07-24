{
  pkgs,
  agentshPackage,
  agentshSource,
  basePolicy,
}:
let
  lib = pkgs.lib;
  yaml = pkgs.formats.yaml { };
  projectRoot = "/scratch/theo/qshell-project";
  qshellRoot = "${projectRoot}/qshell";
  symlinkedQshellRoot = "/zroot/scratch-real/theo/qshell-project/qshell";
  releaseUID = "1234";
  releaseLease = "lease-22222222-2222-4222-8222-222222222222";
  releaseRuntimeRoot = "/run/agentsh/nethelper/${releaseUID}/${releaseLease}";
  scratchRoot = "${releaseRuntimeRoot}/composition";
  qshellArgvFixture = "${agentshSource}/internal/composition/testdata/qshell-bwrap-0.11.2-argv.json";

  sourceFixture = pkgs.runCommand "agentsh-release-gate-read-only-source" { } ''
    mkdir -p "$out/descendant"
    printf '%s\n' broker-source > "$out/marker"
    printf '%s\n' broker-descendant > "$out/descendant/marker"
    cat > "$out/denied-helper" <<'EOF'
    #!${pkgs.runtimeShell}
    printf '%s\n' source-command-policy-bypass
    EOF
    chmod 0755 "$out/denied-helper"
  '';

  qshellPathFixture = pkgs.runCommand "agentsh-release-gate-qshell-store-path" { } ''
    mkdir -p "$out/etc"
  '';

  payloadHelper = pkgs.writeShellApplication {
    name = "agentsh-release-gate-payload";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      set -euo pipefail
      case "$(pwd)" in
        ${qshellRoot}|${symlinkedQshellRoot}) ;;
        *) echo "unexpected completed-root cwd: $(pwd)" >&2; exit 1 ;;
      esac
      test "$(cat /nix-support/marker)" = broker-source
      test "$(cat ${qshellPathFixture}/etc/rpc)" = broker-source
      test -r /.host-etc/os-release
      if test -e /.host-etc/shadow; then
        echo "source metadata policy was bypassed" >&2
        exit 1
      fi
      if cat /.host-etc/shadow >/dev/null 2>&1; then
        echo "source file policy was bypassed" >&2
        exit 1
      fi
      printf '%s\n' project-write > .agentsh-release-gate-write
      test "$(cat .agentsh-release-gate-write)" = project-write
      rm .agentsh-release-gate-write
      if cat /scratch/theo/outside/agentsh-release-gate-secret >/dev/null 2>&1; then
        echo "the /scratch list-only alias broadened sibling read authority" >&2
        exit 1
      fi
      if cat /mnt/agentsh-release-gate-secret >/dev/null 2>&1; then
        echo "a list-only FHS bind root gained file-read authority" >&2
        exit 1
      fi
      if cat /home/theo/agentsh-release-gate-secret >/dev/null 2>&1; then
        echo "the /home list-only bind root gained unrelated file-read authority" >&2
        exit 1
      fi
      if printf denied > /scratch/theo/outside/agentsh-release-gate-write 2>/dev/null; then
        echo "the /scratch alias broadened project write authority" >&2
        exit 1
      fi
      if printf denied > /nix/agentsh-release-gate-write 2>/dev/null; then
        echo "the /nix alias became writable" >&2
        exit 1
      fi
      if printf denied > /nix/store/agentsh-release-gate-write 2>/dev/null; then
        echo "the /nix/store alias became writable" >&2
        exit 1
      fi
      if /nix-support/denied-helper >/dev/null 2>&1; then
        echo "source command policy was bypassed through a visible alias" >&2
        exit 1
      fi
      test -d /tmp/.X11-unix
      test -c /dev/null
      if test -e /run/agentsh/recovery; then
        echo "AgentSH recovery controls leaked into the composed root" >&2
        exit 1
      fi
      if test -e ${scratchRoot}; then
        echo "AgentSH composition runtime leaked into the payload" >&2
        exit 1
      fi
      for control_variable in AGENTSH_NETHELPER_BOOTSTRAP_RESULT AGENTSH_NETHELPER_RECOVERY_TOKEN_FILE; do
        if printenv "$control_variable" >/dev/null 2>&1; then
          echo "AgentSH helper control environment leaked into the payload: $control_variable" >&2
          exit 1
        fi
      done
      if test "''${QSHELL_RELEASE_MODE:?}" = vivado-version; then
        ${recursiveDriver}/bin/agentsh-release-gate-recursive-driver
      fi
      printf 'qshell-release-payload cwd=%s mode=%s result=pass\n' "$(pwd)" "$QSHELL_RELEASE_MODE"
    '';
  };

  qshellDriver = pkgs.writeShellApplication {
    name = "agentsh-release-gate-qshell-driver";
    runtimeInputs = [ pkgs.python3 ];
    text = ''
      # Match Nixpkgs buildFHSEnv's runtime auto-mount discovery. This must run
      # inside the real AgentSH boundary: replaying the captured argv would miss
      # a policy or Landlock denial of the `/*` scan.
      ignored=(/nix /dev /proc /etc /bin /lib /lib32 /lib64 /libexec /sbin /usr)
      declare -A ignored_set=()
      for path in "''${ignored[@]}"; do
        ignored_set["$path"]=1
      done
      auto_mount_roots=()
      for dir in /*; do
        if [[ -d "$dir" && -z "''${ignored_set[$dir]:-}" ]]; then
          auto_mount_roots+=("$dir")
        fi
      done

      exec python3 - "''${auto_mount_roots[@]}" <<'PY'
      import json
      import os
      import sys

      with open("${qshellArgvFixture}", encoding="utf-8") as stream:
          captured = json.load(stream)

      captured_auto_roots = {
          "/boot", "/home", "/mnt", "/opt", "/root", "/run", "/scratch",
          "/share", "/srv", "/sys", "/tmp", "/var", "/zokelmannvms", "/zroot",
      }
      auto_mount_roots = sys.argv[1:]
      ordinary_auto_roots = ["/home", "/mnt", "/scratch", "/share", "/sys", "/tmp", "/var"]
      symlinked_auto_roots = ordinary_auto_roots + ["/zroot"]
      if auto_mount_roots not in (ordinary_auto_roots, symlinked_auto_roots):
          raise SystemExit(
              f"unexpected policy-filtered FHS auto mounts: {auto_mount_roots!r}; "
              f"want {ordinary_auto_roots!r} or {symlinked_auto_roots!r}"
          )

      # Keep the 51 fixed captured operations, but discard the 14 host roots
      # that were generated outside AgentSH and replace them with this command's
      # policy-filtered runtime discovery.
      argv = [captured[0]]
      index = 1
      while index < len(captured):
          if (
              captured[index] == "--bind"
              and index + 2 < len(captured)
              and captured[index + 1] == captured[index + 2]
              and captured[index + 1] in captured_auto_roots
          ):
              index += 3
              continue
          argv.append(captured[index])
          index += 1
      insertion = next(
          index
          for index in range(1, len(argv) - 1)
          if argv[index] == "--tmpfs" and argv[index + 1] == "/tmp/.X11-unix"
      )
      dynamic_mounts = [
          argument
          for root in auto_mount_roots
          for argument in ("--bind", root, root)
      ]
      argv[insertion:insertion] = dynamic_mounts

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

      argv = [argument.replace(captured_glibc, dynamic_glibc) for argument in argv]
      payload = argv.index("/nix/store/bf1n8hy1zs7lwyhv282kh9y575iziyk6-container-init")
      argv[payload:] = ["${payloadHelper}/bin/agentsh-release-gate-payload"]
      os.execv(argv[0], argv)
      PY
    '';
  };

  recursivePayload = pkgs.writeShellApplication {
    name = "agentsh-release-gate-recursive-payload";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      set -euo pipefail
      case "$(pwd)" in
        ${qshellRoot}|${symlinkedQshellRoot}) ;;
        *) echo "unexpected recursive cwd: $(pwd)" >&2; exit 1 ;;
      esac
      printf 'qshell-release-recursive cwd=%s result=pass\n' "$(pwd)"
    '';
  };

  recursiveDriver = pkgs.writeShellApplication {
    name = "agentsh-release-gate-recursive-driver";
    runtimeInputs = [ pkgs.bubblewrap ];
    text = ''
      set -euo pipefail
      exec bwrap \
        --die-with-parent \
        --bind /nix /nix \
        --bind /scratch /scratch \
        --chdir ${qshellRoot} \
        -- ${recursivePayload}/bin/agentsh-release-gate-recursive-payload
    '';
  };

  mockNix = pkgs.writeShellApplication {
    name = "nix";
    text = ''
      set -euo pipefail
      test "$HOME" = /home/theo
      test "$XDG_CONFIG_HOME" = /home/theo/.config-rose
      test "$XDG_CACHE_HOME" = /scratch/theo/.cache
      test "$XDG_STATE_HOME" = /scratch/theo/.local/share
      test "$XDG_DATA_HOME" = /home/theo/.local/share
      if ! test -d "$XDG_CACHE_HOME/nix"; then
        printf 'release-gate cache directory is unavailable inside AgentSH: %s\\n' "$XDG_CACHE_HOME/nix" >&2
        ls -ld /scratch /scratch/theo "$XDG_CACHE_HOME" "$XDG_CACHE_HOME/nix" >&2 || true
        exit 1
      fi
      cache_probe="$XDG_CACHE_HOME/nix/fetcher-cache-v4.sqlite.release-gate.$$"
      printf '%s\n' cache-write-pass > "$cache_probe"
      test "$(cat "$cache_probe")" = cache-write-pass
      rm "$cache_probe"
      case "$*" in
        "develop .#ultrascale --command true")
          export QSHELL_RELEASE_MODE=true
          ;;
        "develop .#ultrascale --command vivado -version")
          export QSHELL_RELEASE_MODE=vivado-version
          ;;
        *)
          echo "unexpected release-gate nix argv: $*" >&2
          exit 64
          ;;
      esac
      exec ${qshellDriver}/bin/agentsh-release-gate-qshell-driver
    '';
  };

  reviewedShellPattern = "^-c[[:space:]]+(cd[[:space:]]+(${qshellRoot}|qshell|\\./qshell)[[:space:]]+&&[[:space:]]+)?nix[[:space:]]+develop[[:space:]]+\\.#ultrascale[[:space:]]+--command[[:space:]]+(true|vivado[[:space:]]+-version)[[:space:]]*$";

  projectOverlay = yaml.generate "qshell-release-overlay.yaml" {
    name = "qshell-release-gate";
    command_rules = [
      {
        name = "allow-reviewed-qshell-outer-bash";
        description = "Select reviewed QShell composition only for Pi exec_bash intent inside the trusted project";
        commands = [ "bash" ];
        args_patterns = [ reviewedShellPattern ];
        working_directory_roots = [ "\${PROJECT_ROOT}" ];
        decision = "allow";
        sandbox_composition = "bubblewrap-0.11.2";
      }
      {
        name = "allow-reviewed-qshell-direct-nix";
        commands = [ "nix" ];
        args_patterns = [
          "^develop[[:space:]]+\\.#ultrascale[[:space:]]+--command[[:space:]]+(true|vivado[[:space:]]+-version)[[:space:]]*$"
        ];
        working_directory_roots = [ "\${PROJECT_ROOT}" ];
        decision = "allow";
        sandbox_composition = "bubblewrap-0.11.2";
      }
      {
        name = "deny-release-gate-source-command";
        description = "Keep a denied source executable denied through an allowed-looking composed alias";
        commands = [ "${sourceFixture}/denied-helper" ];
        decision = "deny";
      }
      {
        name = "allow-release-gate-visible-command-alias-probe";
        commands = [ "/nix-support/denied-helper" ];
        decision = "allow";
      }
      {
        name = "allow-release-gate-immutable-helpers";
        commands = [
          "${qshellDriver}/bin/agentsh-release-gate-qshell-driver"
          "${payloadHelper}/bin/agentsh-release-gate-payload"
          "${recursiveDriver}/bin/agentsh-release-gate-recursive-driver"
          "${recursivePayload}/bin/agentsh-release-gate-recursive-payload"
          "${pkgs.bubblewrap}/bin/bwrap"
          "${agentshPackage}/bin/agentsh-bwrap-adapter"
          "${agentshPackage}/bin/agentsh-composition-mount-helper"
          "${agentshPackage}/bin/agentsh-composition-ns-launcher"
        ];
        decision = "allow";
      }
    ];
    file_rules = [
      {
        name = "allow-release-gate-fhs-root-discovery";
        description = "Permit the Nixpkgs FHS launcher to enumerate only the top-level directory names";
        paths = [ "/" ];
        operations = [
          "access"
          "list"
          "open"
          "readlink"
          "stat"
        ];
        decision = "allow";
      }
      {
        name = "allow-release-gate-fhs-bind-root-metadata";
        description = "Permit metadata and directory-list authority, but not file reads, for policy-visible FHS bind roots";
        paths = [
          "/home"
          "/mnt"
          "/scratch"
          "/share"
          "/sys"
          "/tmp"
          "/var"
          "/zroot/scratch-real"
        ];
        operations = [
          "access"
          "list"
          "readlink"
          "stat"
        ];
        decision = "allow";
      }
      {
        name = "allow-release-gate-scratch-alias-parent-metadata";
        description = "Preserve metadata-only traversal through the reviewed lexical project parent when /scratch is a symlink";
        paths = [ "/scratch/theo" ];
        operations = [
          "access"
          "readlink"
          "stat"
        ];
        decision = "allow";
      }
      {
        name = "allow-release-gate-symlink-source-list-root";
        description = "Retain directory-list authority for the canonical parent only when real-path policy already exposes it";
        paths = [ "/zroot" ];
        operations = [ "list" ];
        decision = "allow";
      }
      {
        name = "deny-release-gate-unreviewed-fhs-bind-root-metadata";
        description = "Make unreviewed top-level directory probes fail noninteractively after root discovery";
        paths = [ "/*" ];
        operations = [
          "access"
          "readlink"
          "stat"
        ];
        decision = "deny";
      }
      {
        name = "allow-release-gate-python-nix-prefix-metadata";
        description = "Allow immutable Python prefix probes without granting any /nix mutation";
        paths = [
          "/nix/lib"
          "/nix/lib/**"
        ];
        operations = [
          "access"
          "list"
          "open"
          "read"
          "readlink"
          "stat"
        ];
        decision = "allow";
      }
      {
        name = "allow-release-gate-reviewed-visible-aliases";
        description = "Permit reviewed visible aliases while retaining independent source-object policy checks";
        paths = [
          "/.host-etc"
          "/.host-etc/**"
          "/nix-support"
          "/nix-support/**"
        ];
        operations = [
          "access"
          "list"
          "open"
          "read"
          "readlink"
          "stat"
        ];
        decision = "allow";
      }
      {
        name = "allow-release-gate-os-release-source";
        description = "Permit the reviewed non-sensitive source object behind the host-etc alias";
        paths = [ "/etc/os-release" ];
        operations = [
          "access"
          "open"
          "read"
          "readlink"
          "stat"
        ];
        decision = "allow";
      }
      {
        name = "allow-release-gate-visible-project-alias-write";
        description = "Permit the reviewed lexical project alias while source policy independently confines the canonical project object";
        paths = [
          projectRoot
          "${projectRoot}/**"
        ];
        operations = [ "*" ];
        decision = "allow";
      }
      {
        name = "deny-release-gate-list-only-read-probes";
        description = "Keep files beneath metadata-only FHS roots unreadable through composed aliases";
        paths = [
          "/home/theo/agentsh-release-gate-secret"
          "/mnt/agentsh-release-gate-secret"
          "/run/agentsh/recovery"
          "/scratch/theo/outside/agentsh-release-gate-secret"
        ];
        operations = [
          "access"
          "open"
          "read"
          "readlink"
          "stat"
        ];
        decision = "deny";
      }
      {
        name = "deny-release-gate-reviewed-write-probes";
        description = "Deny release-gate mutation probes without entering an interactive approval path";
        paths = [
          "/nix"
          "/nix/**"
          "/scratch/theo/outside"
          "/scratch/theo/outside/**"
        ];
        operations = [
          "chmod"
          "chown"
          "create"
          "delete"
          "link"
          "mkdir"
          "mknod"
          "rename"
          "rmdir"
          "symlink"
          "write"
        ];
        decision = "deny";
      }
      {
        name = "deny-release-gate-shadow-source";
        paths = [ "/etc/shadow" ];
        operations = [
          "open"
          "stat"
          "readlink"
          "access"
        ];
        decision = "deny";
        message = "The release gate keeps source-aware sensitive metadata denied through aliases.";
      }
    ];
  };

  policyDirectory = pkgs.runCommand "agentsh-release-gate-policies" { } ''
    mkdir -p "$out"
    cp ${basePolicy} "$out/pi-supervised.yaml"
  '';

  serverConfigDocument = {
    server = {
      http.addr = "127.0.0.1:18080";
      grpc.enabled = false;
      unix_socket = {
        enabled = true;
        path = "/run/agentsh-release/control.sock";
      };
    };
    auth.type = "none";
    approvals = {
      enabled = true;
      mode = "local_tty";
      timeout = "30s";
    };
    metrics.enabled = false;
    policies = {
      dir = policyDirectory;
      default = "pi-supervised";
      project_overlays = {
        enabled = true;
        paths = [ ".agentsh/policy-overlays/*.yaml" ];
        require_approval = false;
        on_denied = "fail";
      };
    };
    sessions = {
      base_dir = "/var/lib/agentsh-release/sessions";
      workspace_overlay.enabled = false;
      workspace_shadow.enabled = false;
    };
    audit = {
      enabled = true;
      output = "/var/lib/agentsh-release/audit.jsonl";
      storage.sqlite_path = "/var/lib/agentsh-release/events.db";
    };
    landlock = {
      enabled = true;
      network = {
        allow_connect_tcp = true;
        allow_bind_tcp = true;
      };
    };
    sandbox = {
      fuse.enabled = false;
      cgroups.enabled = false;
      network = {
        enabled = true;
        transparent.enabled = false;
        ebpf = {
          enabled = true;
          enforce = true;
          required = false;
        };
      };
      unix_sockets = {
        enabled = true;
        wrapper_bin = "${agentshPackage}/bin/agentsh-unixwrap";
      };
      seccomp = {
        wait_killable = false;
        execve.enabled = true;
        file_monitor = {
          enabled = true;
          enforce_without_fuse = true;
          intercept_metadata = true;
          write_only_opens = false;
          openat_emulation = false;
          block_io_uring = true;
        };
      };
      ptrace.enabled = false;
      composition.bubblewrap = {
        enabled = true;
        dialect = "0.11.2";
        adapter_path = "${agentshPackage}/bin/agentsh-bwrap-adapter";
        mount_helper_path = "${agentshPackage}/bin/agentsh-composition-mount-helper";
        scratch_root = "auto";
        max_namespace_depth = 4;
        max_namespace_transitions = 32;
        max_plan_operations = 256;
        max_synthetic_mounts = 16;
        max_data_bytes = 16777216;
        device_ioctl_paths = [ ];
      };
      env_inject.PYTHONNOUSERSITE = "1";
      env_inject.PATH = lib.makeBinPath [
        mockNix
        pkgs.bash
        pkgs.coreutils
        pkgs.findutils
        pkgs.gnugrep
        pkgs.gnused
        pkgs.nix
        pkgs.python3
        pkgs.util-linux
      ];
    };
  };

  serverConfig = yaml.generate "agentsh-qshell-release-config.yaml" serverConfigDocument;
  invalidRuntimeServerConfig = yaml.generate "agentsh-qshell-invalid-runtime-config.yaml" (
    lib.recursiveUpdate serverConfigDocument {
      server = {
        http.addr = "127.0.0.1:18081";
        unix_socket.path = "/run/agentsh-auto-runtime/control.sock";
      };
      sessions.base_dir = "/run/agentsh-auto-runtime/sessions";
      audit = {
        output = "/run/agentsh-auto-runtime/audit.jsonl";
        storage.sqlite_path = "/run/agentsh-auto-runtime/events.db";
      };
      sandbox.composition.bubblewrap.scratch_root = "auto";
    }
  );

  serverLauncher = pkgs.writeShellScript "agentsh-release-gate-server" ''
    set -eu
    export AGENTSH_NETHELPER_INSTANCE_CREDENTIAL="$(${pkgs.coreutils}/bin/cat ${releaseRuntimeRoot}/instance-credential)"
    exec ${agentshPackage}/bin/agentsh server --config ${serverConfig}
  '';

  nethelperBootstrapLauncher = pkgs.writeShellScript "agentsh-release-gate-nethelper-bootstrap" ''
    set -eu
    export SUDO_UID=${releaseUID}
    export SUDO_GID=${releaseUID}
    export SUDO_USER=agentsh-release-user
    exec ${agentshPackage}/bin/agentsh nethelper bootstrap \
      --uid ${releaseUID} --gid ${releaseUID} --lease ${releaseLease} \
      --runtime 192h --soft-lease 49h
  '';
in
assert lib.versionAtLeast pkgs.bubblewrap.version "0.11.2";
pkgs.testers.runNixOSTest {
  name = "agentsh-qshell-composition-release-gate";

  nodes.machine = {
    security.unprivilegedUsernsClone = true;
    boot.kernel.sysctl."user.max_user_namespaces" = 1024;
    fileSystems."/sys/fs/bpf" = {
      device = "bpffs";
      fsType = "bpf";
      options = [ "mode=0700" ];
    };
    users.groups.agentsh-release-user.gid = 1234;
    users.users.agentsh-release-user = {
      isNormalUser = true;
      uid = 1234;
      group = "agentsh-release-user";
    };
    environment.systemPackages = [
      agentshPackage
      pkgs.curl
      pkgs.jq
      pkgs.python3
      pkgs.util-linux
    ];
    systemd.tmpfiles.rules = [
      "d /var/lib/agentsh-release 0700 agentsh-release-user agentsh-release-user -"
      "d /run/agentsh-release 0700 agentsh-release-user agentsh-release-user -"
      "d /boot 0755 root root -"
      "d /home 0755 root root -"
      "d /home/theo 0755 agentsh-release-user agentsh-release-user -"
      "d /home/theo/.config-rose 0755 agentsh-release-user agentsh-release-user -"
      "d /home/theo/.config-rose/nix 0755 agentsh-release-user agentsh-release-user -"
      "d /home/theo/.local 0755 agentsh-release-user agentsh-release-user -"
      "d /home/theo/.local/share 0755 agentsh-release-user agentsh-release-user -"
      "d /home/theo/.local/share/nix 0755 agentsh-release-user agentsh-release-user -"
      "d /mnt 0755 root root -"
      "d /opt 0755 root root -"
      "d /share 0755 root root -"
      "d /srv 0755 root root -"
      "d /zokelmannvms 0755 root root -"
      "d /zroot 0755 root root -"
      "d /scratch/theo 0755 agentsh-release-user agentsh-release-user -"
      "d /scratch/theo/.cache 0755 agentsh-release-user agentsh-release-user -"
      "d /scratch/theo/.cache/nix 0755 agentsh-release-user agentsh-release-user -"
      "d /scratch/theo/.local 0755 agentsh-release-user agentsh-release-user -"
      "d /scratch/theo/.local/share 0755 agentsh-release-user agentsh-release-user -"
      "d /scratch/theo/.local/share/nix 0755 agentsh-release-user agentsh-release-user -"
    ];
    systemd.services.agentsh-release-nethelper-bootstrap = {
      requiredBy = [ "agentsh-supervisor-release-gate.service" ];
      before = [ "agentsh-supervisor-release-gate.service" ];
      after = [
        "sys-fs-bpf.mount"
        "systemd-tmpfiles-setup.service"
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = nethelperBootstrapLauncher;
        User = "root";
        Group = "root";
      };
    };
    systemd.services.agentsh-supervisor-release-gate = {
      wantedBy = [ "multi-user.target" ];
      requires = [ "agentsh-release-nethelper-bootstrap.service" ];
      after = [
        "network.target"
        "agentsh-release-nethelper-bootstrap.service"
      ];
      environment = {
        AGENTSH_NETHELPER_SOCKET = "${releaseRuntimeRoot}/nethelper.sock";
        AGENTSH_NETHELPER_CREDENTIAL_FILE = "${releaseRuntimeRoot}/instance-credential";
        AGENTSH_NETHELPER_BOOTSTRAP_RESULT = "${releaseRuntimeRoot}/bootstrap.json";
        AGENTSH_DETACHED_SUPERVISOR_LAUNCH_MODE = "systemd-user-delegated";
        XDG_CACHE_HOME = "/scratch/theo/.cache";
        XDG_CONFIG_HOME = "/home/theo/.config-rose";
        XDG_DATA_HOME = "/home/theo/.local/share";
        XDG_STATE_HOME = "/scratch/theo/.local/share";
      };
      serviceConfig = {
        Type = "simple";
        ExecStart = serverLauncher;
        Restart = "no";
        User = "agentsh-release-user";
        Group = "agentsh-release-user";
        Delegate = true;
        LimitMEMLOCK = "infinity";
        StandardOutput = "append:/var/lib/agentsh-release/server.log";
        StandardError = "append:/var/lib/agentsh-release/server.log";
      };
    };
    virtualisation = {
      memorySize = 3072;
      cores = 2;
    };
    system.stateVersion = "25.11";
  };

  testScript = ''
    import json
    import shlex

    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("systemctl is-active agentsh-supervisor-release-gate.service || { cat /var/lib/agentsh-release/server.log >&2; exit 1; }")
    machine.wait_until_succeeds("curl -fsS http://127.0.0.1:18080/health", timeout=30)
    machine.succeed("test -x ${agentshPackage}/bin/.agentsh-unixwrap-wrapped")

    with subtest("main supervisor uses the privileged lease-scoped composition runtime"):
        machine.succeed(
            "jq -e --arg scratch ${scratchRoot} '"
            ".bootstrap_schema_version >= 3 and .lease_id == \"${releaseLease}\" and "
            ".composition_scratch_root == $scratch' ${releaseRuntimeRoot}/bootstrap.json >/dev/null"
        )
        assert machine.succeed("stat -Lc '%u:%g:%a' ${scratchRoot}").strip() == "0:0:1733"
        machine.fail("test -e /agentsh-composition-scratch")
        machine.fail("grep -E '/agentsh-composition-scratch|/run/agentsh/nethelper' ${projectOverlay}")
        machine.succeed(
            "runuser -u agentsh-release-user -- sh -c '"
            "printf cache-host-pass > /scratch/theo/.cache/nix/release-host-probe && "
            "rm /scratch/theo/.cache/nix/release-host-probe'"
        )
        machine.succeed(
            "jq -s -e '"
            "([.[] | select(.type == \"composition_runtime_provisioned\" and .fields.mode == \"lease\" and "
            ".fields.lease_id == \"${releaseLease}\" and .fields.scratch_root == \"${scratchRoot}\" and "
            ".fields.owner == \"root:root\" and .fields.mode_bits == \"1733\")] | length == 1) and "
            "([.[] | select(.type == \"composition_runtime_ready\" and .fields.mode == \"lease\" and "
            ".fields.lease_id == \"${releaseLease}\" and .fields.scratch_root == \"${scratchRoot}\")] | length == 1)' "
            "/var/lib/agentsh-release/audit.jsonl >/dev/null"
        )

    with subtest("unsafe runtime permissions fail startup with durable evidence"):
        lease = "lease-33333333-3333-4333-8333-333333333333"
        runtime = "/run/agentsh/nethelper/1234/" + lease
        scratch = runtime + "/composition"
        socket = runtime + "/nethelper.sock"
        credential = runtime + "/instance-credential"
        result = runtime + "/bootstrap.json"
        machine.succeed(
            "env SUDO_UID=1234 SUDO_GID=1234 SUDO_USER=agentsh-release-user "
            "${agentshPackage}/bin/agentsh nethelper bootstrap --uid 1234 --gid 1234 "
            "--lease " + lease + " --runtime 1h"
        )
        machine.succeed("chmod 0733 " + shlex.quote(scratch))
        machine.succeed("install -d -o agentsh-release-user -g agentsh-release-user -m 0700 /run/agentsh-auto-runtime")
        machine.succeed(
            "systemd-run --unit=agentsh-invalid-runtime --property=User=agentsh-release-user "
            "--property=Group=agentsh-release-user --property=Delegate=yes "
            "--property=Environment=AGENTSH_NETHELPER_SOCKET=" + shlex.quote(socket) + " "
            "--property=Environment=AGENTSH_NETHELPER_CREDENTIAL_FILE=" + shlex.quote(credential) + " "
            "--property=Environment=AGENTSH_NETHELPER_BOOTSTRAP_RESULT=" + shlex.quote(result) + " "
            "-- ${agentshPackage}/bin/agentsh server --config ${invalidRuntimeServerConfig}"
        )
        machine.wait_until_succeeds(
            "test -s /run/agentsh-auto-runtime/audit.jsonl && "
            "! systemctl is-active --quiet agentsh-invalid-runtime.service",
            timeout=20,
        )
        machine.succeed(
            "jq -s -e '[.[] | select(.type == \"composition_runtime_failed\" and "
            "(.fields.reason | contains(\"unsafe type, mode, or ownership\")) and "
            "(.fields.reason | contains(\"type=040000 mode=0733 uid=0 gid=0\")))] | length == 1' "
            "/run/agentsh-auto-runtime/audit.jsonl >/dev/null"
        )
        machine.succeed("chmod 1733 " + shlex.quote(scratch))
        machine.succeed(
            "runuser -u agentsh-release-user -- ${agentshPackage}/bin/agentsh nethelper release "
            "--socket " + shlex.quote(socket) + " --credential-file " + shlex.quote(credential) + " --lease " + lease
        )
        machine.wait_until_succeeds("test ! -e " + shlex.quote(runtime), timeout=10)

    machine.succeed(
        "python3 - <<'PY'\n"
        "import json\n"
        "argv=json.load(open('${qshellArgvFixture}'))\n"
        "options={'--symlink':2,'--bind':2,'--ro-bind':2,'--tmpfs':1,'--dev-bind':2,'--proc':1,'--chdir':1,'--die-with-parent':0,'--remount-ro':1}\n"
        "i=1; count=0\n"
        "while i < len(argv) and argv[i] in options:\n"
        "    count += 1; i += 1 + options[argv[i]]\n"
        "assert count == 67, count\n"
        "assert '--bind' in argv and '/scratch' in argv and '--chdir' in argv\n"
        "PY"
    )

    def install_project(root):
        machine.succeed(
            "install -d -o agentsh-release-user -g agentsh-release-user -m 0755 " + shlex.quote(root) + " " +
            shlex.quote(root + "/qshell") + " " + shlex.quote(root + "/.agentsh") + " " +
            shlex.quote(root + "/.agentsh/policy-overlays") + " && " +
            "install -o agentsh-release-user -g agentsh-release-user -m 0644 ${projectOverlay} " +
            shlex.quote(root + "/.agentsh/policy-overlays/overlay.yaml") + " && " +
            "printf '{ outputs = _: {}; }\\n' > " + shlex.quote(root + "/flake.nix") + " && " +
            "chown agentsh-release-user:agentsh-release-user " + shlex.quote(root + "/flake.nix")
        )

    def create_session(workspace, project_root):
        request = json.dumps({
            "workspace": workspace,
            "project_root": project_root,
            "home": "/home/theo",
            "runtime_home_mode": "real",
            "env_base_mode": "minimal",
            "env_inherit": [
                "XDG_CONFIG_HOME",
                "XDG_CACHE_HOME",
                "XDG_STATE_HOME",
                "XDG_DATA_HOME",
            ],
            "policy": "pi-supervised",
            "real_paths": True,
            "workspace_mode": "direct",
        })
        response = machine.succeed(
            "curl -sS -H 'content-type: application/json' -X POST "
            "http://127.0.0.1:18080/api/v1/sessions --data " + shlex.quote(request)
        )
        session = json.loads(response)
        assert "id" in session, response
        session_id = session["id"]
        preflight_raw = machine.succeed(
            "curl -sS -H 'content-type: application/json' -X POST "
            "http://127.0.0.1:18080/api/v1/sessions/" + session_id
            + "/network-enforcement/preflight"
        )
        preflight = json.loads(preflight_raw)
        assert preflight["readiness"] == "ready", preflight_raw
        jail = preflight["preflight"]
        assert jail["status"] == "ready", preflight_raw
        for invariant in [
            "private_proc_proven",
            "cgroupfs_hidden",
            "control_paths_hidden",
            "credential_source_hidden",
            "helper_socket_hidden",
            "inherited_descriptors_closed",
            "no_new_privs",
        ]:
            assert jail[invariant] is True, (invariant, preflight_raw)
        return session_id

    def exec_bash(session, cwd, command):
        request = json.dumps({"command": command, "cwd": cwd, "include_events": "all"})
        raw = machine.succeed(
            "curl -sS -H 'content-type: application/json' -X POST "
            + "http://127.0.0.1:18080/api/v1/sessions/" + session
            + "/tools/exec_bash --data " + shlex.quote(request)
        )
        response = json.loads(raw)
        assert response["ok"] is True, raw
        result = response["result"]
        if result["exit_code"] != 0:
            server_tail = machine.succeed("tail -n 200 /var/lib/agentsh-release/server.log")
            raise AssertionError(raw + "\nserver log:\n" + server_tail)
        assert "qshell-release-payload" in result["stdout"], raw
        assert "overflowuid" not in result["stderr"], raw
        return response

    def composition_plan_count():
        return int(machine.succeed("grep -c '\"type\":\"composition_plan\"' /var/lib/agentsh-release/audit.jsonl || true").strip())

    machine.succeed("install -d -m 0755 /scratch/theo/outside && printf denied > /scratch/theo/outside/agentsh-release-gate-secret && printf denied > /mnt/agentsh-release-gate-secret && printf denied > /home/theo/agentsh-release-gate-secret")
    install_project("${projectRoot}")
    ordinary = create_session("${projectRoot}", "${projectRoot}")

    with subtest("Pi exec_bash absolute, relative, dot-relative, and already-in-QShell forms select composition"):
        forms = [
            ("${projectRoot}", "cd ${qshellRoot} && nix develop .#ultrascale --command true"),
            ("${projectRoot}", "cd qshell && nix develop .#ultrascale --command true"),
            ("${projectRoot}", "cd ./qshell && nix develop .#ultrascale --command true"),
            ("${qshellRoot}", "nix develop .#ultrascale --command vivado -version"),
        ]
        before = composition_plan_count()
        for cwd, command in forms:
            response = exec_bash(ordinary, cwd, command)
            if command.endswith("vivado -version"):
                assert "qshell-release-recursive" in response["result"]["stdout"], response
        assert composition_plan_count() == before + len(forms) + 1

    with subtest("arbitrary Bash in the project does not select composition"):
        before = composition_plan_count()
        request = json.dumps({"command": "printf arbitrary-bash-pass", "cwd": "${projectRoot}"})
        raw = machine.succeed(
            "curl -sS -H 'content-type: application/json' -X POST "
            + "http://127.0.0.1:18080/api/v1/sessions/" + ordinary
            + "/tools/exec_bash --data " + shlex.quote(request)
        )
        response = json.loads(raw)
        assert response["ok"] is True and response["result"]["stdout"] == "arbitrary-bash-pass", raw
        assert composition_plan_count() == before

    with subtest("a symlinked /scratch root preserves the completed QShell cwd"):
        machine.succeed(
            "rm -rf /scratch && install -d -m 0755 /zroot/scratch-real/theo/outside && "
            "install -d -o agentsh-release-user -g agentsh-release-user -m 0755 /zroot/scratch-real/theo/.cache/nix /zroot/scratch-real/theo/.local/share/nix && "
            "ln -s /zroot/scratch-real /scratch"
        )
        install_project("/zroot/scratch-real/theo/qshell-project")
        symlinked = create_session("${projectRoot}", "${projectRoot}")
        exec_bash(symlinked, "${projectRoot}", "cd qshell && nix develop .#ultrascale --command true")

    with subtest("a separate project submount preserves the completed QShell cwd"):
        machine.succeed(
            "rm /scratch && rm -rf /zroot/scratch-real && "
            "install -d -m 0755 ${projectRoot} /scratch/theo/outside && "
            "install -d -o agentsh-release-user -g agentsh-release-user -m 0755 /scratch/theo/.cache/nix /scratch/theo/.local/share/nix && "
            "mount -t tmpfs -o nosuid,nodev,size=32m tmpfs ${projectRoot}"
        )
        install_project("${projectRoot}")
        mounted = create_session("${projectRoot}", "${projectRoot}")
        exec_bash(mounted, "${qshellRoot}", "nix develop .#ultrascale --command true")

    with subtest("normalized plans, exact started PIDs, and approval-free adapter selection are audited"):
        machine.succeed(
            "jq -s -e '"
            "[.[] | select(.type == \"composition_plan\")] as $plans | "
            "[.[] | select(.type == \"execve\" and .filename == \"${pkgs.bubblewrap}/bin/bwrap\")] as $bwrap | "
            "[$plans[] | select((.fields.normalized_plan.operation_count == 58 or .fields.normalized_plan.operation_count == 59) and "
            ".fields.normalized_plan.cwd == \"${qshellRoot}\" and "
            "([.fields.normalized_plan.operations[] | select(.type == \"bind\" and .source == \"/scratch\" and .target == \"/scratch\" and .recursive == true)] | length) == 1 and "
            "(([.fields.normalized_plan.operations[] | select(.type == \"bind\" and .source == .target and .source != \"/nix\") | .source] | sort) as $roots | "
            "($roots == [\"/home\", \"/mnt\", \"/scratch\", \"/share\", \"/sys\", \"/tmp\", \"/var\"] or $roots == [\"/home\", \"/mnt\", \"/scratch\", \"/share\", \"/sys\", \"/tmp\", \"/var\", \"/zroot\"])))] as $qshell | "
            "[$plans[] | select(.fields.normalized_plan.operation_count == 2 and "
            ".fields.normalized_plan.cwd == \"${qshellRoot}\")] as $recursive | "
            "($plans | length) == 7 and ($qshell | length) == 6 and ($recursive | length) == 1 and "
            "($bwrap | length) == ($plans | length) and "
            "all($plans[]; .fields.parent_pid > 0 and .fields.target_pid > 0 and .fields.parent_pid != .fields.target_pid) and "
            "all($bwrap[]; .effective_action == \"composition\" and .fields.sandbox_composition == \"bubblewrap-0.11.2\") and "
            "([$plans[].fields.parent_pid] | sort) == ([$bwrap[].pid] | sort)' "
            "/var/lib/agentsh-release/audit.jsonl >/dev/null"
        )
        machine.succeed(
            "jq -s -e '"
            "[.[] | select(.type == \"composition_runtime_ready\" and .fields.mode == \"lease\" and "
            ".fields.lease_id == \"${releaseLease}\" and .fields.scratch_root == \"${scratchRoot}\")] | length == 1' "
            "/var/lib/agentsh-release/audit.jsonl >/dev/null"
        )
        machine.succeed("test -z \"$(find ${scratchRoot} -mindepth 1 -maxdepth 1 -print -quit)\"")
        machine.succeed(
            "jq -s -e '"
            "[.[] | select(.type == \"composition_runtime_cleanup\" and .operation == \"synthetic_pool_paths_removed\" and "
            ".fields.scope == \"command\" and .fields.scratch_root == \"${scratchRoot}\" and "
            ".fields.construction_paths_removed == true and (.command_id | type == \"string\" and length > 0))] as $cleanup | "
            "($cleanup | length) == 6 and ([$cleanup[].command_id] | unique | length) == 6' "
            "/var/lib/agentsh-release/audit.jsonl >/dev/null"
        )
        approval_events = machine.succeed(
            "grep -E '\"type\":\"approval_(requested|resolved)\"' "
            "/var/lib/agentsh-release/audit.jsonl || true"
        ).strip()
        assert approval_events == "", approval_events
        machine.fail("grep -F 'overflowuid' /var/lib/agentsh-release/audit.jsonl /var/lib/agentsh-release/server.log")
        machine.fail("grep -F 'E_COMPOSITION_REQUESTER_CHANGED' /var/lib/agentsh-release/audit.jsonl")

    with subtest("lease teardown removes the empty private composition runtime"):
        machine.succeed("systemctl stop agentsh-supervisor-release-gate.service")
        machine.succeed(
            "runuser -u agentsh-release-user -- ${agentshPackage}/bin/agentsh nethelper release "
            "--socket ${releaseRuntimeRoot}/nethelper.sock "
            "--credential-file ${releaseRuntimeRoot}/instance-credential --lease ${releaseLease}"
        )
        machine.wait_until_succeeds("test ! -e ${releaseRuntimeRoot}", timeout=10)
  '';
}
