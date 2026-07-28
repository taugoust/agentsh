{
  config,
  lib,
  pkgs,
  defaultPackage ? null,
  ...
}:
let
  cfg = config.services.agentsh;
  inherit (lib)
    mapAttrs'
    mkEnableOption
    mkIf
    mkOption
    nameValuePair
    optionalAttrs
    types
    ;

  yaml = pkgs.formats.yaml { };

  safeAbsolutePath =
    path:
    lib.hasPrefix "/" path
    && builtins.match "^[A-Za-z0-9_./+@-]+$" path != null
    && !lib.hasInfix "/../" path
    && !lib.hasSuffix "/.." path
    && !lib.hasInfix "/./" path
    && !lib.hasSuffix "/." path;
  nethelperRuntimeDir = instance: "/run/agentsh/nethelper/${toString instance.uid}";
  nethelperSocketPath =
    instance:
    if instance.socketPath != null then
      instance.socketPath
    else
      "${nethelperRuntimeDir instance}/nethelper.sock";
  nethelperCredentialPath = instance: "${nethelperRuntimeDir instance}/instance-credential";
  nethelperPinRoot =
    instance:
    if instance.pinRoot != null then
      instance.pinRoot
    else
      "/sys/fs/bpf/agentsh/nethelper/${toString instance.uid}";
  nethelperCapabilities =
    instance:
    [
      "CAP_BPF"
      "CAP_NET_ADMIN"
      "CAP_PERFMON"
    ]
    ++ lib.optional instance.allowCompatSysAdmin "CAP_SYS_ADMIN";

  nethelperProfile = lib.concatStringsSep "\n" (
    lib.mapAttrsToList (name: instance: ''
      if [ "$(${pkgs.coreutils}/bin/id -u)" = ${lib.escapeShellArg (toString instance.uid)} ]; then
        export AGENTSH_DETACHED_SUPERVISOR_SYSTEMD_RUN=1
        export AGENTSH_NETHELPER_SOCKET=${lib.escapeShellArg (nethelperSocketPath instance)}
        export AGENTSH_NETHELPER_CREDENTIAL_FILE=${lib.escapeShellArg (nethelperCredentialPath instance)}
      fi
    '') cfg.nethelper.instances
  );

  nethelperProvisionServices = mapAttrs' (
    name: instance:
    nameValuePair "agentsh-nethelper-provision-${name}" {
      description = "Provision protected AgentSH nethelper runtime for ${instance.user}";
      before = [
        "agentsh-nethelper-${name}.socket"
        "agentsh-nethelper-${name}.service"
      ];
      # A NixOS switch can restart the socket/helper while this RemainAfterExit
      # oneshot still appears active. Propagate that restart so the protected
      # user-readable runtime credential is recreated before the socket listens.
      partOf = [ "agentsh-nethelper-${name}.socket" ];
      requiredBy = [ "agentsh-nethelper-${name}.socket" ];
      unitConfig.AssertPathIsMountPoint = "/sys/fs/bpf";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        User = "root";
        Group = "root";
        LoadCredential = "agentsh-nethelper-instance-credential:${instance.credentialFile}";
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ReadWritePaths = [
          "/run"
          "/sys/fs/bpf"
        ];
        RestrictAddressFamilies = [ "AF_UNIX" ];
        RestrictNamespaces = true;
        UMask = "0077";
      };
      script = ''
        ${pkgs.coreutils}/bin/install -d -m 0711 -o root -g root /run/agentsh/nethelper
        ${pkgs.coreutils}/bin/install -d -m 0711 -o root -g root ${lib.escapeShellArg (nethelperRuntimeDir instance)}
        ${pkgs.coreutils}/bin/install -m 0400 -o ${lib.escapeShellArg instance.user} -g root \
          "$CREDENTIALS_DIRECTORY/agentsh-nethelper-instance-credential" \
          ${lib.escapeShellArg (nethelperCredentialPath instance)}
        ${pkgs.coreutils}/bin/install -d -m 0700 -o root -g root ${lib.escapeShellArg (nethelperPinRoot instance)}
      '';
    }
  ) cfg.nethelper.instances;

  nethelperSockets = mapAttrs' (
    name: instance:
    nameValuePair "agentsh-nethelper-${name}" {
      description = "AgentSH privileged network helper socket for ${instance.user}";
      # Provisioning consumes the installed SOPS credential after basic.target.
      # Opt this socket out of the implicit Before=sockets.target dependency so
      # it can start later without creating basic.target ordering cycles.
      wantedBy = [ "multi-user.target" ];
      requires = [ "agentsh-nethelper-provision-${name}.service" ];
      after = [ "agentsh-nethelper-provision-${name}.service" ];
      before = [ "shutdown.target" ];
      conflicts = [ "shutdown.target" ];
      unitConfig.DefaultDependencies = false;
      socketConfig = {
        ListenStream = nethelperSocketPath instance;
        Accept = false;
        SocketMode = "0600";
        SocketUser = instance.user;
        SocketGroup = "root";
        FileDescriptorName = "control";
        DirectoryMode = "0711";
        RemoveOnStop = true;
        Service = "agentsh-nethelper-${name}.service";
      };
    }
  ) cfg.nethelper.instances;

  nethelperServices = mapAttrs' (
    name: instance:
    nameValuePair "agentsh-nethelper-${name}" {
      description = "AgentSH root network helper for ${instance.user}";
      requires = [
        "agentsh-nethelper-${name}.socket"
        "agentsh-nethelper-provision-${name}.service"
      ];
      after = [
        "agentsh-nethelper-${name}.socket"
        "agentsh-nethelper-provision-${name}.service"
      ];
      unitConfig = {
        AssertPathIsMountPoint = "/sys/fs/bpf";
      };
      serviceConfig = {
        Type = "simple";
        ExecStart = "${lib.getExe cfg.package} nethelper serve --socket ${nethelperSocketPath instance} --uid ${toString instance.uid} --pin-root ${nethelperPinRoot instance}";
        User = "root";
        Group = "root";
        LoadCredential = "agentsh-nethelper-instance-credential:${instance.credentialFile}";
        UnsetEnvironment = [
          "AGENTSH_DETACHED_EVENT_TOKEN"
          "AGENTSH_NETHELPER_CREDENTIAL_FILE"
          "AGENTSH_NETHELPER_INSTANCE_CREDENTIAL"
          "AGENTSH_NETHELPER_SESSION_NONCE"
        ];
        Restart = "on-failure";
        RestartSec = "1s";

        AmbientCapabilities = nethelperCapabilities instance;
        CapabilityBoundingSet = nethelperCapabilities instance;
        NoNewPrivileges = true;
        DevicePolicy = "closed";
        IPAddressDeny = "any";
        PrivateDevices = true;
        PrivateIPC = true;
        PrivateMounts = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProcSubset = "all";
        ProtectSystem = "strict";
        ReadOnlyPaths = [
          "/run"
          "/sys/fs/cgroup"
        ];
        ReadWritePaths = [ (nethelperPinRoot instance) ];
        RestrictAddressFamilies = [ "AF_UNIX" ];
        SocketBindDeny = "any";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        LimitMEMLOCK = "infinity";
        MemoryDenyWriteExecute = true;
        RemoveIPC = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "bpf"
          "perf_event_open"
          "pidfd_open"
        ];
        SystemCallErrorNumber = "EPERM";
        UMask = "0077";
      };
    }
  ) cfg.nethelper.instances;

  configFile = yaml.generate "agentsh-config.yml" (
    lib.recursiveUpdate {
      server = {
        http.addr = cfg.server.http.addr;
        unix_socket = {
          enabled = cfg.server.unixSocket.enable;
          path = cfg.server.unixSocket.path;
        };
      };

      auth = {
        type = cfg.auth.type;
      }
      // optionalAttrs (cfg.auth.type == "api_key") {
        api_key = {
          keys_file = cfg.auth.apiKey.keysFile;
          header_name = cfg.auth.apiKey.headerName;
        };
      };

      logging = {
        inherit (cfg.logging) level format output;
      };

      audit = {
        enabled = cfg.audit.enable;
        output = cfg.audit.output;
        storage.sqlite_path = cfg.audit.storage.sqlitePath;
      };

      sessions = {
        base_dir = cfg.sessions.baseDir;
        output_artifacts.max_bytes = cfg.sessions.outputArtifacts.maxBytes;
        subagents = {
          default_timeout = cfg.sessions.subagents.defaultTimeout;
          max_exec_concurrency = cfg.sessions.subagents.maxExecConcurrency;
        };
        workspace_overlay = {
          enabled = cfg.sessions.workspaceOverlay.enable;
          base_dir = cfg.sessions.workspaceOverlay.baseDir;
          default_excludes = cfg.sessions.workspaceOverlay.defaultExcludes;
          accept_chown = cfg.sessions.workspaceOverlay.acceptChown;
          destroy_action = cfg.sessions.workspaceOverlay.destroyAction;
        };
        workspace_shadow = {
          enabled = cfg.sessions.workspaceShadow.enable;
          base_dir = cfg.sessions.workspaceShadow.baseDir;
          diff_excludes = cfg.sessions.workspaceShadow.diffExcludes;
          accept_excludes = cfg.sessions.workspaceShadow.acceptExcludes;
          accept_chown = cfg.sessions.workspaceShadow.acceptChown;
          destroy_action = cfg.sessions.workspaceShadow.destroyAction;
        };
        detached_supervisors = {
          enable = cfg.sessions.detachedSupervisors.enable;
          roots = cfg.sessions.detachedSupervisors.roots;
          request_timeout = cfg.sessions.detachedSupervisors.requestTimeout;
        };
      };

      sandbox = {
        network = {
          enabled = cfg.sandbox.network.enable;
          proxy_listen_addr = cfg.sandbox.network.proxyListenAddr;
          ebpf = {
            enabled = cfg.sandbox.network.ebpf.enable;
            required = cfg.sandbox.network.ebpf.required;
            enforce = cfg.sandbox.network.ebpf.enforce;
          };
          transparent = {
            enabled = cfg.sandbox.network.transparent.enable;
          };
        };
        cgroups = {
          enabled = cfg.sandbox.cgroups.enable;
          base_path = cfg.sandbox.cgroups.basePath;
        };
        unix_sockets = {
          enabled = cfg.sandbox.unixSockets.enable;
          wrapper_bin = cfg.sandbox.unixSockets.wrapperBin;
        };
        seccomp = {
          execve = {
            enabled = cfg.sandbox.seccomp.execve.enable;
            approval_timeout = cfg.sandbox.seccomp.execve.approvalTimeout;
            approval_timeout_action = cfg.sandbox.seccomp.execve.approvalTimeoutAction;
          };
          file_monitor = {
            enabled = cfg.sandbox.seccomp.fileMonitor.enable;
            enforce_without_fuse = cfg.sandbox.seccomp.fileMonitor.enforceWithoutFUSE;
            intercept_metadata = cfg.sandbox.seccomp.fileMonitor.interceptMetadata;
            write_only_opens = cfg.sandbox.seccomp.fileMonitor.writeOnlyOpens;
            openat_emulation = cfg.sandbox.seccomp.fileMonitor.openatEmulation;
            block_io_uring = cfg.sandbox.seccomp.fileMonitor.blockIOUring;
          };
        };
        ptrace = {
          enabled = cfg.sandbox.ptrace.enable;
          attach_mode = cfg.sandbox.ptrace.attachMode;
          trace = {
            execve = cfg.sandbox.ptrace.trace.execve;
            file = cfg.sandbox.ptrace.trace.file;
            network = cfg.sandbox.ptrace.trace.network;
            signal = cfg.sandbox.ptrace.trace.signal;
          };
          performance = {
            seccomp_prefilter = cfg.sandbox.ptrace.performance.seccompPrefilter;
            max_tracees = cfg.sandbox.ptrace.performance.maxTracees;
            max_hold_ms = cfg.sandbox.ptrace.performance.maxHoldMs;
          };
          mask_tracer_pid = cfg.sandbox.ptrace.maskTracerPid;
          on_attach_failure = cfg.sandbox.ptrace.onAttachFailure;
        };
        composition.bubblewrap = {
          enabled = cfg.sandbox.composition.bubblewrap.enable;
          dialect = cfg.sandbox.composition.bubblewrap.dialect;
          scratch_root = cfg.sandbox.composition.bubblewrap.scratchRoot;
          max_namespace_depth = cfg.sandbox.composition.bubblewrap.maxNamespaceDepth;
          max_namespace_transitions = cfg.sandbox.composition.bubblewrap.maxNamespaceTransitions;
          max_plan_operations = cfg.sandbox.composition.bubblewrap.maxPlanOperations;
          max_synthetic_mounts = cfg.sandbox.composition.bubblewrap.maxSyntheticMounts;
          max_data_bytes = cfg.sandbox.composition.bubblewrap.maxDataBytes;
          adapter_path = cfg.sandbox.composition.bubblewrap.adapterPath;
          mount_helper_path = cfg.sandbox.composition.bubblewrap.mountHelperPath;
          device_ioctl_paths = cfg.sandbox.composition.bubblewrap.deviceIOCTLPaths;
        };
        env_inject = cfg.sandbox.envInject;
      };

      policies = {
        dir = cfg.policies.dir;
        default = cfg.policies.default;
        project_overlays = {
          enabled = cfg.policies.projectOverlays.enable;
          paths = cfg.policies.projectOverlays.paths;
          require_approval = cfg.policies.projectOverlays.requireApproval;
          on_denied = cfg.policies.projectOverlays.onDenied;
        };
      };

      proxy = {
        inherit (cfg.proxy) mode port;
      };

      approvals = {
        enabled = cfg.approvals.enable;
        mode = cfg.approvals.mode;
        timeout = cfg.approvals.timeout;
      };
    } cfg.extraConfig
  );
in
{
  options.services.agentsh = {
    enable = mkEnableOption "agentsh policy-enforced execution gateway";

    package = mkOption {
      type = types.package;
      default =
        if defaultPackage != null then
          defaultPackage
        else
          pkgs.agentsh or (throw "services.agentsh.package must be set to an agentsh package");
      defaultText = "inputs.agentsh.packages.<system>.default or pkgs.agentsh";
      description = "agentsh package to run.";
    };

    configPath = mkOption {
      type = types.str;
      default = "/etc/agentsh/config.yml";
      description = "Path where the generated agentsh config is exposed.";
    };

    server.http.addr = mkOption {
      type = types.str;
      default = "127.0.0.1:18080";
    };

    server.unixSocket = {
      enable = mkOption {
        type = types.bool;
        default = true;
      };
      path = mkOption {
        type = types.str;
        default = "/run/agentsh/agentsh.sock";
      };
    };

    auth = {
      type = mkOption {
        type = types.enum [
          "none"
          "api_key"
        ];
        default = "none";
      };
      apiKey = {
        keysFile = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Path to agentsh API keys YAML file.";
        };
        headerName = mkOption {
          type = types.str;
          default = "X-API-Key";
        };
      };
    };

    logging = {
      level = mkOption {
        type = types.str;
        default = "info";
      };
      format = mkOption {
        type = types.str;
        default = "json";
      };
      output = mkOption {
        type = types.str;
        default = "stdout";
      };
    };

    audit = {
      enable = mkOption {
        type = types.bool;
        default = true;
      };
      output = mkOption {
        type = types.str;
        default = "/var/log/agentsh/audit.jsonl";
      };
      storage.sqlitePath = mkOption {
        type = types.str;
        default = "/var/lib/agentsh/events.db";
      };
    };

    sessions = {
      baseDir = mkOption {
        type = types.str;
        default = "/var/lib/agentsh/sessions";
      };
      outputArtifacts.maxBytes = mkOption {
        type = types.ints.positive;
        default = 16 * 1024 * 1024;
        description = "Maximum bytes retained in each session-owned remote output artifact.";
      };
      subagents = {
        defaultTimeout = mkOption {
          type = types.str;
          default = "2h";
          description = "Default and maximum AgentSH-owned execution deadline for supervised child Pi processes; requests may select a shorter timeout.";
        };
        maxExecConcurrency = mkOption {
          type = types.ints.between 1 4;
          default = 1;
          description = "Aggregate cap for authenticated child exec_bash lanes. Unsupported and strict proxy/eBPF paths remain exclusive.";
        };
      };
      workspaceOverlay = {
        enable = mkOption {
          type = types.bool;
          default = false;
        };
        baseDir = mkOption {
          type = types.str;
          default = "/var/lib/agentsh/overlays";
        };
        defaultExcludes = mkOption {
          type = types.listOf types.str;
          default = [
            ".git"
            ".direnv"
          ];
        };
        acceptChown = mkOption {
          type = types.bool;
          default = true;
        };
        destroyAction = mkOption {
          type = types.enum [
            "reject"
            "keep"
          ];
          default = "reject";
        };
      };
      workspaceShadow = {
        enable = mkOption {
          type = types.bool;
          default = false;
        };
        baseDir = mkOption {
          type = types.str;
          default = "/var/lib/agentsh/workspaces";
        };
        diffExcludes = mkOption {
          type = types.listOf types.str;
          default = [
            ".git"
            ".direnv"
          ];
        };
        acceptExcludes = mkOption {
          type = types.listOf types.str;
          default = [
            ".git"
            ".direnv"
          ];
        };
        acceptChown = mkOption {
          type = types.bool;
          default = true;
        };
        destroyAction = mkOption {
          type = types.enum [
            "reject"
            "keep"
          ];
          default = "reject";
        };
      };
      detachedSupervisors = {
        enable = mkOption {
          type = types.bool;
          default = false;
          description = "Discover detached per-session supervisors and aggregate their approvals/session events through the daemon API.";
        };
        roots = mkOption {
          type = types.listOf types.str;
          default = [ ];
          description = "Detached supervisor metadata roots to discover.";
        };
        requestTimeout = mkOption {
          type = types.str;
          default = "500ms";
          description = "Per-detached-supervisor API request timeout.";
        };
      };
    };

    sandbox = {
      network = {
        enable = mkOption {
          type = types.bool;
          default = true;
        };
        proxyListenAddr = mkOption {
          type = types.str;
          default = "127.0.0.1:0";
        };
        ebpf = {
          enable = mkOption {
            type = types.bool;
            default = true;
          };
          required = mkOption {
            type = types.bool;
            default = false;
          };
          enforce = mkOption {
            type = types.bool;
            default = false;
          };
        };
        transparent.enable = mkOption {
          type = types.bool;
          default = false;
        };
      };

      cgroups = {
        enable = mkOption {
          type = types.bool;
          default = false;
        };
        basePath = mkOption {
          type = types.str;
          default = "/sys/fs/cgroup/system.slice/agentsh.service";
        };
      };

      unixSockets = {
        enable = mkOption {
          type = types.bool;
          default = true;
        };
        wrapperBin = mkOption {
          type = types.str;
          default = "${cfg.package}/bin/agentsh-unixwrap";
        };
      };

      seccomp = {
        execve = {
          enable = mkOption {
            type = types.bool;
            default = false;
          };
          approvalTimeout = mkOption {
            type = types.str;
            default = "10s";
            description = "How long seccomp execve interception waits for approval before applying approvalTimeoutAction.";
          };
          approvalTimeoutAction = mkOption {
            type = types.enum [
              "deny"
              "allow"
            ];
            default = "deny";
            description = "Action to take when seccomp execve approval times out.";
          };
        };
        fileMonitor = {
          enable = mkOption {
            type = types.bool;
            default = true;
          };
          enforceWithoutFUSE = mkOption {
            type = types.bool;
            default = true;
          };
          interceptMetadata = mkOption {
            type = types.bool;
            default = true;
          };
          writeOnlyOpens = mkOption {
            type = types.bool;
            default = false;
          };
          openatEmulation = mkOption {
            type = types.bool;
            default = true;
          };
          blockIOUring = mkOption {
            type = types.bool;
            default = true;
          };
        };
      };

      ptrace = {
        enable = mkOption {
          type = types.bool;
          default = false;
        };
        attachMode = mkOption {
          type = types.enum [
            "children"
            "pid"
          ];
          default = "children";
        };
        trace = {
          execve = mkOption {
            type = types.bool;
            default = true;
          };
          file = mkOption {
            type = types.bool;
            default = true;
          };
          network = mkOption {
            type = types.bool;
            default = true;
          };
          signal = mkOption {
            type = types.bool;
            default = true;
          };
        };
        performance = {
          seccompPrefilter = mkOption {
            type = types.bool;
            default = true;
          };
          maxTracees = mkOption {
            type = types.int;
            default = 500;
          };
          maxHoldMs = mkOption {
            type = types.int;
            default = 5000;
          };
        };
        maskTracerPid = mkOption {
          type = types.str;
          default = "off";
        };
        onAttachFailure = mkOption {
          type = types.enum [
            "fail_open"
            "fail_closed"
          ];
          default = "fail_open";
        };
      };

      composition.bubblewrap = {
        enable = mkEnableOption "the Bubblewrap 0.11.2 semantic composition ceiling";
        dialect = mkOption {
          type = types.enum [ "0.11.2" ];
          default = "0.11.2";
        };
        scratchRoot = mkOption {
          type = types.str;
          default = "/agentsh-composition-scratch";
          description = "Use 'auto' for a helper-lease-scoped runtime, or a dedicated top-level staging directory. Static roots are provisioned write/execute-only and sticky by this module; randomized per-command children remain private.";
        };
        maxNamespaceDepth = mkOption {
          type = types.ints.positive;
          default = 4;
        };
        maxNamespaceTransitions = mkOption {
          type = types.ints.positive;
          default = 32;
        };
        maxPlanOperations = mkOption {
          type = types.ints.positive;
          default = 256;
        };
        maxSyntheticMounts = mkOption {
          type = types.ints.positive;
          default = 16;
        };
        maxDataBytes = mkOption {
          type = types.ints.positive;
          default = 16 * 1024 * 1024;
        };
        adapterPath = mkOption {
          type = types.str;
          default = "${cfg.package}/bin/agentsh-bwrap-adapter";
        };
        mountHelperPath = mkOption {
          type = types.str;
          default = "${cfg.package}/bin/agentsh-composition-mount-helper";
        };
        deviceIOCTLPaths = mkOption {
          type = types.listOf types.str;
          default = [ ];
        };
      };

      envInject = mkOption {
        type = types.attrsOf types.str;
        default = {
          BASH_ENV = "${cfg.package}/lib/agentsh/bash_startup.sh";
        };
      };
    };

    policies = {
      dir = mkOption {
        type = types.str;
        default = "/etc/agentsh/policies";
      };
      source = mkOption {
        type = types.path;
        default = "${cfg.package}/share/agentsh/configs/policies";
      };
      default = mkOption {
        type = types.str;
        default = "default";
      };
      projectOverlays = {
        enable = mkEnableOption "project-local AgentSH policy overlays";
        paths = mkOption {
          type = types.listOf types.str;
          default = [ ".agentsh/policy-overlays/*.yaml" ];
        };
        requireApproval = mkOption {
          type = types.bool;
          default = true;
        };
        onDenied = mkOption {
          type = types.enum [
            "fail"
            "ignore"
          ];
          default = "fail";
        };
      };
    };

    proxy = {
      mode = mkOption {
        type = types.str;
        default = "embedded";
      };
      port = mkOption {
        type = types.int;
        default = 0;
      };
    };

    approvals = {
      enable = mkOption {
        type = types.bool;
        default = false;
      };
      mode = mkOption {
        type = types.enum [
          "local_tty"
          "api"
          "totp"
          "webauthn"
        ];
        default = "local_tty";
      };
      timeout = mkOption {
        type = types.str;
        default = "5m";
      };
    };

    nethelper = {
      enable = mkEnableOption "the root-owned per-user AgentSH network helper socket";
      instances = mkOption {
        default = { };
        description = ''
          Root helper instances keyed by a systemd-safe name. Each instance is
          bound to one explicit Unix UID and uses an operator-provided runtime
          secret. The source path is consumed with systemd credentials and must
          not be a Nix store path. Installing this helper is necessary but does
          not by itself make runtime readiness or network_policy_enforced true;
          the detached preflight must prove the command boundary and bypass
          checks on the deployed host.
        '';
        type = types.attrsOf (
          types.submodule (
            { name, ... }: {
              options = {
                user = mkOption {
                  type = types.str;
                  description = "Unix user allowed to connect to this helper instance.";
                };
                uid = mkOption {
                  type = types.int;
                  description = "Numeric Unix UID verified against SO_PEERCRED.";
                };
                credentialFile = mkOption {
                  type = types.str;
                  description = "Root-readable source file containing the helper-instance credential (for example, /run/secrets/agentsh-nethelper).";
                };
                socketPath = mkOption {
                  type = types.nullOr types.str;
                  default = null;
                  description = "Absolute helper socket path below /run/agentsh/nethelper/<uid>; defaults to nethelper.sock in that protected runtime directory.";
                };
                pinRoot = mkOption {
                  type = types.nullOr types.str;
                  default = null;
                  description = "Protected bpffs pin root at or below /sys/fs/bpf/agentsh/nethelper/<uid>.";
                };
                allowCompatSysAdmin = mkOption {
                  type = types.bool;
                  default = false;
                  description = "Add CAP_SYS_ADMIN for older kernels that cannot load the fixed programs with CAP_BPF/CAP_NET_ADMIN/CAP_PERFMON alone.";
                };
              };
            }
          )
        );
      };
    };

    service = {
      delegate = mkOption {
        type = types.str;
        default = "cpu cpuset io memory pids";
      };
      delegateSubgroup = mkOption {
        type = types.str;
        default = "control";
      };
    };

    extraConfig = mkOption {
      type = yaml.type;
      default = { };
      description = "Extra attrs merged into generated agentsh YAML config.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.auth.type != "api_key" || cfg.auth.apiKey.keysFile != null;
        message = "services.agentsh.auth.apiKey.keysFile must be set when auth.type is api_key.";
      }
      {
        assertion = !(cfg.approvals.enable && cfg.approvals.mode == "api" && cfg.auth.type == "none");
        message = "services.agentsh approvals.mode=api requires auth.type=api_key.";
      }
      {
        assertion =
          !cfg.sandbox.composition.bubblewrap.enable
          || cfg.sandbox.composition.bubblewrap.scratchRoot == "auto"
          || (
            safeAbsolutePath cfg.sandbox.composition.bubblewrap.scratchRoot
            && builtins.dirOf cfg.sandbox.composition.bubblewrap.scratchRoot == "/"
            && cfg.sandbox.composition.bubblewrap.scratchRoot != "/"
          );
        message = "services.agentsh.sandbox.composition.bubblewrap.scratchRoot must be 'auto' or a dedicated top-level directory.";
      }
      {
        assertion =
          !cfg.sandbox.composition.bubblewrap.enable
          || (
            cfg.sandbox.seccomp.fileMonitor.enable
            && cfg.sandbox.seccomp.fileMonitor.enforceWithoutFUSE
            && cfg.sandbox.seccomp.fileMonitor.interceptMetadata
            && !cfg.sandbox.seccomp.fileMonitor.writeOnlyOpens
            && cfg.sandbox.seccomp.fileMonitor.blockIOUring
          );
        message = "services.agentsh.sandbox.composition.bubblewrap requires the complete source-aware file monitor contract.";
      }
      {
        assertion = !cfg.nethelper.enable || cfg.nethelper.instances != { };
        message = "services.agentsh.nethelper.instances must contain at least one per-user helper when nethelper.enable is true.";
      }
      {
        assertion =
          !cfg.nethelper.enable
          || (
            let
              instances = lib.attrValues cfg.nethelper.instances;
              uids = map (instance: instance.uid) instances;
              users = map (instance: instance.user) instances;
              credentialFiles = map (instance: instance.credentialFile) instances;
            in
            builtins.length uids == builtins.length (lib.unique uids)
            && builtins.length users == builtins.length (lib.unique users)
            && builtins.length credentialFiles == builtins.length (lib.unique credentialFiles)
          );
        message = "services.agentsh.nethelper.instances must use unique users, numeric uids, and credential source paths.";
      }
    ]
    ++ lib.optionals cfg.nethelper.enable (
      lib.mapAttrsToList (name: instance: {
        assertion =
          builtins.match "^[A-Za-z0-9_-]+$" name != null
          && instance.uid >= 0
          && builtins.hasAttr instance.user config.users.users
          && config.users.users.${instance.user}.uid != null
          && config.users.users.${instance.user}.uid == instance.uid
          && safeAbsolutePath instance.credentialFile
          && !lib.hasPrefix builtins.storeDir instance.credentialFile
          && safeAbsolutePath (nethelperSocketPath instance)
          && lib.hasPrefix "${nethelperRuntimeDir instance}/" (nethelperSocketPath instance)
          && safeAbsolutePath (nethelperPinRoot instance)
          && (
            nethelperPinRoot instance == "/sys/fs/bpf/agentsh/nethelper/${toString instance.uid}"
            || lib.hasPrefix "/sys/fs/bpf/agentsh/nethelper/${toString instance.uid}/" (
              nethelperPinRoot instance
            )
          );
        message = "Invalid services.agentsh.nethelper.instances.${name}: use a systemd-safe key, an existing user with an explicit matching uid, a socket below the per-uid runtime directory, a pin root below the per-uid AgentSH bpffs root, and an absolute traversal-free credential path outside the Nix store.";
      }) cfg.nethelper.instances
    );

    environment.systemPackages = [ cfg.package ];

    # Both the root supervisor and client-spawned wrappers must create private
    # children here. Deny directory listing/inotify discovery while permitting
    # randomized mkdir, and use the sticky bit to protect distinct users.
    systemd.tmpfiles.rules = lib.optional (
      cfg.sandbox.composition.bubblewrap.enable
      && cfg.sandbox.composition.bubblewrap.scratchRoot != "auto"
    ) "d ${cfg.sandbox.composition.bubblewrap.scratchRoot} 1733 root root -";

    environment.etc = {
      "agentsh/config.yml".source = configFile;
      "agentsh/policies".source = cfg.policies.source;
    }
    // optionalAttrs cfg.nethelper.enable {
      "profile.d/agentsh-nethelper.sh" = {
        mode = "0644";
        text = ''
          # AgentSH detached supervisor integration. This exposes only control
          # paths; the credential value remains in the protected runtime file.
          ${nethelperProfile}
        '';
      };
    };

    systemd.services = {
      agentsh = {
        description = "Policy-enforced execution gateway for AI agents";
        wantedBy = [ "multi-user.target" ];
        restartTriggers = [ configFile ];
        after = [ "network.target" ];

        serviceConfig = {
          Type = "simple";
          ExecStart = "${lib.getExe cfg.package} server --config ${cfg.configPath}";
          Restart = "on-failure";
          RestartSec = "2s";

          User = "root";
          StateDirectory = "agentsh";
          RuntimeDirectory = "agentsh";
          LogsDirectory = "agentsh";

          Delegate = cfg.service.delegate;
          DelegateSubgroup = cfg.service.delegateSubgroup;
          IOAccounting = true;
          MemoryAccounting = true;
          TasksAccounting = true;
        };
      };
    }
    // optionalAttrs cfg.nethelper.enable (nethelperProvisionServices // nethelperServices);

    systemd.sockets = mkIf cfg.nethelper.enable nethelperSockets;

  };
}
