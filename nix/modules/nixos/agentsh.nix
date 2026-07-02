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
    mkEnableOption
    mkIf
    mkOption
    optionalAttrs
    types
    ;

  yaml = pkgs.formats.yaml { };

  configFile = yaml.generate "agentsh-config.yml" (
    {
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
          execve.enabled = cfg.sandbox.seccomp.execve.enable;
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
    }
    // cfg.extraConfig
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
        execve.enable = mkOption {
          type = types.bool;
          default = false;
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
    ];

    environment.systemPackages = [ cfg.package ];

    environment.etc = {
      "agentsh/config.yml".source = configFile;
      "agentsh/policies".source = cfg.policies.source;
    };

    systemd.services.agentsh = {
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
  };
}
