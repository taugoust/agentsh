{
  pkgs,
  self,
}:
let
  system = pkgs.stdenv.hostPlatform.system;
  agentsh = self.packages.${system}.default;
in
pkgs.testers.runNixOSTest {
  name = "agentsh-detached-supervisor-systemd-expiry";

  nodes.machine =
    { pkgs, ... }:
    {
      system.stateVersion = "25.11";
      virtualisation.memorySize = 1536;
      virtualisation.cores = 2;

      users.users.alice = {
        isNormalUser = true;
        uid = 1000;
        home = "/home/alice";
        createHome = true;
      };

      environment.systemPackages = [
        agentsh
        pkgs.coreutils
        pkgs.jq
        pkgs.util-linux
      ];

      environment.etc."agentsh/config.yaml".text = ''
        server:
          http:
            addr: "127.0.0.1:0"
        auth:
          type: "none"
        logging:
          level: "info"
          format: "text"
          output: "stderr"
        audit:
          enabled: true
          storage:
            sqlite_path: "/home/alice/.local/state/agentsh/events.db"
        sessions:
          base_dir: "/home/alice/.local/share/agentsh/sessions"
          default_idle_timeout: "2s"
          cleanup_interval: "250ms"
        sandbox:
          enabled: false
          fuse:
            enabled: false
          network:
            enabled: false
          unix_sockets:
            enabled: false
          seccomp:
            enabled: false
        policies:
          dir: "/etc/agentsh/policies"
          default: "expiry-test"
        approvals:
          enabled: false
        metrics:
          enabled: false
      '';
      environment.etc."agentsh/policies/expiry-test.yaml".text = ''
        version: 1
        name: expiry-test
        command_rules:
          - name: allow-all-commands
            commands: ["*"]
            decision: allow
        file_rules:
          - name: allow-all-files
            paths: ["/**"]
            operations: ["*"]
            decision: allow
        network_rules:
          - name: allow-all-network
            domains: ["*"]
            decision: allow
        audit:
          log_allowed: true
          log_denied: true
          log_approved: true
      '';
    };

  testScript =
    let
      agentshExe = "${agentsh}/bin/agentsh";
      bashExe = "${pkgs.bash}/bin/bash";
    in
    ''
      import json
      import shlex
      import time

      machine.start()
      machine.wait_for_unit("multi-user.target")
      machine.succeed("loginctl enable-linger alice")
      machine.succeed("systemctl start user@1000.service")
      machine.wait_until_succeeds("test -S /run/user/1000/bus")
      machine.succeed("install -d -m 700 -o alice -g users /home/alice/.local/state/agentsh /home/alice/.local/share/agentsh /home/alice/work")
      machine.succeed("printf 'original\\n' >/home/alice/work/original.txt && chown -R alice:users /home/alice/work")

      def alice(command):
          environment = (
              "HOME=/home/alice USER=alice LOGNAME=alice "
              "XDG_RUNTIME_DIR=/run/user/1000 "
              "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus "
              "AGENTSH_CONFIG=/etc/agentsh/config.yaml "
              "AGENTSH_DETACHED_SUPERVISOR_SYSTEMD_RUN=1"
          )
          return "runuser -u alice -- env " + environment + " ${bashExe} -c " + shlex.quote(command)

      session_id = "session-11111111-1111-4111-8111-111111111111"
      started = json.loads(machine.succeed(alice(
          "cd /home/alice/work && ${agentshExe} session start --detach "
          "--session-id " + shlex.quote(session_id) + " "
          "--workspace /home/alice/work --workspace-mode shadow --policy expiry-test --json"
      )))
      assert started["session_id"] == session_id, started
      state_dir = started["state_dir"]
      socket_path = started["supervisor_sock"]
      unit = started["systemd_unit"]
      worktree = started["worktree"]
      owner_pid = int(started["owner_pid"])
      assert unit == "agentsh-supervisor-" + session_id + ".service", started
      machine.succeed(alice("systemctl --user is-active " + shlex.quote(unit)))
      machine.succeed("test -S " + shlex.quote(socket_path))

      # Preserve reviewable shadow work while the active control session expires.
      machine.succeed("printf 'retained-after-expiry\\n' >" + shlex.quote(worktree + "/retained.txt"))
      machine.succeed("test ! -e /home/alice/work/retained.txt")

      machine.wait_until_fails(alice("systemctl --user is-active " + shlex.quote(unit)))
      machine.wait_until_succeeds(
          "jq -e '.state == \"stopped\"' " + shlex.quote(state_dir + "/recovery.json") +
          " && jq -e '.state == \"stopped\" and .event_token == null' " + shlex.quote(state_dir + "/metadata.json"),
          timeout=30,
      )
      machine.wait_until_fails("kill -0 " + str(owner_pid))
      machine.wait_until_fails("test -S " + shlex.quote(socket_path))
      machine.wait_until_fails("test -e " + shlex.quote(state_dir + "/heartbeat.json"))
      machine.wait_until_succeeds(
          alice("test \"$(systemctl --user show --property=LoadState --value " + shlex.quote(unit) + ")\" = not-found"),
          timeout=30,
      )

      machine.succeed("test -f " + shlex.quote(worktree + "/retained.txt"))
      machine.succeed("grep -qx retained-after-expiry " + shlex.quote(worktree + "/retained.txt"))
      machine.succeed("test ! -e /home/alice/work/retained.txt")
      machine.succeed(
          "jq -e --arg sid " + shlex.quote(session_id) +
          " 'select(.type == \"session_expired\" and .session_id == $sid and .fields.expired_by == \"idle_timeout\")' " +
          shlex.quote(state_dir + "/events.jsonl") + " >/dev/null"
      )

      # Exact stop remains idempotent after --collect has removed the unit.
      machine.succeed(alice("${agentshExe} session stop " + shlex.quote(session_id)))
      machine.succeed("jq -e '.state == \"stopped\"' " + shlex.quote(state_dir + "/recovery.json"))
      time.sleep(2)
      machine.fail(alice("systemctl --user is-active " + shlex.quote(unit)))
      machine.fail("kill -0 " + str(owner_pid))

      # A generic API destroy must also terminate its one-session supervisor;
      # lifecycle ownership cannot depend on callers knowing the systemd unit.
      destroyed_id = "session-22222222-2222-4222-8222-222222222222"
      destroyed = json.loads(machine.succeed(alice(
          "cd /home/alice/work && ${agentshExe} session start --detach "
          "--session-id " + shlex.quote(destroyed_id) + " "
          "--workspace /home/alice/work --workspace-mode shadow --policy expiry-test --json"
      )))
      destroyed_unit = destroyed["systemd_unit"]
      destroyed_socket = destroyed["supervisor_sock"]
      destroyed_state = destroyed["state_dir"]
      destroyed_pid = int(destroyed["owner_pid"])
      machine.succeed(alice(
          "${agentshExe} --server unix://" + shlex.quote(destroyed_socket) +
          " session destroy " + shlex.quote(destroyed_id)
      ))
      machine.wait_until_fails(alice("systemctl --user is-active " + shlex.quote(destroyed_unit)))
      machine.wait_until_fails("kill -0 " + str(destroyed_pid))
      machine.wait_until_fails("test -S " + shlex.quote(destroyed_socket))
      machine.wait_until_succeeds(
          "jq -e '.state == \"stopped\"' " + shlex.quote(destroyed_state + "/recovery.json") +
          " && jq -e '.state == \"stopped\" and .event_token == null' " + shlex.quote(destroyed_state + "/metadata.json"),
          timeout=30,
      )
      time.sleep(2)
      machine.fail(alice("systemctl --user is-active " + shlex.quote(destroyed_unit)))
    '';
}
