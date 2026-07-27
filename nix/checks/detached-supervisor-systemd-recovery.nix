{
  pkgs,
  self,
}:
let
  system = pkgs.stdenv.hostPlatform.system;
  agentsh = self.packages.${system}.default;
in
pkgs.testers.runNixOSTest {
  name = "agentsh-detached-supervisor-systemd-recovery";

  nodes.machine =
    { pkgs, ... }:
    {
      system.stateVersion = "25.11";
      virtualisation.memorySize = 2048;
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
        pkgs.curl
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
          default: "recovery-test"
        approvals:
          enabled: false
        metrics:
          enabled: false
      '';
      environment.etc."agentsh/policies/recovery-test.yaml".text = ''
        version: 1
        name: recovery-test
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
      curlExe = "${pkgs.curl}/bin/curl";
    in
    ''
      import json
      import shlex

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

      start_raw = machine.succeed(alice(
          "cd /home/alice/work && ${agentshExe} session start --detach "
          "--workspace /home/alice/work --workspace-mode shadow --policy recovery-test --json"
      ))
      started = json.loads(start_raw)
      session_id = started["session_id"]
      state_dir = started["state_dir"]
      socket_path = started["supervisor_sock"]
      unit = started["systemd_unit"]
      worktree = started["worktree"]
      first_generation = int(started["generation"])
      first_incarnation = started["incarnation_id"]
      first_created_at = started["created_at"]

      assert first_generation == 1, started
      assert unit.startswith("agentsh-supervisor-"), started
      assert worktree != "/home/alice/work", started
      machine.succeed(alice("systemctl --user is-active " + shlex.quote(unit)))
      assert machine.succeed(alice("systemctl --user show -p Restart --value " + shlex.quote(unit))).strip() == "on-failure"
      assert machine.succeed(alice("systemctl --user show -p OOMPolicy --value " + shlex.quote(unit))).strip() == "continue"

      def api(method, path, body=None):
          command = (
              "${curlExe} --fail-with-body --silent --show-error "
              "--unix-socket " + shlex.quote(socket_path) + " -X " + method +
              " http://localhost" + path
          )
          if body is not None:
              command += " -H 'Content-Type: application/json' --data-binary " + shlex.quote(json.dumps(body))
          return json.loads(machine.succeed(alice(command)))

      session_path = "/api/v1/sessions/" + session_id
      write_result = api("POST", session_path + "/tools/write_file", {
          "path": "/workspace/retained.txt",
          "content": "retained-before-crash\\n",
          "create_dirs": True,
          "actor": {"kind": "extension", "label": "systemd recovery VM"},
      })
      assert write_result.get("ok") is True, write_result

      artifact_result = api("POST", session_path + "/tools/exec_bash", {
          "command": "printf 'durable-artifact-output\\n'",
          "cwd": "/workspace",
          "persist_output_over_bytes": 1,
          "actor": {"kind": "extension", "label": "systemd recovery VM"},
      })
      assert artifact_result.get("ok") is True, artifact_result
      machine.succeed("jq -e '.output_artifacts | length >= 1' " + shlex.quote(state_dir + "/recovery.json"))
      artifact_path = machine.succeed("jq -r '.output_artifacts[0]' " + shlex.quote(state_dir + "/recovery.json")).strip()
      machine.succeed("test -s " + shlex.quote(artifact_path))

      api("PATCH", session_path, {"cwd": "/workspace"})
      manifest_created_at = machine.succeed("jq -r .session_created_at " + shlex.quote(state_dir + "/recovery.json")).strip()

      long_body = json.dumps({
          "command": "/bin/sh",
          "args": ["-c", "echo started > child.started; exec sleep 300"],
          "working_dir": worktree,
          "timeout": "10m",
          "include_events": "none",
      })
      long_curl = (
          "${curlExe} --silent --show-error --unix-socket " + shlex.quote(socket_path) +
          " -X POST http://localhost" + session_path + "/exec "
          "-H 'Content-Type: application/json' --data-binary " + shlex.quote(long_body)
      )
      machine.succeed(
          "systemd-run --quiet --unit=agentsh-recovery-vm-client "
          "--property=User=alice --property=Group=users "
          "--property=Environment=HOME=/home/alice "
          "--property=Environment=XDG_RUNTIME_DIR=/run/user/1000 "
          "${bashExe} -c " + shlex.quote(long_curl)
      )
      child_started_path = worktree + "/child.started"
      machine.wait_until_succeeds("test -s " + shlex.quote(child_started_path))
      child_pid = int(machine.succeed("pgrep -u alice -x sleep").strip())
      machine.succeed("kill -0 " + str(child_pid))

      first_owner_pid = int(machine.succeed("jq -r .owner_pid " + shlex.quote(state_dir + "/metadata.json")).strip())
      machine.succeed(alice("systemctl --user kill --kill-whom=main --signal=KILL " + shlex.quote(unit)))

      machine.wait_until_succeeds(
          "jq -e --arg sid " + shlex.quote(session_id) +
          " '.session_id == $sid and .state == \"ready\" and .generation >= 2 and (.incarnation_id | length) > 0' " +
          shlex.quote(state_dir + "/metadata.json")
      )
      machine.wait_until_succeeds(alice("systemctl --user is-active " + shlex.quote(unit)))
      machine.wait_until_fails("kill -0 " + str(child_pid))

      recovered = json.loads(machine.succeed("cat " + shlex.quote(state_dir + "/metadata.json")))
      assert recovered["session_id"] == session_id, recovered
      assert int(recovered["generation"]) > first_generation, recovered
      assert recovered["incarnation_id"] != first_incarnation, recovered
      assert int(recovered["owner_pid"]) != first_owner_pid, recovered
      assert recovered["created_at"] == first_created_at, recovered

      status = api("GET", "/api/v1/detached/status")
      assert status["session_id"] == session_id, status
      assert int(status["generation"]) == int(recovered["generation"]), status
      assert status["incarnation_id"] == recovered["incarnation_id"], status
      assert status["lifecycle_state"] == "ready", status

      exact_session = api("GET", session_path)
      assert exact_session.get("id") == session_id, exact_session
      retained = api("POST", session_path + "/tools/read_file", {
          "path": "/workspace/retained.txt",
          "max_bytes": 4096,
          "actor": {"kind": "extension", "label": "systemd recovery VM"},
      })
      assert retained.get("ok") is True and "retained-before-crash" in json.dumps(retained), retained
      after = api("POST", session_path + "/tools/write_file", {
          "path": "/workspace/after-recovery.txt",
          "content": "same-session-after-recovery\\n",
          "create_dirs": True,
          "actor": {"kind": "extension", "label": "systemd recovery VM"},
      })
      assert after.get("ok") is True, after

      manifest = json.loads(machine.succeed("cat " + shlex.quote(state_dir + "/recovery.json")))
      assert manifest["session_id"] == session_id, manifest
      assert manifest["session_created_at"] == manifest_created_at, manifest
      assert len(manifest.get("interrupted", [])) >= 1, manifest
      assert manifest.get("inflight", []) == [], manifest
      assert artifact_path in manifest.get("output_artifacts", []), manifest
      machine.succeed("test -s " + shlex.quote(artifact_path))
      machine.succeed("test -f " + shlex.quote(worktree + "/retained.txt"))
      machine.succeed("test -f " + shlex.quote(worktree + "/after-recovery.txt"))
      machine.succeed("test ! -e /home/alice/work/retained.txt")
      machine.succeed("test ! -e /home/alice/work/after-recovery.txt")

      # Also exercise the explicit exact-recovery command without systemd's
      # automatic restart path. It must reopen the retained shadow and advance
      # the same durable identity rather than creating a replacement session.
      machine.succeed(alice("${agentshExe} session stop " + shlex.quote(session_id)))
      machine.succeed("install -d -m 700 -o alice -g users /home/alice/direct-work")
      direct_raw = machine.succeed(alice(
          "cd /home/alice/direct-work && AGENTSH_DETACHED_SUPERVISOR_SYSTEMD_RUN=0 "
          "${agentshExe} session start --detach --workspace /home/alice/direct-work "
          "--workspace-mode shadow --policy recovery-test --json"
      ))
      direct = json.loads(direct_raw)
      direct_session_id = direct["session_id"]
      assert not direct.get("systemd_unit"), direct
      socket_path = direct["supervisor_sock"]
      session_path = "/api/v1/sessions/" + direct_session_id
      direct_worktree = direct["worktree"]
      direct_state_dir = direct["state_dir"]
      direct_incarnation = direct["incarnation_id"]
      direct_write = api("POST", session_path + "/tools/write_file", {
          "path": "/workspace/explicit-recovery.txt",
          "content": "retained-for-explicit-recovery\\n",
          "create_dirs": True,
          "actor": {"kind": "extension", "label": "explicit recovery VM"},
      })
      assert direct_write.get("ok") is True, direct_write
      direct_long_body = json.dumps({
          "command": "/bin/sh",
          "args": ["-c", "echo started > explicit-child.started; sleep 300 & wait"],
          "working_dir": direct_worktree,
          "timeout": "10m",
          "include_events": "none",
      })
      direct_long_curl = (
          "${curlExe} --silent --show-error --unix-socket " + shlex.quote(socket_path) +
          " -X POST http://localhost" + session_path + "/exec "
          "-H 'Content-Type: application/json' --data-binary " + shlex.quote(direct_long_body)
      )
      machine.succeed(
          "systemd-run --quiet --unit=agentsh-explicit-recovery-vm-client "
          "--property=User=alice --property=Group=users "
          "--property=Environment=HOME=/home/alice "
          "${bashExe} -c " + shlex.quote(direct_long_curl)
      )
      machine.wait_until_succeeds("test -s " + shlex.quote(direct_worktree + "/explicit-child.started"))
      direct_child_pid = int(machine.succeed("pgrep -u alice -x sleep").strip())
      machine.wait_until_succeeds("jq -e '.inflight | any(.external_process == true and .pid > 0 and .process_group_id == .pid)' " + shlex.quote(direct_state_dir + "/recovery.json"))
      direct_owner = int(machine.succeed("jq -r .owner_pid " + shlex.quote(direct_state_dir + "/metadata.json")).strip())
      machine.succeed("kill -KILL " + str(direct_owner))
      machine.wait_until_fails("kill -0 " + str(direct_owner))
      recovered_raw = machine.succeed(alice(
          "AGENTSH_DETACHED_SUPERVISOR_SYSTEMD_RUN=0 ${agentshExe} session recover " +
          shlex.quote(direct_session_id) + " --json"
      ))
      explicitly_recovered = json.loads(recovered_raw)
      assert explicitly_recovered["session_id"] == direct_session_id, explicitly_recovered
      assert int(explicitly_recovered["generation"]) == 2, explicitly_recovered
      assert explicitly_recovered["incarnation_id"] != direct_incarnation, explicitly_recovered
      machine.wait_until_fails("kill -0 " + str(direct_child_pid))
      direct_manifest = json.loads(machine.succeed("cat " + shlex.quote(direct_state_dir + "/recovery.json")))
      assert direct_manifest.get("inflight", []) == [] and len(direct_manifest.get("interrupted", [])) >= 1, direct_manifest
      direct_read = api("POST", session_path + "/tools/read_file", {
          "path": "/workspace/explicit-recovery.txt",
          "max_bytes": 4096,
          "actor": {"kind": "extension", "label": "explicit recovery VM"},
      })
      assert direct_read.get("ok") is True and "retained-for-explicit-recovery" in json.dumps(direct_read), direct_read
      assert json.loads(machine.succeed("cat " + shlex.quote(direct_state_dir + "/recovery.json")))["session_id"] == direct_session_id
      machine.succeed("test -f " + shlex.quote(direct_worktree + "/explicit-recovery.txt"))
      machine.succeed("test ! -e /home/alice/direct-work/explicit-recovery.txt")
    '';
}
