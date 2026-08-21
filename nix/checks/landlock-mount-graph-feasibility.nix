{
  pkgs,
  self,
}:
let
  probe = pkgs.stdenv.mkDerivation {
    pname = "agentsh-landlock-mount-graph-probe";
    version = "unstable-2026-07-20";
    src = self;
    strictDeps = true;
    dontConfigure = true;
    buildPhase = ''
      runHook preBuild
      $CC -std=gnu11 -O2 -Wall -Wextra -Werror \
        nix/checks/fixtures/landlock-mount-graph-probe/main.c \
        -o landlock-mount-graph-probe
      runHook postBuild
    '';
    installPhase = ''
      runHook preInstall
      install -D -m 0755 landlock-mount-graph-probe \
        "$out/bin/landlock-mount-graph-probe"
      runHook postInstall
    '';
  };
in
pkgs.testers.runNixOSTest {
  name = "agentsh-landlock-mount-graph-feasibility";

  nodes.machine = _: {
    security.unprivilegedUsernsClone = true;
    boot.kernel.sysctl."user.max_user_namespaces" = 1024;
    users.users.tester = {
      isNormalUser = true;
      uid = 1000;
    };
    environment.systemPackages = [ probe ];
    virtualisation = {
      memorySize = 1536;
      cores = 2;
    };
    system.stateVersion = "25.11";
  };

  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")

    scenarios = [
        "identity",
        "nonidentity",
        "descendant",
        "destination-hazard",
        "mask-preservation",
        "samepath-restore",
        "synthetic-pool",
        "ioctl-deny",
        "ioctl-allow",
    ]
    for scenario in scenarios:
        with subtest(f"Landlock mount graph: {scenario}"):
            output = machine.succeed(
                "runuser -u tester -- ${probe}/bin/landlock-mount-graph-probe "
                + scenario
                + " 2>&1"
            )
            assert f"scenario={scenario} result=pass" in output, output
  '';
}
