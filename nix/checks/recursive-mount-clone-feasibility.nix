{
  pkgs,
  self,
}:
let
  probe = pkgs.stdenv.mkDerivation {
    pname = "agentsh-recursive-mount-clone-probe";
    version = "unstable-2026-07-20";
    src = self;
    strictDeps = true;
    dontConfigure = true;
    buildPhase = ''
      runHook preBuild
      $CC -std=c11 -O2 -Wall -Wextra -Werror \
        nix/checks/fixtures/recursive-mount-clone-probe/main.c \
        -o recursive-mount-clone-probe
      runHook postBuild
    '';
    installPhase = ''
      runHook preInstall
      install -D -m 0755 recursive-mount-clone-probe \
        "$out/bin/recursive-mount-clone-probe"
      runHook postInstall
    '';
  };
  unshare = "${pkgs.util-linux}/bin/unshare";
  shell = "${pkgs.bash}/bin/bash";
  binary = "${probe}/bin/recursive-mount-clone-probe";
in
pkgs.testers.runNixOSTest {
  name = "agentsh-recursive-mount-clone-feasibility";

  nodes.machine = {
    security.unprivilegedUsernsClone = true;
    boot.kernel.sysctl."user.max_user_namespaces" = 1024;
    users.users.tester = {
      isNormalUser = true;
      uid = 1000;
    };
    virtualisation = {
      memorySize = 1024;
      cores = 2;
    };
    system.stateVersion = "25.11";
  };

  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.succeed(
      "install -d -o tester -g users -m 0755 "
      "/run/recursive-clone/direct-baseline "
      "/run/recursive-clone/direct-union "
      "/run/recursive-clone/nested-baseline "
      "/run/recursive-clone/nested-union "
      "/run/recursive-clone/double-union"
    )

    direct_baseline = machine.succeed(
      "${binary} baseline /nix /nix/store /run/recursive-clone/direct-baseline"
    )
    direct_union = machine.succeed(
      "${binary} union /nix /nix/store /run/recursive-clone/direct-union"
    )
    nested_baseline = machine.succeed(
      "runuser -u tester -- ${unshare} --user --map-root-user --mount --fork "
      "${binary} baseline /nix /nix/store /run/recursive-clone/nested-baseline"
    )
    nested_union = machine.succeed(
      "runuser -u tester -- ${unshare} --user --map-root-user --mount --fork "
      "${binary} union /nix /nix/store /run/recursive-clone/nested-union"
    )
    double_union = machine.succeed(
      "runuser -u tester -- ${unshare} --user --map-root-user --mount --fork "
      "${shell} -c 'exec ${unshare} --user --map-root-user --mount --fork "
      "${binary} union /nix /nix/store /run/recursive-clone/double-union'"
    )

    machine.log("direct baseline: " + direct_baseline.strip())
    machine.log("direct union: " + direct_union.strip())
    machine.log("nested baseline: " + nested_baseline.strip())
    machine.log("nested union: " + nested_union.strip())
    machine.log("double nested union: " + double_union.strip())
    assert "preserved=true" in direct_baseline, direct_baseline
    assert "readonly=true" in direct_baseline, direct_baseline
    assert "preserved=true" in nested_baseline, nested_baseline
    assert "readonly=true" in nested_baseline, nested_baseline
    assert "preserved=true" in direct_union, direct_union
    assert "readonly=true" in direct_union, direct_union
    assert "preserved=true" in nested_union, nested_union
    assert "readonly=true" in nested_union, nested_union
    assert "preserved=true" in double_union, double_union
    assert "readonly=true" in double_union, double_union
  '';
}
