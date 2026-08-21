{
  pkgs,
  self,
}:
let
  testArtifacts = pkgs.buildGoModule {
    pname = "agentsh-unfiltered-seccomp-test-artifacts";
    version = "unstable-2026-08-20";
    src = self;
    vendorHash = "sha256-zeKD8JIgh3rwtQVpJofd3Ug1KlZ+DNoOrA7tw/mPFrg=";

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
    buildPhase = ''
      runHook preBuild
      go test -c -o api.test ./internal/api
      go test -c -o kernelinstall.test ./internal/shim/kernelinstall
      go build -tags shimtest -o agentsh-shell-shim-test ./cmd/agentsh-shell-shim
      go build -o agentsh-unixwrap-test ./cmd/agentsh-unixwrap
      runHook postBuild
    '';
    installPhase = ''
      mkdir -p "$out/bin"
      install -m755 api.test kernelinstall.test agentsh-shell-shim-test agentsh-unixwrap-test "$out/bin/"
    '';
    doCheck = false;
  };
in
pkgs.testers.runNixOSTest {
  name = "agentsh-unfiltered-seccomp-tests";

  nodes.machine =
    { ... }:
    {
      environment.systemPackages = [
        pkgs.bash
        pkgs.coreutils
        testArtifacts
      ];
      virtualisation = {
        memorySize = 3072;
        cores = 2;
      };
      system.stateVersion = "25.11";
    };

  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("test $(awk '/^Seccomp_filters:/ { print $2 }' /proc/self/status) -eq 0")
    kernel_output = machine.succeed(
      "${testArtifacts}/bin/kernelinstall.test -test.v -test.timeout=2m "
      "-test.run='^TestInstall_ModeOn_(WrapInitError|EmptyResponse)_FailsClosed$'"
    )
    assert "--- SKIP" not in kernel_output, kernel_output
    api_output = machine.succeed(
      "AGENTSH_TEST_SHIM_BINARY=${testArtifacts}/bin/agentsh-shell-shim-test "
      "AGENTSH_TEST_WRAP_BINARY=${testArtifacts}/bin/agentsh-unixwrap-test "
      "${testArtifacts}/bin/api.test -test.v -test.timeout=2m -test.run='^TestShimInstall_(SiblingProcessTree|NestedInstallsCompose)$'"
    )
    assert "--- SKIP" not in api_output, api_output
  '';
}
