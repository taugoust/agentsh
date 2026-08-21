{
  pkgs,
  self,
}:
let
  inherit (pkgs) lib stdenv;
in
lib.optionalAttrs (stdenv.hostPlatform.system == "x86_64-linux") {
  lifecycle-leak-tests = pkgs.buildGoModule {
    pname = "agentsh-lifecycle-leak-tests";
    version = "unstable-2026-06-17";
    src = self;
    vendorHash = "sha256-zeKD8JIgh3rwtQVpJofd3Ug1KlZ+DNoOrA7tw/mPFrg=";

    nativeBuildInputs = [
      pkgs.diffutils
      pkgs.gnumake
      pkgs.llvmPackages.clang-unwrapped
      pkgs.pkg-config
      pkgs.rsync
    ];
    buildInputs = [
      pkgs.fuse
      pkgs.libbpf
      pkgs.libseccomp
      pkgs.linuxHeaders
    ];
    env = {
      CGO_ENABLED = "1";
      CGO_CFLAGS = "-I${pkgs.fuse.dev}/include";
      GOTELEMETRY = "off";
    };

    buildPhase = ''
      runHook preBuild
      runHook postBuild
    '';
    preCheck = ''
      make -C internal/netmonitor/ebpf clean all \
        BPF_CLANG=${pkgs.llvmPackages.clang-unwrapped}/bin/clang \
        BPF_INCLUDE="-I${pkgs.libbpf}/include -I${pkgs.linuxHeaders}/include"
    '';
    checkPhase = ''
      runHook preCheck
      mkdir -p "$TMPDIR/go-tmp" "$TMPDIR/home" "$TMPDIR/test-bin"
      export GOTMPDIR="$TMPDIR/go-tmp"
      export HOME="$TMPDIR/home"
      export AGENTSH_LEAKCHECK=1
      go build -o "$TMPDIR/test-bin/agentsh-unixwrap" ./cmd/agentsh-unixwrap
      export PATH="$TMPDIR/test-bin:$PATH"
      go test -count=3 -shuffle=1700000001 -p 1 -timeout=20m \
        ./internal/approvals \
        ./internal/detached \
        ./internal/detachedtransport \
        ./internal/nethelper \
        ./internal/proxy \
        ./internal/runtimeprovider \
        ./internal/session \
        ./internal/testutil/leakcheck \
        ./internal/workspace/shadow
      runHook postCheck
    '';
    installPhase = ''
      runHook preInstall
      mkdir -p "$out"
      touch "$out/passed"
      runHook postInstall
    '';
  };
}
