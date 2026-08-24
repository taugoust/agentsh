{
  pkgs,
  self,
}:
let
  inherit (pkgs) lib stdenv;
in
lib.optionalAttrs (stdenv.hostPlatform.system == "x86_64-linux") {
  concurrency-race-tests = pkgs.buildGoModule {
    pname = "agentsh-concurrency-race-tests";
    version = "unstable-2026-06-17";
    src = self;
    vendorHash = "sha256-D5LujqOssPZWviaDRqgeZOQLXBAUkL5Kj5FvxpL5kvQ=";

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
      go build -o "$TMPDIR/test-bin/agentsh-unixwrap" ./cmd/agentsh-unixwrap
      export PATH="$TMPDIR/test-bin:$PATH"
      go test -race -count=1 -p 1 -timeout=20m \
        ./internal/approvals \
        ./internal/api \
        ./internal/detached \
        ./internal/detachedtransport \
        ./internal/events \
        ./internal/nethelper \
        ./internal/netmonitor \
        ./internal/proxy \
        ./internal/runtimeprovider/... \
        ./internal/session \
        ./internal/store/composite \
        ./internal/store/jsonl \
        ./internal/store/sqlite \
        ./internal/store/watchtower \
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
