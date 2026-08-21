{
  pkgs,
  self,
}:
let
  inherit (pkgs) lib stdenv;
in
lib.optionalAttrs (stdenv.hostPlatform.system == "x86_64-linux") {
  go-coverage-baseline = pkgs.buildGoModule {
    pname = "agentsh-go-coverage-baseline";
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
      go test -count=1 -p 2 -covermode=atomic -coverprofile="$TMPDIR/coverage.out" ./...
      go tool cover -func="$TMPDIR/coverage.out" > "$TMPDIR/coverage-functions.txt"
      awk '/^total:/ { print $3 }' "$TMPDIR/coverage-functions.txt" > "$TMPDIR/coverage-total.txt"
      test -s "$TMPDIR/coverage.out"
      test -s "$TMPDIR/coverage-total.txt"
      runHook postCheck
    '';
    installPhase = ''
      runHook preInstall
      mkdir -p "$out"
      cp "$TMPDIR/coverage.out" "$out/coverage.out"
      cp "$TMPDIR/coverage-functions.txt" "$out/functions.txt"
      cp "$TMPDIR/coverage-total.txt" "$out/total.txt"
      runHook postInstall
    '';
  };
}
