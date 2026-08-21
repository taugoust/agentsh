{
  go-vulndb,
  pkgs,
  self,
}:
let
  inherit (pkgs) lib stdenv;
  version = "unstable-2026-06-17";
  vendorHash = "sha256-D5LujqOssPZWviaDRqgeZOQLXBAUkL5Kj5FvxpL5kvQ=";

  linuxNativeBuildInputs = lib.optionals stdenv.hostPlatform.isLinux [
    pkgs.gnumake
    pkgs.llvmPackages.clang-unwrapped
    pkgs.pkg-config
  ];
  linuxBuildInputs = lib.optionals stdenv.hostPlatform.isLinux [
    pkgs.fuse
    pkgs.libbpf
    pkgs.libseccomp
    pkgs.linuxHeaders
  ];
  analysisEnvironment = {
    CGO_ENABLED = if stdenv.hostPlatform.isLinux then "1" else "0";
    CGO_CFLAGS = lib.optionalString stdenv.hostPlatform.isLinux "-I${pkgs.fuse.dev}/include";
    GOTELEMETRY = "off";
  };
  prepareEBPF = lib.optionalString stdenv.hostPlatform.isLinux ''
    make -C internal/netmonitor/ebpf clean all \
      BPF_CLANG=${pkgs.llvmPackages.clang-unwrapped}/bin/clang \
      BPF_INCLUDE="-I${pkgs.libbpf}/include -I${pkgs.linuxHeaders}/include"
  '';
  emptyBuildPhase = ''
    runHook preBuild
    runHook postBuild
  '';
  passedInstallPhase = ''
    runHook preInstall
    mkdir -p "$out"
    touch "$out/passed"
    runHook postInstall
  '';

  vulnerabilityDatabaseTools = pkgs.buildGoModule {
    pname = "go-vulnerability-database-tools";
    version = "unstable";
    src = go-vulndb;
    vendorHash = "sha256-Lvd93Wjw3hpgy5ZwPqy9Ok6gIOgj425L6Qk1/pHwbVs=";
    subPackages = [ "cmd/indexdb" ];
    doCheck = false;
  };

  vulnerabilityDatabase =
    pkgs.runCommand "go-vulnerability-database"
      {
        nativeBuildInputs = [ vulnerabilityDatabaseTools ];
      }
      ''
        indexdb -vulns ${go-vulndb}/data/osv -out "$out"
      '';
in
{
  go-lint = pkgs.buildGoModule {
    pname = "agentsh-go-lint";
    inherit version vendorHash;
    src = self;
    nativeBuildInputs = [ pkgs.golangci-lint ] ++ linuxNativeBuildInputs;
    buildInputs = linuxBuildInputs;
    env = analysisEnvironment;
    buildPhase = emptyBuildPhase;
    preCheck = prepareEBPF;
    checkPhase = ''
      runHook preCheck
      export GOLANGCI_LINT_CACHE="$TMPDIR/golangci-cache"
      golangci-lint run ./...
      runHook postCheck
    '';
    installPhase = passedInstallPhase;
  };

  go-vulnerability-scan = pkgs.buildGoModule {
    pname = "agentsh-go-vulnerability-scan";
    inherit version vendorHash;
    src = self;
    nativeBuildInputs = [
      pkgs.govulncheck
      pkgs.jq
    ]
    ++ linuxNativeBuildInputs;
    buildInputs = linuxBuildInputs;
    env = analysisEnvironment;
    buildPhase = emptyBuildPhase;
    preCheck = prepareEBPF;
    checkPhase = ''
      runHook preCheck
      set +e
      govulncheck -format=json -mode=source -scan=symbol -db file://${vulnerabilityDatabase} ./... > "$TMPDIR/govuln.json"
      status=$?
      set -e
      if [ "$status" -ne 0 ] && [ "$status" -ne 3 ]; then
        cat "$TMPDIR/govuln.json"
        exit "$status"
      fi

      grep -Ev '^[[:space:]]*(#|$)' ${./govulncheck-stdlib-allowlist.txt} | sort -u > "$TMPDIR/allowed"
      jq -rs '[.[] | .finding? // empty | select(.trace[0].function != null) | .osv] | unique[]' "$TMPDIR/govuln.json" | sort -u > "$TMPDIR/found"
      jq -rs '
        [ .[] | .finding? // empty
          | select(.trace[0].function != null and .trace[0].module != "stdlib")
          | .osv ] | unique[]
      ' "$TMPDIR/govuln.json" | sort -u > "$TMPDIR/non-stdlib"

      if [ -s "$TMPDIR/non-stdlib" ]; then
        echo "reachable third-party vulnerabilities:" >&2
        cat "$TMPDIR/non-stdlib" >&2
        cat "$TMPDIR/govuln.json"
        exit 1
      fi
      if ! diff -u "$TMPDIR/allowed" "$TMPDIR/found"; then
        echo "reachable standard-library vulnerability baseline changed; update the pinned Go toolchain or review the narrow allowlist" >&2
        exit 1
      fi
      runHook postCheck
    '';
    installPhase = passedInstallPhase;
  };
}
