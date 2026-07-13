{
  description = "AgentSH - policy-enforced execution gateway for AI agents";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f (import nixpkgs { inherit system; }));
    in
    {
      packages = forAllSystems (
        pkgs:
        let
          inherit (pkgs) lib stdenv;
          rev = self.shortRev or self.dirtyShortRev or "unknown";
          version = "unstable-2026-06-17";
          runtimePath = lib.makeBinPath (
            lib.optionals stdenv.hostPlatform.isLinux [
              pkgs.coreutils
              pkgs.diffutils
              pkgs.fuse3
              pkgs.iproute2
              pkgs.iptables
              pkgs.rsync
              pkgs.util-linux
            ]
          );

          agentsh = pkgs.buildGoModule {
            pname = "agentsh";
            inherit version;

            src = self;
            vendorHash = "sha256-SnrqSrkgeH/jOiLV71h3a2q9OZj5ISru042kVjhrGRE=";

            subPackages = [
              "cmd/agentsh"
              "cmd/agentsh-shell-shim"
            ]
            ++ lib.optionals stdenv.hostPlatform.isLinux [
              "cmd/agentsh-stub"
              "cmd/agentsh-unixwrap"
            ]
            ++ lib.optionals stdenv.hostPlatform.isDarwin [
              "cmd/agentsh-stub"
              "cmd/agentsh-rlimit-exec"
            ];

            nativeBuildInputs = [
              pkgs.makeWrapper
            ]
            ++ lib.optionals stdenv.hostPlatform.isLinux [
              pkgs.gnumake
              pkgs.llvm
              pkgs.llvmPackages.clang-unwrapped
              pkgs.pkg-config
            ];
            buildInputs = lib.optionals stdenv.hostPlatform.isLinux [
              pkgs.fuse3
              pkgs.libbpf
              pkgs.libseccomp
              pkgs.linuxHeaders
            ];

            env.CGO_ENABLED = if stdenv.hostPlatform.isLinux then "1" else "0";

            ldflags = [
              "-s"
              "-w"
              "-X main.version=${version}"
              "-X main.commit=${rev}"
            ]
            ++ lib.optionals stdenv.hostPlatform.isLinux [
              "-X github.com/agentsh/agentsh/internal/workspace/runtimebin.packagedPath=${runtimePath}"
            ];

            preBuild = lib.optionalString stdenv.hostPlatform.isLinux ''
              make -C internal/netmonitor/ebpf clean all \
                BPF_CLANG=${pkgs.llvmPackages.clang-unwrapped}/bin/clang \
                BPF_INCLUDE="-I${pkgs.libbpf}/include -I${pkgs.linuxHeaders}/include"
            '';

            postBuild = lib.optionalString stdenv.hostPlatform.isDarwin ''
              # Keep the main agentsh binary CGO-disabled on Darwin so cgofuse
              # does not require macFUSE headers. Build only the Seatbelt wrapper
              # with CGO enabled; it needs sandbox_init_with_parameters().
              CGO_ENABLED=1 go build \
                -ldflags='-s -w -X main.version=${version} -X main.commit=${rev}' \
                -o agentsh-macwrap \
                ./cmd/agentsh-macwrap
            '';

            # Tests exercise kernel features such as FUSE, seccomp, eBPF,
            # ptrace, and network namespaces. Keep package builds pure and
            # leave integration testing to VM/NixOS tests.
            doCheck = false;

            postInstall = ''
              install -Dm644 packaging/bash_startup.sh \
                $out/lib/agentsh/bash_startup.sh

              install -Dm644 config.yml \
                $out/share/agentsh/config.yml
              cp -r configs $out/share/agentsh/configs

              substituteInPlace $out/share/agentsh/config.yml \
                --replace-fail /usr/lib/agentsh/bash_startup.sh \
                  $out/lib/agentsh/bash_startup.sh
              substituteInPlace $out/share/agentsh/configs/server-config.yaml \
                --replace-fail /usr/lib/agentsh/bash_startup.sh \
                  $out/lib/agentsh/bash_startup.sh
            ''
            + lib.optionalString stdenv.hostPlatform.isDarwin ''

              install -Dm755 agentsh-macwrap $out/bin/agentsh-macwrap

              wrapProgram $out/bin/agentsh \
                --suffix PATH : "$out/bin:${runtimePath}"
              wrapProgram $out/bin/agentsh-shell-shim \
                --suffix PATH : "$out/bin:${runtimePath}"
              # Do not wrap agentsh-stub: execve interception redirects
              # supervised workloads to this exact binary. A makeWrapper shell
              # script would exec the hidden .agentsh-stub-wrapped binary,
              # which is then seen as a second, untrusted exec and can be
              # denied before the approval workflow starts.
              wrapProgram $out/bin/agentsh-rlimit-exec \
                --suffix PATH : "$out/bin:${runtimePath}"
              wrapProgram $out/bin/agentsh-macwrap \
                --suffix PATH : "$out/bin:${runtimePath}"
            ''
            + lib.optionalString stdenv.hostPlatform.isLinux ''

              substituteInPlace $out/share/agentsh/config.yml \
                --replace-fail '# wrapper_bin: "agentsh-unixwrap"' \
                  'wrapper_bin: "'$out'/bin/agentsh-unixwrap"'

              wrapProgram $out/bin/agentsh \
                --suffix PATH : "$out/bin:${runtimePath}"
              wrapProgram $out/bin/agentsh-shell-shim \
                --suffix PATH : "$out/bin:${runtimePath}"
              # Do not wrap agentsh-stub: execve interception redirects
              # supervised workloads to this exact binary. A makeWrapper shell
              # script would exec the hidden .agentsh-stub-wrapped binary,
              # which is then seen as a second, untrusted exec and can be
              # denied before the approval workflow starts.
              wrapProgram $out/bin/agentsh-unixwrap \
                --suffix PATH : "$out/bin:${runtimePath}"
            '';

            meta = {
              description = "Policy-enforced execution gateway for AI agents";
              homepage = "https://github.com/canyonroad/agentsh";
              license = lib.licenses.asl20;
              mainProgram = "agentsh";
              platforms = lib.platforms.linux ++ lib.platforms.darwin;
            };
          };
        in
        {
          default = agentsh;
          agentsh = agentsh;
        }
      );

      nixosModules = {
        default =
          {
            config,
            lib,
            pkgs,
            ...
          }@args:
          import ./nix/modules/nixos/agentsh.nix (
            args
            // {
              defaultPackage = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
            }
          );
        agentsh = self.nixosModules.default;
      };

      checks = forAllSystems (
        pkgs:
        let
          inherit (pkgs) lib stdenv;
        in
        {
          go-unit-tests = pkgs.buildGoModule {
            pname = "agentsh-go-unit-tests";
            version = "unstable-2026-06-17";
            src = self;
            vendorHash = "sha256-SnrqSrkgeH/jOiLV71h3a2q9OZj5ISru042kVjhrGRE=";

            nativeBuildInputs = lib.optionals stdenv.hostPlatform.isLinux [
              pkgs.gnumake
              pkgs.llvm
              pkgs.llvmPackages.clang-unwrapped
              pkgs.pkg-config
            ];
            buildInputs = lib.optionals stdenv.hostPlatform.isLinux [
              pkgs.libbpf
              pkgs.libseccomp
              pkgs.linuxHeaders
            ];
            env.CGO_ENABLED = if stdenv.hostPlatform.isLinux then "1" else "0";

            buildPhase = ''
              runHook preBuild
              runHook postBuild
            '';
            preCheck = lib.optionalString stdenv.hostPlatform.isLinux ''
              make -C internal/netmonitor/ebpf clean all \
                BPF_CLANG=${pkgs.llvmPackages.clang-unwrapped}/bin/clang \
                BPF_INCLUDE="-I${pkgs.libbpf}/include -I${pkgs.linuxHeaders}/include"
            '';
            checkPhase = ''
              runHook preCheck
              go test ./internal/policy -run 'Test(DiscoverProjectOverlays|LoadOverlay|MergePolicyOverlays)'
              go test ./internal/config -run 'TestProjectOverlays'
              go test ./internal/nethelper
              go test ./internal/detached ./internal/detachedreport
              go test ./internal/workspace/runtimebin ./internal/workspace/shadow ./internal/workspace/overlay
              runHook postCheck
            '';
            installPhase = ''
              runHook preInstall
              mkdir -p $out
              touch $out/passed
              runHook postInstall
            '';
          };

          approval-regression-tests =
            if stdenv.hostPlatform.isLinux then
              pkgs.buildGoModule {
                pname = "agentsh-approval-regression-tests";
                version = "unstable-2026-06-17";
                src = self;
                vendorHash = "sha256-SnrqSrkgeH/jOiLV71h3a2q9OZj5ISru042kVjhrGRE=";

                nativeBuildInputs = [
                  pkgs.gnumake
                  pkgs.llvm
                  pkgs.llvmPackages.clang-unwrapped
                  pkgs.pkg-config
                ];
                buildInputs = [
                  pkgs.fuse3
                  pkgs.libbpf
                  pkgs.libseccomp
                  pkgs.linuxHeaders
                ];
                env.CGO_ENABLED = "1";

                buildPhase = ''
                  runHook preBuild
                  runHook postBuild
                '';
                checkPhase = ''
                  runHook preCheck
                  make -C internal/netmonitor/ebpf clean all \
                    BPF_CLANG=${pkgs.llvmPackages.clang-unwrapped}/bin/clang \
                    BPF_INCLUDE="-I${pkgs.libbpf}/include -I${pkgs.linuxHeaders}/include"
                  go test ./internal/approvals -run 'Test(SessionCommandScopeResolutionCoversConcurrentPendingApprovals|ExactCommandScopeResolutionOnlyCoversMatchingConcurrentPendingApproval)'
                  go test ./internal/api -run 'Test(ResolveApprovalLocal_PiSelectedExecutableSessionScopeResolvesConcurrentPending|ApprovalUIResolve_PiSelectedExecutableSessionScopeResolvesConcurrentPending|DetachedSessionsPushedCommandSessionScopeResolvesCoveredPending)$'
                  go test ./internal/netmonitor/unix -run 'TestExecveHandler_Action/approve_preserves_notify_session_for_nested_exec_when_parent_was_first_seen_without_ancestry'
                  runHook postCheck
                '';
                installPhase = ''
                  runHook preInstall
                  mkdir -p $out
                  touch $out/passed
                  runHook postInstall
                '';
              }
            else
              pkgs.runCommand "agentsh-approval-regression-tests-skipped" { } ''
                mkdir -p $out
                touch $out/skipped-non-linux
              '';
        }
      );

      devShells = forAllSystems (
        pkgs:
        let
          inherit (pkgs) lib stdenv;
        in
        {
          default = pkgs.mkShell {
            packages = [
              (pkgs.go_1_25 or pkgs.go)
              pkgs.gopls
              pkgs.gotools
            ]
            ++ lib.optionals stdenv.hostPlatform.isLinux [
              pkgs.pkg-config
              pkgs.gcc
              pkgs.gnumake
              pkgs.llvm
              pkgs.llvmPackages.clang-unwrapped
              pkgs.fuse3
              pkgs.libbpf
              pkgs.libseccomp
              pkgs.linuxHeaders
              pkgs.coreutils
              pkgs.diffutils
              pkgs.iproute2
              pkgs.iptables
              pkgs.rsync
              pkgs.util-linux
            ];

            shellHook =
              lib.optionalString stdenv.hostPlatform.isLinux ''
                export CGO_ENABLED=1
                export BPF_CLANG=${pkgs.llvmPackages.clang-unwrapped}/bin/clang
                export BPF_INCLUDE="-I${pkgs.libbpf}/include -I${pkgs.linuxHeaders}/include"
              ''
              + lib.optionalString stdenv.hostPlatform.isDarwin ''
                export CGO_ENABLED=0
              '';
          };
        }
      );

      formatter = forAllSystems (pkgs: pkgs.nixfmt-rfc-style);
    };
}
