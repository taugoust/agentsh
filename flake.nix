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
              "cmd/agentsh-bwrap-adapter"
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

            postBuild =
              lib.optionalString stdenv.hostPlatform.isLinux ''
                $CC -std=c11 -O2 -Wall -Wextra -Werror -static \
                  -L${pkgs.glibc.static}/lib \
                  cmd/agentsh-composition-mount-helper/main.c \
                  -o agentsh-composition-mount-helper
                $CC -std=c11 -O2 -Wall -Wextra -Werror -static \
                  -L${pkgs.glibc.static}/lib \
                  cmd/agentsh-composition-ns-launcher/main.c \
                  -o agentsh-composition-ns-launcher
                $CC -std=c11 -O2 -Wall -Wextra -Werror -static \
                  -L${pkgs.glibc.static}/lib \
                  cmd/agentsh-file-lookup-broker/main.c \
                  -o agentsh-file-lookup-broker
                CGO_ENABLED=0 go build \
                  -ldflags='-s -w' \
                  -o agentsh-bwrap-adapter-static \
                  ./cmd/agentsh-bwrap-adapter
              ''
              + lib.optionalString stdenv.hostPlatform.isDarwin ''
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

              install -Dm755 agentsh-bwrap-adapter-static \
                $out/bin/agentsh-bwrap-adapter
              install -Dm755 agentsh-composition-mount-helper \
                $out/bin/agentsh-composition-mount-helper
              install -Dm755 agentsh-composition-ns-launcher \
                $out/bin/agentsh-composition-ns-launcher
              install -Dm755 agentsh-file-lookup-broker \
                $out/bin/agentsh-file-lookup-broker
              for trusted_binary in \
                $out/bin/agentsh-bwrap-adapter \
                $out/bin/agentsh-composition-mount-helper \
                $out/bin/agentsh-composition-ns-launcher \
                $out/bin/agentsh-file-lookup-broker; do
                if readelf -l "$trusted_binary" | grep -q 'Requesting program interpreter'; then
                  echo "trusted native binary is dynamically linked: $trusted_binary" >&2
                  exit 1
                fi
              done

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
          formatted-go-source =
            pkgs.runCommand "agentsh-formatted-go-source"
              {
                nativeBuildInputs = [ pkgs.go ];
              }
              ''
                mkdir -p "$out"
                cp -R ${self}/. "$out/"
                chmod -R u+w "$out"
                find "$out" -type f -name '*.go' \
                  -not -path "$out/vendor/*" \
                  -exec gofmt -w {} +
              '';
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
          moduleTestPackage =
            pkgs.runCommand "agentsh-module-test-package"
              {
                meta.mainProgram = "agentsh";
              }
              ''
                mkdir -p "$out/bin"
                touch "$out/bin/agentsh"
              '';
          evalSessionRuntimeModule =
            maxBytes: subagentTimeout:
            nixpkgs.lib.nixosSystem {
              system = stdenv.hostPlatform.system;
              modules = [
                self.nixosModules.default
                ({ ... }: {
                  system.stateVersion = "25.11";
                  services.agentsh = {
                    enable = true;
                    package = moduleTestPackage;
                    policies.source = moduleTestPackage;
                    extraConfig.sessions.default_idle_timeout = "9h";
                  }
                  //
                    lib.recursiveUpdate
                      (lib.optionalAttrs (maxBytes != null) {
                        sessions.outputArtifacts.maxBytes = maxBytes;
                      })
                      (
                        lib.optionalAttrs (subagentTimeout != null) {
                          sessions.subagents.defaultTimeout = subagentTimeout;
                        }
                      );
                })
              ];
            };
          defaultSessionRuntimeModule = evalSessionRuntimeModule null null;
          customSessionRuntimeModule = evalSessionRuntimeModule 33554432 "45m";
          compositionEnabledModule = nixpkgs.lib.nixosSystem {
            system = stdenv.hostPlatform.system;
            modules = [
              self.nixosModules.default
              ({ ... }: {
                system.stateVersion = "25.11";
                services.agentsh = {
                  enable = true;
                  package = moduleTestPackage;
                  policies.source = moduleTestPackage;
                  sandbox = {
                    composition.bubblewrap.enable = true;
                    seccomp.execve.enable = true;
                    network.ebpf.enforce = true;
                  };
                  extraConfig.landlock.enabled = true;
                };
              })
            ];
          };
          compositionAutoModule = nixpkgs.lib.nixosSystem {
            system = stdenv.hostPlatform.system;
            modules = [
              self.nixosModules.default
              ({ ... }: {
                system.stateVersion = "25.11";
                services.agentsh = {
                  enable = true;
                  package = moduleTestPackage;
                  policies.source = moduleTestPackage;
                  sandbox = {
                    composition.bubblewrap = {
                      enable = true;
                      scratchRoot = "auto";
                    };
                    seccomp.execve.enable = true;
                    network.ebpf.enforce = true;
                  };
                  extraConfig.landlock.enabled = true;
                };
              })
            ];
          };
        in
        rec {
          go-format =
            pkgs.runCommand "agentsh-go-format-check"
              {
                nativeBuildInputs = [ pkgs.go ];
              }
              ''
                set -euo pipefail
                cp -R ${self} source
                chmod -R u+w source
                cd source
                find . -type f -name '*.go' \
                  -not -path './.git/*' \
                  -not -path './vendor/*' \
                  -exec gofmt -l {} + > "$TMPDIR/unformatted-go"
                if [ -s "$TMPDIR/unformatted-go" ]; then
                  echo "Go files require formatting; run: nix fmt -- <files>" >&2
                  cat "$TMPDIR/unformatted-go" >&2
                  exit 1
                fi
                mkdir -p "$out"
                touch "$out/passed"
              '';

          linux-amd64-compile =
            if stdenv.hostPlatform.system == "aarch64-linux" then
              let
                cross = pkgs.pkgsCross.gnu64;
              in
              cross.buildGoModule {
                pname = "agentsh-linux-amd64-compile";
                version = "unstable-2026-06-17";
                src = self;
                vendorHash = "sha256-SnrqSrkgeH/jOiLV71h3a2q9OZj5ISru042kVjhrGRE=";
                subPackages = [ "internal/netmonitor/unix" ];
                nativeBuildInputs = [
                  pkgs.gnumake
                  pkgs.llvmPackages.clang-unwrapped
                  cross.pkg-config
                ];
                buildInputs = [
                  cross.libbpf
                  cross.libseccomp
                  cross.linuxHeaders
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
                doCheck = false;
              }
            else
              pkgs.runCommand "agentsh-linux-amd64-compile-covered-natively" { } ''
                mkdir -p "$out"
                touch "$out/covered-natively"
              '';

          nested-namespace-feasibility =
            if stdenv.hostPlatform.isLinux then
              import ./nix/checks/nested-namespace-feasibility.nix {
                inherit pkgs self;
              }
            else
              pkgs.runCommand "agentsh-nested-namespace-feasibility-skipped" { } ''
                mkdir -p "$out"
                touch "$out/skipped-non-linux"
              '';

          nested-namespace-broker-feasibility =
            if stdenv.hostPlatform.isLinux then
              import ./nix/checks/nested-namespace-broker-feasibility.nix {
                inherit pkgs self;
              }
            else
              pkgs.runCommand "agentsh-nested-namespace-broker-feasibility-skipped" { } ''
                mkdir -p "$out"
                touch "$out/skipped-non-linux"
              '';

          recursive-mount-clone-feasibility =
            if stdenv.hostPlatform.isLinux then
              import ./nix/checks/recursive-mount-clone-feasibility.nix {
                inherit pkgs self;
              }
            else
              pkgs.runCommand "agentsh-recursive-mount-clone-feasibility-skipped" { } ''
                mkdir -p "$out"
                touch "$out/skipped-non-linux"
              '';

          landlock-mount-graph-feasibility =
            if stdenv.hostPlatform.isLinux then
              import ./nix/checks/landlock-mount-graph-feasibility.nix {
                inherit pkgs self;
              }
            else
              pkgs.runCommand "agentsh-landlock-mount-graph-feasibility-skipped" { } ''
                mkdir -p "$out"
                touch "$out/skipped-non-linux"
              '';

          approval-resolution-race-tests = pkgs.buildGoModule {
            pname = "agentsh-approval-resolution-race-tests";
            version = "unstable-2026-06-17";
            src = self;
            vendorHash = "sha256-SnrqSrkgeH/jOiLV71h3a2q9OZj5ISru042kVjhrGRE=";

            env = {
              CGO_ENABLED = "0";
              GOTELEMETRY = "off";
            };

            buildPhase = ''
              runHook preBuild
              runHook postBuild
            '';
            checkPhase = ''
              runHook preCheck
              go test -v -count=1 ./internal/approvals
              runHook postCheck
            '';
            installPhase = ''
              runHook preInstall
              mkdir -p $out
              touch $out/passed
              runHook postInstall
            '';
          };

          # Authoritative native Go suite. Focused checks below reuse the same
          # build environment but remain separate for faster diagnosis.
          go-unit-tests = pkgs.buildGoModule {
            pname = "agentsh-go-tests";
            version = "unstable-2026-06-17";
            src = self;
            vendorHash = "sha256-SnrqSrkgeH/jOiLV71h3a2q9OZj5ISru042kVjhrGRE=";

            nativeBuildInputs = lib.optionals stdenv.hostPlatform.isLinux [
              pkgs.diffutils
              pkgs.gnumake
              pkgs.llvm
              pkgs.llvmPackages.clang-unwrapped
              pkgs.pkg-config
              pkgs.rsync
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
              mkdir -p "$TMPDIR/go-tmp"
              export GOTMPDIR="$TMPDIR/go-tmp"
              go test -count=1 -p 2 ./...
              runHook postCheck
            '';
            installPhase = ''
              runHook preInstall
              mkdir -p $out
              touch $out/passed
              runHook postInstall
            '';
          };

          shadow-review-atomicity-tests = go-unit-tests.overrideAttrs (_: {
            pname = "agentsh-shadow-review-atomicity-tests";
            checkPhase = ''
              runHook preCheck
              go test ./internal/workspace/shadow -run '^Test(Review|WorkspaceDiff|WorkspaceLifecycle|Prepared)'
              go test ./internal/session -run '^TestWorkspaceFinalization'
              go test ./internal/api -run '^Test(ShadowReview|ReservedWorkspaceFinalization|GRPCDestroyRefusesWorkspaceFinalization|WorkspacePendingFinalization)'
              runHook postCheck
            '';
          });

          detached-control-transport-tests = go-unit-tests.overrideAttrs (_: {
            pname = "agentsh-detached-control-transport-tests";
            checkPhase = ''
              runHook preCheck
              go test ./internal/detachedtransport
              go test ./internal/client -run '^TestExchangeDetachedControl'
              go test ./internal/approvals -run '^TestApprovalResolution'
              go test ./internal/api -run '^TestDetachedControl'
              go test ./internal/cli -run '^TestDetachedSupervisor(ServiceEnv|RestartEnvironment|BuildSystemdRun)'
              runHook postCheck
            '';
          });

          runtime-provider-tests = go-unit-tests.overrideAttrs (_: {
            pname = "agentsh-runtime-provider-tests";
            checkPhase = ''
              runHook preCheck
              go test ./internal/runtimeprovider
              go test ./internal/config -run '^TestRuntimeProfiles'
              go test ./internal/api -run '^Test(CreateSessionRejectsCallerRuntimeSelection|GRPCCreateSessionRejectsCallerRuntimeSelection)$'
              go test ./internal/cli -run '^TestRuntimeProvider'
              runHook postCheck
            '';
          });

          guest-control-protocol-tests = go-unit-tests.overrideAttrs (_: {
            pname = "agentsh-guest-control-protocol-tests";
            checkPhase = ''
              runHook preCheck
              go test ./internal/guestcontrol
              go test ./internal/cli -run '^TestGuestControl'
              runHook postCheck
            '';
          });

          # Stable focused gates consumed by lifecycle integration branches.
          detached-supervisor-recovery-tests = go-unit-tests.overrideAttrs (_: {
            pname = "agentsh-detached-supervisor-recovery-tests";
            checkPhase = ''
              runHook preCheck
              go test ./internal/detached
              go test ./internal/workspace/shadow -run 'TestOpenMulti'
              go test ./internal/api -run 'TestNethelperRebind_DetachedBootstrap'
              go test ./internal/cli -run 'Test(DetachedSupervisor|BuildDetachedSupervisor|BuildSystemdRunDetachedSupervisor)'
              runHook postCheck
            '';
          });

          detached-supervisor-expiry-tests = go-unit-tests.overrideAttrs (_: {
            pname = "agentsh-detached-supervisor-expiry-tests";
            checkPhase = ''
              runHook preCheck
              go test ./internal/session -run '^TestManager_ReapExpiredGuarded_'
              go test ./internal/detached -run '^TestRuntimeHeartbeatUsesAdvisoryRecordAndStopsAtTerminal$'
              go test ./internal/api -run '^Test(ReapExpiredSessions_|DestroySession_SignalsDetachedSupervisorShutdown|DetachedRuntimeStatus_)'
              go test ./internal/server -run '^TestServerRun_ExitsCleanlyWhenDetachedSessionExpires$'
              go test ./internal/cli -run '^Test(DetachedSessionIDRequiresCanonicalCallerIdentity|ValidateDetachedStopAuthorityRequiresExactTopology|ExactDetachedSessionNotFoundRequiresProtocolV2Typed404|StopDetachedSessionExact_ContinuesAfterIdentityChecked404|StopDetachedSupervisorSystemdUnit_AlreadyCollectedIsSuccess)$'
              runHook postCheck
            '';
          });

          detached-supervisor-systemd-recovery =
            if stdenv.hostPlatform.isLinux then
              import ./nix/checks/detached-supervisor-systemd-recovery.nix {
                inherit pkgs self;
              }
            else
              pkgs.runCommand "agentsh-detached-supervisor-systemd-recovery-skipped" { } ''
                mkdir -p "$out"
                touch "$out/skipped-non-linux"
              '';

          detached-supervisor-systemd-expiry =
            if stdenv.hostPlatform.isLinux then
              import ./nix/checks/detached-supervisor-systemd-expiry.nix {
                inherit pkgs self;
              }
            else
              pkgs.runCommand "agentsh-detached-supervisor-systemd-expiry-skipped" { } ''
                mkdir -p "$out"
                touch "$out/skipped-non-linux"
              '';

          nethelper-lifecycle-tests = go-unit-tests.overrideAttrs (_: {
            pname = "agentsh-nethelper-lifecycle-tests";
            checkPhase = ''
              runHook preCheck
              go test ./internal/nethelper -run 'Test(EphemeralInstanceController|ReleaseWaitsForInFlightRegistration|ReleaseTimeoutReopensLifecycleAdmission|ClientServerReleaseCancellationRecoversAdmission|FailedRegistrationCompensationRetainsAuthenticatedTombstone|SupervisorAuthorizerReaper|BootstrapResult|DefaultBootstrapRuntime)'
              go test ./internal/cli -run 'Test(EphemeralSystemdRunArgs|NethelperBootstrapRuntime|ValidateEphemeralNethelperRuntime)'
              runHook postCheck
            '';
          });
          nethelper-rebind-tests = go-unit-tests.overrideAttrs (_: {
            pname = "agentsh-nethelper-rebind-tests";
            checkPhase = ''
              runHook preCheck
              go test ./internal/api -run 'Test(NethelperRebind|RebindSerializes|FailedCandidateCleanup|HelperDisappearance|WrapperRecoveryToken|RunCommand.*AuthoritativeStart|NormalizeBarrierFailure|PiToolExecBash_(PreExecFailure|ChildExit127))'
              runHook postCheck
            '';
          });

          command-timeout-tests = pkgs.buildGoModule {
            pname = "agentsh-command-timeout-tests";
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
            env = {
              CGO_ENABLED = if stdenv.hostPlatform.isLinux then "1" else "0";
              GOTELEMETRY = "off";
            };

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
              go test ./internal/api -run '^(TestCommandTimeout.*|TestCommandOutputArtifactCapture_DirenvEnvironmentPrecedenceAndProtectedFilter)$'
              go test ./internal/approvals -run '^TestRequestApproval_ExtendsCommandTimeout$'
              go test ./internal/policy -run '^(TestPolicyValidateCommandTimeoutMinimum|TestPolicyLoadRejectsSubMillisecondCommandTimeout|TestEngine_Limits)$'
              go test ./internal/store/sqlite -run '^TestAppendEventSaturationDropsBulkButPreservesLifecycle$'
              go test ./internal/store/jsonl -run '^TestAppendEventHonorsContextWhileWriterLockIsHeld$'
              runHook postCheck
            '';
            installPhase = ''
              runHook preInstall
              mkdir -p $out
              touch $out/passed
              runHook postInstall
            '';
          };

          api-darwin-cross-compile-tests = pkgs.buildGoModule {
            pname = "agentsh-api-darwin-cross-compile-tests";
            version = "unstable-2026-06-17";
            src = self;
            vendorHash = "sha256-SnrqSrkgeH/jOiLV71h3a2q9OZj5ISru042kVjhrGRE=";

            env = {
              CGO_ENABLED = "0";
              GOTELEMETRY = "off";
            };

            buildPhase = ''
              runHook preBuild
              GOOS=darwin GOARCH=amd64 go test -c -o api-darwin-amd64.test ./internal/api
              GOOS=darwin GOARCH=arm64 go test -c -o api-darwin-arm64.test ./internal/api
              runHook postBuild
            '';
            doCheck = false;
            installPhase = ''
              runHook preInstall
              mkdir -p $out
              touch $out/passed
              runHook postInstall
            '';
          };

          workspace-runtime-tests = pkgs.buildGoModule {
            pname = "agentsh-workspace-runtime-tests";
            version = "unstable-2026-06-17";
            src = self;
            vendorHash = "sha256-SnrqSrkgeH/jOiLV71h3a2q9OZj5ISru042kVjhrGRE=";
            nativeBuildInputs = [
              pkgs.diffutils
              pkgs.rsync
            ];

            env = {
              CGO_ENABLED = "0";
              GOTELEMETRY = "off";
            };

            buildPhase = ''
              runHook preBuild
              runHook postBuild
            '';
            checkPhase = ''
              runHook preCheck
              go test ./internal/workspace/runtimebin ./internal/workspace/shadow ./internal/workspace/overlay
              GOOS=linux go build ./internal/workspace/... ./internal/session
              GOOS=darwin go build ./internal/workspace/... ./internal/session
              GOOS=windows go build ./internal/workspace/... ./internal/session
              runHook postCheck
            '';
            installPhase = ''
              runHook preInstall
              mkdir -p $out
              touch $out/passed
              runHook postInstall
            '';
          };

          subagent-reliability-tests = pkgs.buildGoModule {
            pname = "agentsh-subagent-reliability-tests";
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
              pkgs.fuse3
              pkgs.libbpf
              pkgs.libseccomp
              pkgs.linuxHeaders
            ];
            env = {
              CGO_ENABLED = if stdenv.hostPlatform.isLinux then "1" else "0";
              GOTELEMETRY = "off";
            };

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
              go test ./internal/api -run '^Test(Subagent|ValidateSpawnSubagentRequest|SplitCommandArgs|ParsePiJSONFinal|AppendSubagentTaskArgs|PrepareSubagentPiDirs|WithEnvOverrides)'
              runHook postCheck
            '';
            installPhase = ''
              runHook preInstall
              mkdir -p $out
              touch $out/passed
              runHook postInstall
            '';
          };

          child-execution-lane-tests = go-unit-tests.overrideAttrs (_: {
            pname = "agentsh-child-execution-lane-tests";
            checkPhase = ''
              runHook preCheck
              go test -race ./internal/session -run '^(TestExecutionLanes_|TestLockExecContextCancelledQueueNeverAcquiresLater$|TestManager_ReapExpired_DoesNotIdleReapBusySession$)'
              go test ./internal/config -run '^TestSubagents_'
              go test -race ./internal/netmonitor -run '^(TestStartProxy|TestProxy|TestHandleConnect|TestCheckConnectNetwork)'
              go test -race ./internal/api -run '^(TestChildExecution(Lanes|Capability)_|TestKillCommand_KillsRunningExec$|TestNetworkCleanupFailureCannotBeOverwrittenByInactiveSuccess$)'
              runHook postCheck
            '';
          });

          nixos-output-artifacts-module =
            if stdenv.hostPlatform.isLinux then
              assert
                defaultSessionRuntimeModule.config.services.agentsh.sessions.outputArtifacts.maxBytes == 16777216;
              assert
                defaultSessionRuntimeModule.config.services.agentsh.sessions.subagents.defaultTimeout == "2h";
              assert
                defaultSessionRuntimeModule.config.services.agentsh.sessions.subagents.maxExecConcurrency == 1;
              assert
                customSessionRuntimeModule.config.services.agentsh.sessions.outputArtifacts.maxBytes == 33554432;
              assert
                customSessionRuntimeModule.config.services.agentsh.sessions.subagents.defaultTimeout == "45m";
              assert builtins.elem "d /agentsh-composition-scratch 1733 root root -"
                compositionEnabledModule.config.systemd.tmpfiles.rules;
              assert
                !(builtins.any (lib.hasInfix "agentsh-composition-scratch") compositionAutoModule.config.systemd.tmpfiles.rules);
              pkgs.runCommand "agentsh-nixos-output-artifacts-module-test"
                {
                  nativeBuildInputs = [ pkgs.yq-go ];
                }
                ''
                  set -euo pipefail
                  yq -e '.sessions.output_artifacts.max_bytes == 16777216' \
                    ${defaultSessionRuntimeModule.config.environment.etc."agentsh/config.yml".source}
                  yq -e '.sessions.subagents.default_timeout == "2h"' \
                    ${defaultSessionRuntimeModule.config.environment.etc."agentsh/config.yml".source}
                  yq -e '.sessions.subagents.max_exec_concurrency == 1' \
                    ${defaultSessionRuntimeModule.config.environment.etc."agentsh/config.yml".source}
                  yq -e '.sessions.default_idle_timeout == "9h"' \
                    ${defaultSessionRuntimeModule.config.environment.etc."agentsh/config.yml".source}
                  yq -e '.sandbox.composition.bubblewrap.enabled == false' \
                    ${defaultSessionRuntimeModule.config.environment.etc."agentsh/config.yml".source}
                  yq -e '.sandbox.composition.bubblewrap.scratch_root == "/agentsh-composition-scratch"' \
                    ${defaultSessionRuntimeModule.config.environment.etc."agentsh/config.yml".source}
                  yq -e '.sandbox.seccomp.file_monitor.intercept_metadata == true' \
                    ${compositionEnabledModule.config.environment.etc."agentsh/config.yml".source}
                  yq -e '.sandbox.seccomp.file_monitor.write_only_opens == false' \
                    ${compositionEnabledModule.config.environment.etc."agentsh/config.yml".source}
                  yq -e '.sandbox.seccomp.file_monitor.block_io_uring == true' \
                    ${compositionEnabledModule.config.environment.etc."agentsh/config.yml".source}
                  yq -e '.sandbox.composition.bubblewrap.scratch_root == "auto"' \
                    ${compositionAutoModule.config.environment.etc."agentsh/config.yml".source}
                  yq -e '.sessions.output_artifacts.max_bytes == 33554432' \
                    ${customSessionRuntimeModule.config.environment.etc."agentsh/config.yml".source}
                  yq -e '.sessions.subagents.default_timeout == "45m"' \
                    ${customSessionRuntimeModule.config.environment.etc."agentsh/config.yml".source}
                  mkdir -p "$out"
                  touch "$out/passed"
                ''
            else
              pkgs.runCommand "agentsh-nixos-output-artifacts-module-test-skipped" { } ''
                mkdir -p "$out"
                touch "$out/skipped-non-linux"
              '';

          missing-read-probe-tests =
            if stdenv.hostPlatform.isLinux then
              go-unit-tests.overrideAttrs (old: {
                pname = "agentsh-missing-read-probe-tests";
                nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.binutils ];
                checkPhase = ''
                  runHook preCheck
                  $CC -std=c11 -O2 -Wall -Wextra -Werror -static \
                    -L${pkgs.glibc.static}/lib \
                    cmd/agentsh-file-lookup-broker/main.c \
                    -o "$TMPDIR/agentsh-file-lookup-broker"
                  if readelf -l "$TMPDIR/agentsh-file-lookup-broker" | grep -q 'Requesting program interpreter'; then
                    echo "file lookup worker is dynamically linked" >&2
                    exit 1
                  fi
                  export AGENTSH_FILE_LOOKUP_WORKER_TEST="$TMPDIR/agentsh-file-lookup-broker"
                  go test ./internal/filelookup
                  go test ./internal/wraphandoff -run '^Test(Local|Lineage)'
                  go test ./cmd/agentsh-unixwrap -run '^TestPayloadForkInstallsNotifyOnlyInExactChild$'
                  go test ./internal/approvals -run '^TestRequestApprovalScoped_'
                  go test ./internal/netmonitor/unix -run '^Test(EvaluateFileNotification|FileLookupBroker|FileHandlerFileLookupProbe|FileHandler_|EligibleMissingLookup|ExtractFileArgs_|ExtractLegacyFileArgs_|ReadPathname_|ResolvePathAt|ReadOpenHow|ApplyOpenHow|NotifRespond(Errno|Deny))'
                  go test ./internal/api -run '^Test(AcceptNotifyFDLineage|CreateFileHandler_|FilePolicyEngineWrapper_|FileHandler_(Prepare|Resolve)|FileApprovalScope_|FileLookupWorkerForWrapper)'
                  runHook postCheck
                '';
              })
            else
              pkgs.runCommand "agentsh-missing-read-probe-tests-skipped" { } ''
                mkdir -p $out
                touch $out/skipped-non-linux
              '';

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
                  go test ./internal/api -run 'Test(ResolveApprovalLocal_PiSelectedExecutableSessionScopeResolvesConcurrentPending|ApprovalUIResolve_PiSelectedExecutableSessionScopeResolvesConcurrentPending)$'
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
              pkgs.pre-commit
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

            shellHook = ''
              if git rev-parse --git-dir >/dev/null 2>&1; then
                git config --local core.hooksPath .githooks
              fi
            ''
            + lib.optionalString stdenv.hostPlatform.isLinux ''
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

      formatter = forAllSystems (
        pkgs:
        pkgs.writeShellApplication {
          name = "agentsh-format";
          runtimeInputs = [
            pkgs.findutils
            pkgs.go
            pkgs.nixfmt-rfc-style
          ];
          text = ''
            set -euo pipefail
            mode=all
            if [ "''${1:-}" = "--go-only" ]; then
              mode=go
              shift
            fi
            if [ "$#" -eq 0 ]; then
              set -- .
            fi
            go_files=()
            nix_files=()
            add_file() {
              case "$1" in
                *.go) go_files+=("$1") ;;
                *.nix)
                  if [ "$mode" = all ]; then
                    nix_files+=("$1")
                  fi
                  ;;
              esac
            }
            for target in "$@"; do
              if [ -d "$target" ]; then
                while IFS= read -r -d $'\0' file; do
                  add_file "$file"
                done < <(find "$target" -type f \( -name '*.go' -o -name '*.nix' \) -not -path '*/.git/*' -not -path '*/vendor/*' -print0)
              elif [ -f "$target" ]; then
                add_file "$target"
              fi
            done
            if [ "''${#go_files[@]}" -gt 0 ]; then
              gofmt -w "''${go_files[@]}"
            fi
            if [ "''${#nix_files[@]}" -gt 0 ]; then
              nixfmt "''${nix_files[@]}"
            fi
          '';
        }
      );
    };
}
