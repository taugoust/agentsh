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
            ];

            nativeBuildInputs = [
              pkgs.makeWrapper
            ]
            ++ lib.optionals stdenv.hostPlatform.isLinux [ pkgs.pkg-config ];
            buildInputs = lib.optionals stdenv.hostPlatform.isLinux [
              pkgs.fuse3
              pkgs.libseccomp
            ];

            env.CGO_ENABLED = if stdenv.hostPlatform.isLinux then "1" else "0";

            ldflags = [
              "-s"
              "-w"
              "-X main.version=${version}"
              "-X main.commit=${rev}"
            ];

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
            + lib.optionalString stdenv.hostPlatform.isLinux ''

              substituteInPlace $out/share/agentsh/config.yml \
                --replace-fail '# wrapper_bin: "agentsh-unixwrap"' \
                  'wrapper_bin: "'$out'/bin/agentsh-unixwrap"'

              wrapProgram $out/bin/agentsh \
                --suffix PATH : "$out/bin:${runtimePath}"
              wrapProgram $out/bin/agentsh-shell-shim \
                --suffix PATH : "$out/bin:${runtimePath}"
              wrapProgram $out/bin/agentsh-stub \
                --suffix PATH : "$out/bin:${runtimePath}"
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
              pkgs.fuse3
              pkgs.libseccomp
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
