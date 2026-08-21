{
  pkgs,
  self,
}:
{
  shell-validation =
    pkgs.runCommand "agentsh-shell-validation"
      {
        nativeBuildInputs = [
          pkgs.shellcheck
          pkgs.shfmt
        ];
      }
      ''
        cp -R ${self} source
        chmod -R u+w source
        cd source
        mapfile -d "" scripts < <(find . -type f \( -name '*.sh' -o -name '*.bash' \) \
        -not -path './.git/*' -not -path './packaging/completions/*' -print0)
        if [ "''${#scripts[@]}" -eq 0 ]; then
          echo "no shell scripts found" >&2
          exit 1
        fi
        shellcheck --external-sources --severity=warning "''${scripts[@]}"
        shfmt --diff --indent 2 --case-indent --binary-next-line "''${scripts[@]}"
        mkdir -p "$out"
        touch "$out/passed"
      '';

  nix-validation =
    pkgs.runCommand "agentsh-nix-validation"
      {
        nativeBuildInputs = [
          pkgs.deadnix
          pkgs.nixfmt
          pkgs.statix
        ];
      }
      ''
        cp -R ${self} source
        chmod -R u+w source
        cd source
        mapfile -d "" expressions < <(find . -type f -name '*.nix' -not -path './.git/*' -print0)
        if [ "''${#expressions[@]}" -eq 0 ]; then
          echo "no Nix expressions found" >&2
          exit 1
        fi
        nixfmt --check "''${expressions[@]}"
        statix check .
        deadnix --fail .
        mkdir -p "$out"
        touch "$out/passed"
      '';
}
