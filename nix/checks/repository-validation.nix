{
  pkgs,
  self,
}:
{
  shell-validation =
    pkgs.runCommand "agentsh-shell-validation"
      {
        nativeBuildInputs = [ pkgs.shellcheck ];
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
        mkdir -p "$out"
        touch "$out/passed"
      '';

  nix-validation =
    pkgs.runCommand "agentsh-nix-validation"
      {
        nativeBuildInputs = [ pkgs.nixfmt ];
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
        mkdir -p "$out"
        touch "$out/passed"
      '';
}
