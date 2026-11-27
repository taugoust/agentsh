{
  projectRootFile = "flake.nix";

  programs = {
    gofmt.enable = true;
    golines = {
      enable = true;
      maxLength = 100;
      tabLength = 4;
    };
    nixfmt.enable = true;
    shfmt.enable = true;
  };

  settings.formatter = {
    # golines emits gofmt-formatted output; run it after gofmt so both
    # formatters agree on the final result.
    golines = {
      priority = 1;
      # Generated protobuf code is regenerated, not hand-formatted.
      excludes = [ "*.pb.go" ];
    };

    shfmt = {
      options = [
        "--indent"
        "2"
        "--case-indent"
        "--binary-next-line"
      ];
    };
  };
}
