{
  projectRootFile = "flake.nix";

  programs = {
    gofmt.enable = true;
    nixfmt.enable = true;
    shfmt.enable = true;
  };

  settings.formatter.shfmt = {
    options = [
      "--indent"
      "2"
      "--case-indent"
      "--binary-next-line"
    ];
  };
}
