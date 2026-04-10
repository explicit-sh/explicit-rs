{ pkgs, lib, ... }:

{
  imports = [ ./devenv.generated.nix ];

  packages = [
    pkgs.git
    pkgs.jq
    pkgs.nono
  ];

  scripts.explicit.exec = ''
    cargo run -- "$@"
  '';

  enterShell = ''
    echo "Run 'explicit apply' to refresh detected tools and hooks, or 'explicit shell --command codex' to enter the sandboxed agent shell."
  '';
}
