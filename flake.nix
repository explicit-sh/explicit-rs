{
  inputs = {
    nixpkgs.url = "github:cachix/devenv-nixpkgs/rolling";
    devenv.url = "github:cachix/devenv";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs =
    inputs@{ flake-parts, nixpkgs, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ inputs.devenv.flakeModule ];

      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-darwin"
        "x86_64-linux"
      ];

      perSystem =
        { lib, pkgs, system, ... }:
        let
          syncTool = pkgs.rustPlatform.buildRustPackage {
            pname = "explicit";
            version = "0.1.0";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            meta.mainProgram = "explicit";
          };
        in
        {
          packages = {
            explicit = syncTool;
            default = syncTool;
          };

          apps = {
            explicit = {
              type = "app";
              program = "${syncTool}/bin/explicit";
            };
            default = {
              type = "app";
              program = "${syncTool}/bin/explicit";
            };
          };

          devenv.shells.default = {
            imports = [ ./devenv.nix ];
          };
        };
    };
}
