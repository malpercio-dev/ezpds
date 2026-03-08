{
  description = "ezpds development shell";

  nixConfig = {
    extra-substituters = "https://devenv.cachix.org";
    extra-trusted-public-keys = "devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw=";
    allow-import-from-derivation = true;
  };

  inputs = {
    nixpkgs.url = "github:cachix/devenv-nixpkgs/rolling";
    devenv.url = "github:cachix/devenv";
    systems.url = "github:nix-systems/default";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs = { nixpkgs.follows = "nixpkgs"; };
  };

  outputs = { self, nixpkgs, devenv, systems, rust-overlay, ... } @ inputs:
  let
    forEachSystem = f: nixpkgs.lib.genAttrs (import systems) f;
  in {
    devShells = forEachSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        default = devenv.lib.mkShell {
          inherit inputs pkgs;
          modules = [ ./devenv.nix ];
        };
      }
    );
  };
}
