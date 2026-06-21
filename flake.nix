{
  description = "ezpds development shell";

  nixConfig = {
    extra-substituters = "https://devenv.cachix.org https://nix-community.cachix.org";
    extra-trusted-public-keys = "devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw= nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCUSOut=";
    allow-import-from-derivation = true;
  };

  inputs = {
    nixpkgs.url = "github:cachix/devenv-nixpkgs/rolling";
    devenv.url = "github:cachix/devenv";
    systems.url = "github:nix-systems/default";
  };

  outputs = { self, nixpkgs, devenv, systems, ... } @ inputs:
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

    # nixosModules is not per-system — placed outside forEachSystem.
    # The reworked module has no package option — it runs the OCI image directly.
    nixosModules.default = { ... }: {
      imports = [ ./nix/module.nix ];
    };
  };
}
