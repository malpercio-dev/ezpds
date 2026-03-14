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
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs = { nixpkgs.follows = "nixpkgs"; };
    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, devenv, systems, rust-overlay, crane, ... } @ inputs:
  let
    forEachSystem = f: nixpkgs.lib.genAttrs (import systems) f;
  in {
    packages = forEachSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        commonArgs = {
          src = craneLib.cleanCargoSource ./.;
          pname = "relay";
          strictDeps = true;
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.sqlite ];
          LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
        };

        # Build deps separately so they're cached when only source changes.
        # Scope buildDepsOnly to relay-related crates only.
        # apps/identity-wallet/src-tauri uses Tauri (webkit2gtk on Linux, Apple frameworks
        # on macOS) which are not in commonArgs.buildInputs. Without this scope,
        # buildDepsOnly would attempt to compile Tauri's native deps and fail in Nix.
        cargoArtifacts = craneLib.buildDepsOnly (commonArgs // {
          cargoExtraArgs = "--package relay --package repo-engine --package crypto --package common";
        });

        relay = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          cargoExtraArgs = "--package relay";
        });
      in {
        inherit relay;
        default = relay;
      } // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
        docker-image = import ./nix/docker.nix { inherit pkgs relay; };
      }
    );

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
    # self is captured from the outputs function closure.
    nixosModules.default = { lib, pkgs, ... }: {
      imports = [ ./nix/module.nix ];
      # Guard the package default: on unsupported architectures self.packages
      # won't have an entry, and the raw attrset access would produce an
      # opaque "attribute missing" error. When the guard fails, NixOS surfaces
      # its own "option services.ezpds.package is not set" message instead.
      config.services.ezpds.package = lib.mkIf
        (self.packages ? ${pkgs.system})
        (lib.mkDefault self.packages.${pkgs.system}.relay);
    };
  };
}
