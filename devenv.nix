{ pkgs, lib, config, ... }:
{
  languages.rust = {
    enable = true;
    toolchainFile = ./rust-toolchain.toml;
  };

  packages = [
    pkgs.just
    pkgs.cargo-audit
    pkgs.sqlite
    pkgs.pkg-config
  ];

  env.LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
}
