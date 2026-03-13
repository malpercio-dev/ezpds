{ pkgs, config, ... }:
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

  # Relay dev configuration — override any of these in devenv.local.nix.
  env.EZPDS_CONFIG = "${config.devenv.root}/relay.dev.toml";
  env.EZPDS_DATA_DIR = "${config.devenv.root}/.devenv/state/relay";
  env.EZPDS_PUBLIC_URL = "http://localhost:8080";
  env.RUST_LOG = "info";

  # Signing key master key for local development.
  # DO NOT USE IN PRODUCTION.
  env.EZPDS_SIGNING_KEY_MASTER_KEY = "2a55ebbdb7c0a4864a3944a443765b13602c6fbbeda38c2d6afc57b96663810e";

  processes.relay = {
    exec = "cargo run --package relay";
  };
}
