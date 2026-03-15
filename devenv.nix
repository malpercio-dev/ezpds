{ pkgs, config, ... }:
{
  packages = [
    pkgs.just
    pkgs.cargo-audit
    pkgs.sqlite
    pkgs.pkg-config
    pkgs.cargo-tauri
    pkgs.nodejs_22
    pkgs.pnpm
    pkgs.rustup
  ];

  env.LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";

  # Rustup/Cargo state lives inside the project tree for a hermetic, per-project
  # toolchain installation. enterShell (below) prepends CARGO_HOME/bin to PATH.
  # languages.rust is intentionally absent: Nix's rust-default package does not
  # ship iOS target stdlibs; rustup reads rust-toolchain.toml and installs them.
  env.RUSTUP_HOME = "${config.devenv.root}/.devenv/state/rustup";
  env.CARGO_HOME  = "${config.devenv.root}/.devenv/state/cargo";

  # Relay dev configuration — override any of these in devenv.local.nix.
  env.EZPDS_CONFIG = "${config.devenv.root}/relay.dev.toml";
  env.EZPDS_DATA_DIR = "${config.devenv.root}/.devenv/state/relay";
  env.EZPDS_PUBLIC_URL = "http://localhost:8080";
  env.RUST_LOG = "info";

  # Signing key master key for local development.
  # DO NOT USE IN PRODUCTION.
  env.EZPDS_SIGNING_KEY_MASTER_KEY = "2a55ebbdb7c0a4864a3944a443765b13602c6fbbeda38c2d6afc57b96663810e";

  enterShell = ''
    # Nix's Darwin setup hooks (xcbuild, apple-sdk) override DEVELOPER_DIR to a
    # Nix SDK stub that has no runtime tools. Re-export here so this shell and all
    # processes it spawns (cargo tauri ios dev, xcodebuild, xcrun, simctl) use the
    # real Xcode installation. enterShell runs after all Nix hooks, so it wins.
    export DEVELOPER_DIR="/Applications/Xcode.app/Contents/Developer"
    export PATH="$CARGO_HOME/bin:$PATH"
    if ! "$CARGO_HOME/bin/cargo" --version > /dev/null 2>&1; then
      echo "Installing Rust toolchain (first time — reads rust-toolchain.toml)…"
      rustup toolchain install
    fi
  '';

  processes.relay = {
    exec = ''
      export PATH="$CARGO_HOME/bin:$PATH"
      exec cargo run --package relay
    '';
  };
}
