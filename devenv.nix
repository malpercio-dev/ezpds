{ pkgs, config, ... }:
{
  packages = [
    pkgs.just
    pkgs.cargo-audit
    # cargo-deny: dependency license + supply-chain gate (`just deny`, policy in deny.toml).
    # Complements cargo-audit (advisories) — CI runs both, so the dev shell provides both.
    pkgs.cargo-deny
    # jq: used by just recipes (verify-release-tag, the ios-ipa/admin-ipa build-number
    # stamp). CI runners preinstall it; the dev shell must provide it too.
    pkgs.jq
    pkgs.sqlite
    pkgs.pkg-config
    # cmake: builds aws-lc-sys, the crypto provider behind reqwest 0.13's rustls
    # TLS backend (needed for host builds and the iOS cross-compile alike).
    pkgs.cmake
    pkgs.cargo-tauri
    pkgs.nodejs_22
    # pnpm major pinned to 9 to match CI (pnpm/action-setup, version 9.15.9) and the
    # "packageManager" field in apps/*/package.json — a different major regenerates
    # pnpm-lock.yaml in a format that fails CI's `pnpm install --frozen-lockfile`.
    pkgs.pnpm_9
    pkgs.rustup
    pkgs.shellcheck
  ];

  env.LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";

  # Rustup/Cargo state lives inside the project tree for a hermetic, per-project
  # toolchain installation. enterShell (below) prepends CARGO_HOME/bin to PATH.
  # languages.rust is intentionally absent: Nix's rust-default package does not
  # ship iOS target stdlibs; rustup reads rust-toolchain.toml and installs them.
  env.RUSTUP_HOME = "${config.devenv.root}/.devenv/state/rustup";
  env.CARGO_HOME  = "${config.devenv.root}/.devenv/state/cargo";

  # PDS dev configuration — override any of these in devenv.local.nix.
  env.EZPDS_CONFIG = "${config.devenv.root}/pds.dev.toml";
  env.EZPDS_DATA_DIR = "${config.devenv.root}/.devenv/state/relay";
  env.EZPDS_PUBLIC_URL = "http://localhost:8080";
  env.RUST_LOG = "info";

  # Signing key master key for local development.
  # DO NOT USE IN PRODUCTION.
  env.EZPDS_SIGNING_KEY_MASTER_KEY = "2a55ebbdb7c0a4864a3944a443765b13602c6fbbeda38c2d6afc57b96663810e";

  enterShell = ''
    export PATH="$CARGO_HOME/bin:$PATH"
    # Apple toolchain for iOS cross-compilation, derived dynamically via xcrun/
    # xcode-select (no hardcoded Xcode paths). Also sets DEVELOPER_DIR, which Nix's
    # Darwin hooks otherwise clobber to a stub SDK. enterShell runs after all Nix
    # hooks, so this wins. Same script is sourced by the Xcode Run Script phase
    # (patched by apps/identity-wallet/scripts/ios-postinit.sh) so CLI and
    # Xcode-driven builds resolve the toolchain identically.
    if [ -f "${config.devenv.root}/apps/identity-wallet/scripts/ios-env.sh" ]; then
      source "${config.devenv.root}/apps/identity-wallet/scripts/ios-env.sh"
    fi
    if ! "$CARGO_HOME/bin/cargo" --version > /dev/null 2>&1; then
      echo "Installing Rust toolchain (first time — reads rust-toolchain.toml)…"
      rustup toolchain install
    fi
  '';

  processes.pds = {
    exec = ''
      export PATH="$CARGO_HOME/bin:$PATH"
      exec cargo run --package pds
    '';
  };
}
