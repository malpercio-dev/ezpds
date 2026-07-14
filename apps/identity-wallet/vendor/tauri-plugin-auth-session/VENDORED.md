# Vendored: tauri-plugin-auth-session

Source: https://github.com/yanqianglu/tauri-plugin-auth-session
Pinned commit: b335cfff0662d04e468df8e32869c047e6400135 (2026-03-23)
License: MIT OR Apache-2.0 (see LICENSE-MIT / LICENSE-APACHE)

Vendored (not a live git dependency) because it sits in the wallet's auth path and
the upstream is a single-author, pre-release repo — we audit and control the exact
source that ships. `src/apple.rs` (the iOS ASWebAuthenticationSession wrapper) was
reviewed: it bridges the session and returns the callback URL to the caller; it does
not log, store, or transmit the URL/code.

The `guest-js/` npm API is intentionally NOT vendored — the app invokes
`plugin:auth-session|start` directly from `src/lib/ipc/oauth.ts`.

## Local modifications to the upstream source

- `Cargo.toml`: added `publish = false` (this is a private fork that must never be released to
  crates.io under the upstream's name/metadata).

To update: re-copy from a newer pinned commit, re-apply the local modifications above, and
re-audit `src/apple.rs` + `src/lib.rs`.
