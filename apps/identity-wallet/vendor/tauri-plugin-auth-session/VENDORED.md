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
- `src/apple.rs`: a `// SAFETY:` comment on every `unsafe` block, and three blocks replaced with
  safe code: the presentation anchor takes its `MainThreadMarker` from `self.mtm()`, the iOS
  scene lookup uses a checked `downcast_ref::<UIWindowScene>()` instead of an unchecked pointer
  cast, and the macOS refocus uses the checked `MainThreadMarker::new()`. The plugin is not a
  workspace member, so clippy's `undocumented_unsafe_blocks` never reaches it — a re-vendor has
  to carry these by hand.

To update: re-copy from a newer pinned commit, re-apply the local modifications above, and
re-audit `src/apple.rs` + `src/lib.rs`.
