# ADR-0006: OAuth callback via ASWebAuthenticationSession (vendored plugin), not deep links

- **Status:** Accepted
- **Date:** 2026-07-02 (backfilled)
- **Deciders:** ezpds maintainers
- **Related:** [`apps/identity-wallet/CLAUDE.md`](../../../apps/identity-wallet/CLAUDE.md) · [`apps/identity-wallet/vendor/tauri-plugin-auth-session/VENDORED.md`](../../../apps/identity-wallet/vendor/tauri-plugin-auth-session/VENDORED.md)

## Context

The identity-wallet authenticates to PDSes with OAuth 2.0 Authorization Code +
PKCE (RFC 7636) and DPoP-bound tokens (RFC 9449). The flow ends with a redirect
to the app's custom scheme (`dev.malpercio.identitywallet:/oauth/callback?...`)
carrying the authorization code, which the app must capture.

The initial implementation used `tauri-plugin-deep-link` + `on_open_url`. It
**silently failed on iOS**: iOS Safari will not auto-launch an app from a
*server-side* redirect to a custom scheme, so the callback never reached the app.

## Decision

Capture the OAuth callback with **`ASWebAuthenticationSession`**, via a
**vendored** `tauri-plugin-auth-session`. The Rust `prepare_*` command returns the
authorize URL; the frontend calls `plugin:auth-session|start`, which opens the
in-app auth sheet and returns the custom-scheme callback URL directly; the Rust
`complete_*` command validates CSRF state and does the token exchange. The custom
scheme stays registered as the session's `callbackURLScheme`.

The plugin is **vendored** (a path dep, not a live git dependency) because it
sits directly in the authentication path.

## Consequences

- **Reliable callback capture with no app relaunch** — `ASWebAuthenticationSession`
  captures the redirect itself; the PKCE verifier and CSRF state never leave the
  Rust backend.
- **Links `AuthenticationServices.framework`** — enforced by the `ios-postinit`
  `OTHER_LDFLAGS` patch (a staticlib → Xcode link gap; see the wallet CLAUDE.md
  Troubleshooting).
- **Vendoring cost:** we track upstream ourselves and document provenance/audit
  in `VENDORED.md`, accepted because the plugin is security-sensitive.
- Both OAuth flows (create and claim) share this one in-app auth session and the
  `parse_callback_url` helper.

## Alternatives considered

- **`tauri-plugin-deep-link` (custom-scheme deep links).** Rejected: silently
  broken — iOS Safari won't auto-launch the app from a server redirect to a
  custom scheme.
- **Universal Links (`https://` associated domains).** Rejected: requires
  hosting an AASA file and binding to a domain, heavier than the in-app session
  and unnecessary once `ASWebAuthenticationSession` captures the callback.
- **A live git dependency for the plugin.** Rejected for an auth-path component;
  vendoring gives us a pinned, audited copy.
