# ADR-0017: One global admin device key across N relays, in a single pairing document

- **Status:** Accepted
- **Date:** 2026-07-06
- **Deciders:** ezpds maintainers
- **Related:** [design plan](../../design-plans/2026-07-06-admin-multi-server.md) · [ADR-0005](0005-functional-core-imperative-shell.md)

## Context

The Brass Console (admin-companion) originally bound the device to exactly one relay: a fixed keychain triple (`admin-device-id`, `admin-relay-url`, `admin-device-label`) overwritten on every pair. One operator running staging and production needs pairings to several relays at once, which forces two decisions: how many device keys exist, and how multi-pairing state is stored and selected.

## Decision

**One global admin device key, registered independently with each relay.** The P-256 admin key is generated once per install and never leaves the device — Secure-Enclave-backed on real iOS hardware, with a software P-256 fallback on macOS and the simulator, where no Enclave exists (see `device_key.rs`). Pairing with a relay registers the same public key with that relay; each relay only ever knows "this public key is registered with me". Relays never learn about each other, and revocation is per-relay by design: revoking the credential on staging leaves production intact, and killing a lost device everywhere means revoking on each relay it was paired with.

**All pairings in one versioned JSON keychain item with a Rust-owned active pointer.** A single `kSecClassGenericPassword` item (account `admin-pairings`, service `ezpds-admin-companion`) holds `{ version, active, pairings[] }`. Entries are keyed by a locally generated UUID (relay-assigned device ids change on re-pair; URLs can repeat). Every mutation is read-modify-write of the whole document ending in one atomic keychain write, with the invariants (active always references an existing entry; auto-promote on removal only when unambiguous) enforced by a pure Rust module. Zero-argument commands like `generate_claim_code` resolve the active pairing on the Rust side, so the server identity the UI shows and the server actually acted on cannot diverge. A document that fails to parse or validate is a hard, loud error — never a silent reset, which would be indistinguishable from a successful unpair. A future format change bumps `version` and ships a deliberate migration.

## Consequences

- Pairing to N relays requires zero server-side changes: every route the app calls already accepts the device signature, and each relay independently registers the key.
- A compromise of the one device key is a compromise on every paired relay. Accepted: on real devices the key is hardware-held and non-exportable (development builds on macOS/simulator use a software key), and the response (per-relay revoke) is the same operation the app already ships.
- Whole-document rewrite per mutation is trivially cheap at the intended scale (2–5 pairings) and avoids the orphan/partial-write risk of dynamic per-pairing keychain items, which would also need raw `security_framework_sys` enumeration.
- The legacy triple is deleted on first load with no migration: existing installs re-pair, and the stale relay-side device entry can be revoked from that relay's device list.

## Alternatives considered

- **Per-relay device keys.** Stronger isolation, but adds Enclave key management and a key-to-relay mapping for no operator-visible gain in a personal tool; the relay's registration model doesn't require it.
- **One keychain item per pairing.** The established `security_framework::passwords` surface has no enumeration; dynamic accounts would need `security_framework_sys` and invite orphaned items on partial writes.
- **Active pointer in UserDefaults.** Splits pairing state across two stores and breaks single-write atomicity; the app deliberately has no UserDefaults plumbing (the biometric preference already lives in the keychain).
- **Frontend-owned active selection.** Passing the target server from the UI into each command makes shown-vs-acted-on divergence possible; resolving in Rust makes it structurally impossible.
