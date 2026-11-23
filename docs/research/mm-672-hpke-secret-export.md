# HPKE secret export for the Spaces MAC secret (atproto pull request 5865)

Research for MM-672. Read-only against upstream; nothing upstream was installed or run. The one program run is a throwaway Rust check against the workspace's pinned `hpke` crate (below).

## Sources

- **Code:** `bluesky-social/atproto`, branch `permissioned-data`, head `047d6032a21be01df8447489f0d6b59d2cc60af8` (2026-11-22, "Atproto spaces: reserveKemKey (#5974)").
  - Pull request 5865 ("HPKE Secret Export") merged as `2d4a6736f5ce0202945c5fb794486d3d78d1f85d` (2026-11-12). Branch commits: `f3ba20bc` "hpke secret export", then `a01a4f6c` "update hpke info".
  - Pull request 5862 (HTTP Message Signatures) merged as `f0b61439901691cb1a8f9e0fef322a1f1ffb0894`.
  - Pull request 5864 (notifications) merged as `2b7ce1e48e1a6cc49ac904a49cc85f0eafb79bba`.
  - All three are ancestors of head. `packages/space/src/kem.ts` is unchanged between the 5865 merge and head.
- **Spec:** `bluesky-social/proposals` pull request 142 merged as `78b5e24559d0eb0822e1aafcccec50f19098fb45` (2026-11-12). `0016-permissioned-data/README.md` at `main` `2755e73a`, §"Shared secret" (lines 420–441) and appendix "Shared secret without HPKE" (lines 1049–1078).
- **Vectors:** RFC 9180; CFRG `test-vectors.json` (vendored in the `hpke` 0.14.1 crate as `test-vectors/origrfc-5f503c5.json`).
- **Local:** `crates/crypto/src/hpke.rs`, root `Cargo.toml` `hpke` entry, `hpke-0.14.1` source in the cargo registry.

## The derivation at head

RFC 9180 HPKE, base mode, single-shot secret export (§6.2 `ReceiveExportBase`):

| Parameter | Value | Source |
|---|---|---|
| KEM | `0x0010` DHKEM(P-256, HKDF-SHA256) | `kem.ts` L70–75 |
| KDF | `0x0001` HKDF-SHA256 | `kem.ts` L73 |
| AEAD | `0xFFFF` Export-only | `kem.ts` L75 |
| Mode | `0x00` base, no PSK | `kem.ts` L78, L99 |
| `info` | `"atproto-mac"` | `kem.ts` L64 |
| `exporter_context` | `""` (empty) | `kem.ts` L105 |
| `L` | 32 | `kem.ts` L96, L105 |

```ts
// packages/space/src/kem.ts @ 047d6032, L63-64
// A fixed label tying the secret to this protocol.
const HPKE_INFO = utf8('atproto-mac')
```

**`"atproto-mac"` wins, and it is the HPKE `info`, not the exporter context.** Pull request 5865's first commit (`f3ba20bc`) used `'atproto-space-mac'`; `a01a4f6c` "update hpke info" changed it to `'atproto-mac'` before merge. The MM-672 ticket body was written against the first commit; the 2026-11-13 watch (ezpds pull request 767) has the merged value. The proposal agrees: `shared_secret = ReceiveExportBase(enc, author_private_key, info="atproto-mac", exporter_context="", L=32)` (README L420–441), and its appendix spells out the same labels.

The reference hand-rolls the key schedule over `@atproto/crypto`'s `hkdfExtractSha256`/`hkdfExpandSha256` with no HPKE library (`kem.ts` L83–132). `enc` is the syncer's ephemeral key, carried as a compressed `did:key` in the signature `keyid` and decompressed to HPKE's 65-byte form.

What 5865 did not change: header names, MAC `ver`, the `hmac-sha256` label, the `keyid` format, any lexicon. Only the secret's bytes change. No version field separates the two derivations, so a pre-5865 peer and a post-5865 peer fail each other's MACs silently.

## The vector

`packages/space/src/kem.test.ts` L60–80 at head (moved from `tests/` by `0b92702f3`):

```ts
  // The keys are from the export-only DHKEM(P-256, HKDF-SHA256) entry of the
  // HPKE test vectors (github.com/cfrg/draft-irtf-cfrg-hpke), where the syncer's
  // key share is `enc` and the author's KEM keypair is `skRm`. Those vectors use
  // a different `info`, so the expected secret was computed with Go's
  // crypto/hpke, using `info` "atproto-mac" and an empty exporter context.
  it('matches HPKE secret export', async () => {
    const enc = hex('04d804370b7e24b94749eb1dc8df6d4d4a5d75f9effad01739ebcad5c54a40d57aaa8b4190fc124dbde2e4f1e1d1b012a3bc4038157dc29b55533a932306d8d38d')
    const skRm = hex('62c3868357a464f8461d03aa0182c7cebcde841036aea7230ddc7339f1088346')
    const sharedSecret = hex('2060e0558d1b34c10086bc137f849bb79ba59fcdc30544418e35c9cd301f0d0d')
```

| Input | Value |
|---|---|
| `enc` (pkEm, uncompressed) | `04d804370b7e24b94749eb1dc8df6d4d4a5d75f9effad01739ebcad5c54a40d57aaa8b4190fc124dbde2e4f1e1d1b012a3bc4038157dc29b55533a932306d8d38d` |
| `skRm` (author KEM private key) | `62c3868357a464f8461d03aa0182c7cebcde841036aea7230ddc7339f1088346` |
| `info` | `"atproto-mac"` |
| `exporter_context`, `L` | `""`, 32 |
| **Expected secret** | `2060e0558d1b34c10086bc137f849bb79ba59fcdc30544418e35c9cd301f0d0d` |

Provenance: the keys come from the CFRG `test-vectors.json` entry `mode 0, kem_id 16, kdf_id 1, aead_id 65535`. That entry's `info` is `"Ode on a Grecian Urn"`, and under it the empty-context export is `8cf837d5bf1994f0fac3ee1faa671d07e9a38b7f6153bdbb8a66b90159ef7d13`. The atproto expected value is **self-minted** (the comment credits Go `crypto/hpke`). RFC 9180's body has no P-256 export-only vector. Appendix A.7 is X25519. A.3.1's exports can't be reused either, because `exporter_secret` binds the full suite id including the AEAD id.

The old test at the 2026-11-06 pin (`a620ad3`) used A.3.1's KEM-level `shared_secret` `c0d26aea…`. That vector is now the `kem_secret` intermediate, not the output.

## Does `crates/crypto`'s `hpke` module cover it?

**The crate does, as-is. The module needs one small function.**

- `crates/crypto/src/hpke.rs` is notification sealing: DHKEM(P-256) + HKDF-SHA256 + AES-256-GCM in `mode_auth`, via `single_shot_seal`/`single_shot_open`. No export function.
- The pinned `hpke = 0.14.1` crate (features `alloc, nistp, aes, getrandom`) already has everything needed, with no new feature or dependency:
  - `aead::ExportOnlyAead`: `AEAD_ID = 0xFFFF` (`src/aead/export_only.rs` L59–65), compiled unconditionally (`src/aead.rs` L475).
  - `setup_receiver::<A, Kdf, Kem>(&OpModeR::Base, sk, enc, info)` (`src/setup.rs` L163).
  - `AeadCtxR::export(exporter_ctx, out)` (`src/aead.rs` L241), which is RFC 9180 `LabeledExpand(exporter_secret, "sec", ctx, L)`.
  - Caveat: the crate refuses to compile with no AEAD feature (`src/lib.rs` L110). That doesn't matter here, because `aes` is already on for notifications.
- **Verified by running it.** A throwaway binary linking `hpke =0.14.1` with the workspace's `Cargo.lock` and the same features (minus `getrandom`), calling `setup_receiver::<ExportOnlyAead, HkdfSha256, DhP256HkdfSha256>(Base, skRm, enc, info)` and then `.export(b"", &mut [0u8; 32])`, prints:
  - `info = "Ode on a Grecian Urn"` → `8cf837d5…7d13`, which matches CFRG.
  - `info = "atproto-mac"` → `2060e055…0d0d`, which matches the reference's `kem.test.ts`.
- The derivation is about ten lines next to `seal_notification`: a `pub fn space_mac_secret(kem_private_key: &[u8; 32], enc: &[u8]) -> Result<[u8; 32], CryptoError>` reusing the module's `private_key_from_bytes`/`public_key_from_sec1`-style decoding, plus a `SPACE_MAC_INFO = b"atproto-mac"` constant. The syncer side is `hpke::setup_sender` + export with the same suite. Hand-rolling the key schedule like the reference does would duplicate the library this crate already ships.
- Golden tests to carry: both vectors above. The CFRG one checks the library and suite; the reference one checks the `info` string.

## What this means for the seam swap

MM-671 decided to build today's DHKEM `ExtractAndExpand` behind a `(ephemeral pubkey, KEM private key) → [u8; 32]` seam and swap it when the reference moved. The reference has moved, and both freeze triggers (pull requests 5862 and 5864) have merged.

No KEM derivation exists in the tree yet. Neither `eae_prk`, `decapsulate` nor `atproto_kem` appears under `crates/` or the wallet's `src-tauri`. So nothing has to be swapped. The secret-derivation half of the seam is built as HPKE export from the start, as one implementation task in the KEM/MAC slice. The seam still earns its place for request parsing and response emission, and it keeps the secret behind one function. The old derivation never ships, and no separate swap ticket or post-freeze ticket is needed.

## Upstream nits (not blocking)

- README line 1051 says the appendix "can be checked against the export-only P-256 entry" of the CFRG vectors. It can't directly, because that entry's `info` differs.
- The README's `Accept-Signature` example uses `tag="atproto-space-commit"`, while `mac.ts` uses `COMMIT_MAC_PROFILE = 'atproto-space-repo'`. The reference wins. This belongs to the MAC/signature-base work, not this derivation, and was checked at the 5865 merge only.
