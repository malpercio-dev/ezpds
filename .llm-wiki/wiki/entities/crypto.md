---
type: entity
category: project
created: 2026-06-22
updated: 2026-06-22
sources: [sources/SRC-2026-06-22-001, sources/SRC-2026-06-22-002, sources/SRC-2026-06-22-004]
---

# Crypto Crate

A pure [[concepts/functional-core-imperative-shell|Functional Core]] providing cryptographic primitives for the [[concepts/ezpds-workspace|ezpds workspace]]. No I/O, no database, no config.

## Purpose

Provides P-256 key generation, `did:key` derivation, AES-256-GCM encryption/decryption of private key material, [[concepts/shamir-secret-sharing|Shamir Secret Sharing]] for DID rotation key recovery, and [[concepts/did-plc|did:plc]] genesis operation building and verification.

## Public API

| Function | Purpose |
|----------|---------|
| `generate_p256_keypair()` | Fresh P-256 keypair from OS RNG |
| `encrypt_private_key(secret, master_key)` | AES-256-GCM encrypt (80 base64 chars) |
| `decrypt_private_key(ciphertext, master_key)` | AES-256-GCM decrypt |
| `split_secret(secret)` | Shamir 2-of-3 split |
| `combine_shares(share1, share2)` | Reconstruct from 2 shares |
| `build_did_plc_genesis_op(...)` | Build signed did:plc genesis op |
| `build_did_plc_genesis_op_with_external_signer(...)` | Same, with signing callback for Secure Enclave |
| `verify_genesis_op(signed_op_json, rotation_key)` | Verify signed genesis op signature |

## Key Design Decisions

- **External signer support**: `build_did_plc_genesis_op_with_external_signer` accepts a `FnOnce(&[u8]) -> Result<Vec<u8>, CryptoError>` callback, enabling signing with non-extractable keys (Apple [[entities/secure-enclave|Secure Enclave]]).
- **Zeroizing everywhere**: Private key bytes and Shamir shares are always `Zeroizing<[u8; 32]>` — zeroed on drop.
- **Information-theoretic Shamir**: A single share reveals nothing about the secret. GF(2^8) uses AES irreducible polynomial (0x11b).
- **Deterministic DID derivation**: Same inputs → same DID (RFC 6979 ECDSA + SHA-256 + base32).

## Key Files

- `src/lib.rs` — Re-exports public API
- `src/keys.rs` — P-256 key generation, AES-256-GCM encrypt/decrypt
- `src/plc.rs` — did:plc genesis operation builder and verifier
- `src/shamir.rs` — Shamir Secret Sharing (split/combine, GF(2^8) arithmetic)
- `src/error.rs` — CryptoError enum

## Dependencies

**Uses**: p256, aes-gcm, multibase, rand_core, base64, zeroize, ciborium, data-encoding, sha2, serde/serde_json

**Used by**: [[entities/relay|Relay]] (key generation, did:plc genesis building and verification), [[entities/identity-wallet|Identity Wallet]] (external signer genesis op building in DID ceremony)

## Related

- [[concepts/did-plc|did:plc]]
- [[concepts/did-key|did:key]]
- [[concepts/shamir-secret-sharing|Shamir Secret Sharing]]
- [[concepts/external-signer|External Signer Pattern]]
- [[sources/SRC-2026-06-22-004]] — Full API documentation
