---
type: concept
domain: engineering
created: 2026-06-22
updated: 2026-06-22
sources: [sources/SRC-2026-06-22-002, sources/SRC-2026-06-22-004]
---

# did:plc

A DID (Decentralized Identifier) method used by ATProto. The identifier is cryptographically derived from the genesis operation content — same inputs always produce the same DID.

## Format

`did:plc:[a-z2-7]{24}` — 28 characters total. Derived from SHA-256 of CBOR-encoded signed genesis operation, base32-lowercase, first 24 characters.

## Genesis Operation

A signed JSON document containing:
- `rotationKeys` — Array of P-256 `did:key` URIs (user's device key + relay's signing key)
- `verificationMethods` — Maps method names to `did:key` URIs (e.g. `atproto` → relay signing key)
- `alsoKnownAs` — Array of `at://` URIs (user's handle)
- `services` — Map of service endpoints (e.g. `atproto_pds` → relay URL)
- `prev` — null for genesis (links to previous op for rotations)
- `sig` — ECDSA-SHA256 signature (base64url, no padding, 64 bytes r‖s, low-S canonical)

## In ezpds

The [[entities/crypto|Crypto Crate]] provides:
- `build_did_plc_genesis_op()` — Build and sign a genesis operation
- `build_did_plc_genesis_op_with_external_signer()` — Same, with signing callback for [[entities/secure-enclave|Secure Enclave]]
- `verify_genesis_op()` — Verify a signed genesis op's signature and extract fields

The [[entities/identity-wallet|Identity Wallet]] performs the DID ceremony:
1. Fetch relay signing key (GET /v1/relay/keys)
2. Build signed genesis op using device key as signer
3. Submit to relay (POST /v1/dids)
4. Receive Shamir recovery shares

## PLC Directory

The PLC Directory (`plc.directory`) is the registry for `did:plc` identifiers. It stores signed operation logs and allows verification of DID history.

## Related

- [[concepts/did-key|did:key]]
- [[concepts/shamir-secret-sharing|Shamir Secret Sharing]]
- [[entities/crypto|Crypto Crate]]
- [[entities/plc-directory|PLC Directory]]
- [[sources/SRC-2026-06-22-004]] — Crypto crate API
