---
type: source
title: "Use @atproto/crypto for DID:plc signatures"
slug: atproto-crypto-use-official-library
status: insight
created: 2026-06-22
updated: 2026-06-22
category: architecture
---
# Use @atproto/crypto for DID:plc signatures
The TypeScript extension's custom P-256 signing implementation produced signatures that plc.directory rejected. Root cause: Node.js `crypto.sign()` returns DER-encoded ECDSA signatures, and even after converting to raw 64-byte format, the signatures were incompatible with plc.directory's verification.

**Fix:** Use the official `@atproto/crypto` package (`P256Keypair`) for key generation and signing. This produces signatures that are byte-compatible with the ATProto ecosystem.

Key learnings:
- `@atproto/crypto` `P256Keypair.create({ exportable: true })` generates keys
- `keypair.sign(unsignedBytes)` returns raw 64-byte Uint8Array (not DER)
- `keypair.did()` returns the `did:key:z...` identifier
- `keypair.export()` returns raw 32-byte private key as Uint8Array
- The `@ipld/dag-cbor` library for CBOR encoding is compatible — the issue was only with signing
*Category: architecture*
---
*Captured: 2026-06-22*
## Related
_Add links to related pages._