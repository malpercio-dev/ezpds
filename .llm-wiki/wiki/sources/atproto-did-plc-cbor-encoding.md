---
type: source
title: "DID:plc CBOR encoding interop issue"
slug: atproto-did-plc-cbor-encoding
status: insight
created: 2026-06-22
updated: 2026-06-22
category: architecture
---
# DID:plc CBOR encoding interop issue
The did:plc signature verification requires CBOR encoding of the unsigned operation. The Rust `ciborium` crate and TypeScript `@ipld/dag-cbor` produce different CBOR encodings for the same input, causing signature verification failures at plc.directory.

Key findings:
- PLC directory expects the signature to be over CBOR-encoded unsigned op
- Rust crate uses compressed P-256 public keys (33 bytes) for did:key
- Multicodec prefix for P-256 is `[0x80, 0x24]` (LEB128 for 0x1200)
- `rotationKeys` array must contain both rotation and signing keys (even if same)
- DAG-CBOR canonical ordering: sort by key byte length, then alphabetically

The TypeScript extension at `.pi/extensions/atproto/` has the crypto primitives implemented but needs CBOR interop debugging for the DID ceremony to work end-to-end.
*Category: architecture*
---
*Captured: 2026-06-22*
## Related
_Add links to related pages._