---
type: source
title: "ATProto DID:PLC CBOR Signing Requirements"
slug: atproto-did-plc-cbor-signing
status: insight
created: 2026-06-22
updated: 2026-06-22
category: architecture
---
# ATProto DID:PLC CBOR Signing Requirements
When building DID:PLC operations for plc.directory:

1. **Use @atproto/crypto P256Keypair** — custom Node.js crypto signing fails with "Invalid signature" even with correct CBOR encoding. The official library produces 64-byte raw signatures (r||s) that plc.directory accepts.

2. **DAG-CBOR encoding** — plc.directory verifies signatures against DAG-CBOR-encoded unsigned operations. Both Rust ciborium and TypeScript @ipld/dag-cbor produce compatible encodings with length-first map key ordering.

3. **Compressed P-256 keys** — did:key encoding requires compressed 33-byte public keys (prefix 0x02/0x03 based on y parity), not uncompressed 65-byte keys.

4. **rotationKeys array** — must contain BOTH rotation_key and signing_key entries (even if same key), matching Rust crate behavior.

See [[atproto-did-plc-cbor-encoding]] for detailed encoding analysis.
*Category: architecture*
---
*Captured: 2026-06-22*
## Related
_Add links to related pages._