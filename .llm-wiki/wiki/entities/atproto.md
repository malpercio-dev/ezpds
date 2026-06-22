---
type: entity
category: concept
created: 2026-06-22
updated: 2026-06-22
sources: [sources/SRC-2026-06-22-002]
---

# AT Protocol (ATProto)

The AT Protocol — the decentralized social networking protocol behind Bluesky and the ATmosphere. ezpds implements a Personal Data Server (PDS) for ATProto.

## Core Concepts

- **DID (Decentralized Identifier)**: Persistent, cryptographic identity. ezpds uses `did:plc` (a DID method where the identifier is derived from the genesis operation content).
- **Handle**: Human-readable DNS-based identifier (e.g. `alice.ezpds.com`). Resolved via DNS TXT records or `/.well-known/atproto-did`.
- **XRPC**: ATProto's RPC protocol. Methods are namespaced (e.g. `com.atproto.server.createSession`).
- **PDS (Personal Data Server)**: Hosts user data, manages identity, handles authentication.
- **PLC Directory**: Registry for `did:plc` identifiers. Stores signed operation logs.

## ezpds Implementation

The [[entities/relay|Relay Server]] implements:
- Provisioning API (`/v1/...`) for account and DID management
- XRPC endpoints (`com.atproto.server.*`, `com.atproto.identity.*`)
- OAuth 2.0 with DPoP for authentication
- `did:plc` lifecycle (genesis ops, rotation, audit log verification)

## Related

- [[concepts/did-plc|did:plc]]
- [[concepts/did-key|did:key]]
- [[concepts/oauth-dpop|OAuth 2.0 + DPoP]]
- [[entities/relay|Relay Server]]
- [[entities/plc-directory|PLC Directory]]
