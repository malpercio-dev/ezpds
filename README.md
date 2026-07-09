# ezpds

An easy-to-host [ATProto](https://atproto.com) Personal Data Server (PDS) — designed to be simple to operate and approachable for end users.

## A personal note from the primary human behind this

<!-- no touchy agents -->

This has primarily been a place for me to experiment, to see how far and in what ways I can push the new robot friends, and to see how far and in what ways I can push myself in building a usable product. I'm mostly a backend software dev, but have always fancied myself generalist, I just love technology and building things. I don't know if I personally treat code itself as a puzzle or art, probably more as a means of expressing ideas into usable, real things.

Maybe just a nice way of saying _caveat emptor_, what you may call "slop" may reside here. I am not yet using this for my primary atprotocol identity, although I hope to get there. I do not necessarily recommend running this yourself in production, but if you are interested in trying it, I welcome you! I don't know that any of this code is idiomatic, well-factored Rust, or well-designed frontends, these are new skills to me, but if you are interested in participating in this experimentation and contributing, again I welcome you!

Keep building y'all. <3

\- Malpercio

<!-- end no touchy agents -->

## What is this?

ezpds is a self-hosted PDS implementation for the AT Protocol (the protocol behind Bluesky and the ATmosphere). It provides:

- **A PDS server** ([`crates/pds`](crates/pds/)) — an Axum-based HTTP server that implements the ATProto provisioning API, XRPC endpoints, and OAuth 2.0 flows. It stores accounts, DIDs, handles, and signing keys in SQLite.
- **A repo engine** ([`crates/repo-engine`](crates/repo-engine/)) — the ATProto repository core: MST construction, CAR export/import, genesis repo creation, record CRUD, and commit signing, consumed by the PDS.
- **A crypto library** ([`crates/crypto`](crates/crypto/)) — P-256 key generation, `did:key` derivation, AES-256-GCM encryption, and full `did:plc` lifecycle support (genesis ops, rotation ops, audit log verification, CID computation).
- **Obsign**, an iOS identity wallet ([`apps/identity-wallet`](apps/identity-wallet/)) — a Tauri v2 app (SvelteKit 2 + Svelte 5 frontend, Rust backend) that walks users through account creation, DID ceremony, handle registration, and identity recovery. Keys are backed by the device Secure Enclave.
- **An admin companion** ([`apps/admin-companion`](apps/admin-companion/)) — a second Tauri v2 iOS app: a terminal-native operator console for the PDS operator (claim codes, admin device pairing/revocation via Secure-Enclave-signed requests).

Supporting pieces: [`sites/marketing/`](sites/marketing/) (zero-build static marketing site for Obsign + Custos), [`tools/interop/`](tools/interop/) (interop CLI that exercises a live deployment against the real ATProto network), [`tools/mcp/`](tools/mcp/) (Custos MCP — a first-party MCP server that onboards itself to a Custos PDS through the auth.md agent flow, then exposes the PDS as tools to AI agents), [`bruno/`](bruno/) (HTTP request collection covering every route, CI-enforced parity), and [`docs/architecture/`](docs/architecture/) (living architecture docs + the ADR log).

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Obsign (iOS)                                           │
│  Tauri v2 · SvelteKit · Secure Enclave keys             │
│                                                         │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐   │
│  │ Account     │  │ DID Ceremony │  │ OAuth Client  │   │
│  │ Creation    │  │ (did:plc)    │  │ (DPoP)        │   │
│  └──────┬──────┘  └──────┬───────┘  └───────┬───────┘   │
└─────────┼────────────────┼──────────────────┼───────────┘
          │                │                  │
          ▼                ▼                  ▼
┌─────────────────────────────────────────────────────────┐
│  Custos (crates/pds)                                    │
│  Axum · SQLite · sqlx                                   │
│                                                         │
│  Provisioning API    XRPC Endpoints    OAuth 2.0        │
│  /v1/accounts        com.atproto.*     /oauth/*         │
│  /v1/dids            (catch-all)       DPoP + JWKS      │
│  /v1/handles                                            │
│  /v1/devices         Auth (JWT + Argon2id)              │
│                      Handle resolution (DB + DNS + HTTP)│
└─────────────────────────────────────────────────────────┘
```

### Crates

| Crate | Purpose | Status |
|-------|---------|--------|
| `crates/pds` | ATProto PDS server — provisioning API, XRPC, OAuth, auth | **Active** — primary development focus |
| `crates/crypto` | P-256 keys, did:key, did:plc genesis/rotation, Shamir secret sharing, AES-256-GCM | **Complete** — well-tested |
| `crates/common` | Shared config, error types, serde utilities | **Complete** |
| `crates/repo-engine` | MST construction, CAR export/import, genesis, record CRUD, commit signing | **Functional** — consumed by `crates/pds` |
| `apps/identity-wallet` | Tauri v2 iOS app (SvelteKit 2 + Svelte 5) | **Active** — account creation, DID ceremony, handle registration, OAuth, PLC monitoring, recovery |
| `apps/admin-companion` | Tauri v2 iOS operator console ("Brass Console") | **Active** — pairing, claim codes, device revocation |

### PDS endpoints

The route surface is large; the exhaustive, kept-current route table lives in
[`crates/pds/CLAUDE.md`](crates/pds/CLAUDE.md), and every route has a matching
request in the [`bruno/`](bruno/) collection (CI-enforced parity via
`just bruno-check`). In summary:

- **Provisioning API** (`/v1/...`) — accounts (desktop + mobile flows), claim
  codes, DIDs, handles, devices, PDS signing keys, admin device
  pairing/revocation, account transfer, usage/storage.
- **XRPC** — the `com.atproto.{server,repo,sync,identity,admin,temp}.*`
  surface: sessions and app passwords, record CRUD + `applyWrites`, blob
  upload/download with GC, repo export/import (CAR), the firehose
  (`subscribeRepos`), handle/DID resolution, PLC operation signing, and the
  admin takedown surface.
- **Service proxy** — catch-all dispatches `app.bsky.*` and
  `com.atproto.moderation.*` to the AppView (with read-after-write munging for
  the account's own writes) and `chat.bsky.*` to the chat service; unmatched
  NSIDs return `MethodNotImplemented`. `app.bsky.actor.{get,put}Preferences`
  are served locally.
- **OAuth 2.0** (with DPoP) — authorization-server metadata, `authorize`, PAR,
  `token`, client metadata, JWKS.
- **Well-known** — `atproto-did`, `oauth-authorization-server`,
  `oauth-protected-resource`.

### Obsign (iOS)

The mobile app guides users through:

1. **PDS configuration** — Connect to an ezpds PDS instance
2. **Account creation** — Claim code → email + handle → device key registration
3. **DID ceremony** — Build and sign a `did:plc` genesis op using the device Secure Enclave, submit to PDS, receive Shamir recovery shares
4. **Handle registration** — Register a handle on the PDS's domain
5. **OAuth login** — Authenticate with the PDS via OAuth 2.0 + DPoP
6. **Identity management** — Multi-identity home, DID document display, rotation key status
7. **PLC monitoring** — Periodic audit log checks for unauthorized DID changes
8. **Recovery** — Shamir secret sharing (3 shares, 2-of-3 threshold) with iCloud Keychain backup

## Getting started

### Prerequisites

This project uses a **Nix flake + devenv** development environment. All tools (Rust toolchain, SQLite, Node.js, pnpm, just, etc.) are managed by Nix — do not install them globally.

### Setup

```bash
# Enter the dev shell (--impure for devenv CWD detection, --accept-flake-config for Cachix binary cache)
nix develop --impure --accept-flake-config

# Or use direnv (auto-activates on cd)
direnv allow
```

On first shell entry, `rustup toolchain install` runs automatically.

### Build

```bash
cargo build                   # Build all crates
cargo build -p pds            # Build just the PDS binary
```

The flake intentionally exposes no package outputs — the PDS ships as an OCI
image built by the root [`Dockerfile`](Dockerfile), not a Nix-built binary
(see [ADR-0008](docs/architecture/decisions/0008-pds-as-oci-image-not-nix-built.md)).

### Run the PDS

```bash
# Create a config file (see pds.dev.toml for an example)
cargo run -p pds -- --config pds.toml
```

### Run checks

```bash
just ci          # Full local gate: fmt-check, lock-check, bruno-check, font-check, swift-rs-check, clippy, test, audit
just test        # Run all tests
just clippy      # Lint (warnings as errors)
just fmt-check   # Check formatting
just nix-check   # Validate NixOS module / flake structure
```

### Docker

```bash
docker build -t pds .    # or: just docker-build
```

## Configuration

The PDS is configured via a TOML file (default: `pds.toml`). See [`pds.dev.toml`](pds.dev.toml) for a full example.

Key settings:
- `bind_address` / `port` — Listen address
- `data_dir` — Required; root for on-disk state
- `database_url` — SQLite path (default: `{data_dir}/relay.db`)
- `public_url` — The PDS's public-facing URL
- `available_user_domains` — Handle domains users can register (e.g. `["obsign.org"]`)
- `invite_code_required` — Whether claim codes are required for account creation
- `admin_token` — Token for management endpoints
- `blobs` — Blob size/quota limits, GC interval, temp-blob TTL
- `appview` / `chat` — Service-proxy targets (AppView URL/DID/CDN, chat service)
- `crawlers` — Relay hosts to notify via `requestCrawl`
- `rate_limit` — Global, per-endpoint, and per-account write-point limits
- `telemetry` — OpenTelemetry trace export

See [`pds.dev.toml`](pds.dev.toml) and `crates/common/src/config.rs` for the full set.

## Project status

ezpds is under active development. The PDS server, repo engine, and crypto library are functional and deployed; both iOS apps are active. Key capabilities:

**Working now:**
- Account creation (desktop + mobile flows)
- DID creation (`did:plc`) with device-backed keys
- Handle registration and resolution
- Session management (JWT + refresh tokens), app passwords
- OAuth 2.0 with DPoP
- Repo records — full CRUD, `applyWrites`, CAR export/import
- Blob upload/download with garbage collection
- Federation — firehose (`subscribeRepos` with durable sequencer), `getRepo`, `requestCrawl`
- App proxy — AppView/chat proxying with read-after-write for the account's own writes
- Interop test CLI ([`tools/interop/`](tools/interop/)) exercising a live deployment against the real ATProto network
- Agent auth (auth.md) — agent registration, human claim ceremony, JWT-bearer exchange, granular scopes — with a first-party MCP server ([`tools/mcp/`](tools/mcp/)) that onboards itself through that flow
- PDS signing key management, provisioning transfer endpoints
- Shamir secret sharing for recovery
- OpenTelemetry observability

**In progress / planned** (Linear is the live source of truth):
- Firehose Sync v1.1 residuals (per-op `prev` CIDs)
- Account migration (PDS↔PDS, inbound + outbound "credible exit")
- Outbound email delivery + email confirmation endpoints
- OAuth granular auth scopes + permission sets
- Tauri IPC lockdown
- Wave 8: auth.md agentic auth (agent identity, claim ceremony, JWT-bearer grants)

## License

See [LICENSE](LICENSE) for details.
