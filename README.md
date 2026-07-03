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
- **A crypto library** ([`crates/crypto`](crates/crypto/)) — P-256 key generation, `did:key` derivation, AES-256-GCM encryption, and full `did:plc` lifecycle support (genesis ops, rotation ops, audit log verification, CID computation).
- **Obsign**, an iOS identity wallet ([`apps/identity-wallet`](apps/identity-wallet/)) — a Tauri v2 app (SvelteKit 2 + Svelte 5 frontend, Rust backend) that walks users through account creation, DID ceremony, handle registration, and identity recovery. Keys are backed by the device Secure Enclave.

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
| `crates/repo-engine` | MST construction, CAR file storage, commit construction | **Stub** — not yet implemented |
| `apps/identity-wallet` | Tauri v2 iOS app (SvelteKit 2 + Svelte 5) | **Active** — account creation, DID ceremony, handle registration, OAuth, PLC monitoring, recovery |

### PDS endpoints

**Provisioning API** (`/v1/...`):
- `POST /v1/accounts` — Create account
- `POST /v1/accounts/mobile` — Create mobile account (with device key)
- `POST /v1/accounts/sessions` — Create provisioning session
- `POST /v1/accounts/claim-codes` — Issue claim codes
- `POST /v1/dids` — Create DID (submit signed genesis op)
- `GET /v1/dids/:did` — Get DID document
- `POST /v1/handles` — Register handle
- `DELETE /v1/handles/:handle` — Delete handle
- `POST /v1/devices` — Register device
- `GET /v1/devices/:id/pds` — Get device PDS
- `GET/POST /v1/pds/keys` — Manage PDS signing keys

**XRPC** (ATProto standard):
- `com.atproto.server.createSession` / `getSession` / `refreshSession` / `deleteSession`
- `com.atproto.server.describeServer`
- `com.atproto.server.requestPasswordReset` / `resetPassword`
- `com.atproto.identity.resolveHandle`
- Catch-all `/:method` — returns `MethodNotImplemented` for unimplemented NSIDs

**OAuth 2.0** (with DPoP):
- `GET /.well-known/oauth-authorization-server`
- `GET/POST /oauth/authorize`
- `POST /oauth/par` (Pushed Authorization Request)
- `POST /oauth/token`
- `GET /oauth/client-metadata.json`
- `GET /oauth/jwks`

**Well-known**:
- `GET /.well-known/atproto-did` — DID document

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
cargo build -p pds          # Build just the PDS binary
nix build .#pds --accept-flake-config  # Build via Nix (output: ./result/bin/pds)
```

### Run the PDS

```bash
# Create a config file (see pds.dev.toml for an example)
cargo run -p pds -- --config pds.toml
```

### Run checks

```bash
just ci          # Full CI pipeline: fmt-check + clippy + test + cargo audit
just test        # Run all tests
just clippy      # Lint (warnings as errors)
just fmt-check   # Check formatting
just nix-check   # Validate NixOS module / flake structure
```

### Docker (Linux only)

```bash
nix build .#docker-image --accept-flake-config
docker load < result
```

On macOS, use a remote Linux builder or CI.

## Configuration

The PDS is configured via a TOML file (default: `pds.toml`). See [`pds.dev.toml`](pds.dev.toml) for a full example.

Key settings:
- `bind_address` / `port` — Listen address
- `database_url` — SQLite path (default: `./relay.db`)
- `public_url` — The PDS's public-facing URL
- `available_user_domains` — Handle domains users can register (e.g. `["ezpds.com"]`)
- `invite_code_required` — Whether claim codes are required for account creation
- `admin_token` — Token for management endpoints
- `oauth` — OAuth 2.0 configuration
- `telemetry` — OpenTelemetry trace export

## Project status

ezpds is under active development. The PDS server and crypto library are functional; the iOS identity wallet is in development. Key capabilities:

**Working now:**
- Account creation (desktop + mobile flows)
- DID creation (`did:plc`) with device-backed keys
- Handle registration and resolution
- Session management (JWT + refresh tokens)
- OAuth 2.0 with DPoP
- Password reset flow
- PDS signing key management
- Shamir secret sharing for recovery
- OpenTelemetry observability

**In progress / planned** (see [Linear project](https://linear.app)):
- Wave 4: Blob upload/download, blob garbage collection
- Wave 5: Federation — firehose, subscribeRepos, getRepo, requestCrawl
- Wave 6: App proxy — catch-all to appview, preferences, chat proxy
- Wave 7: Hardening — interop tests, cargo-audit, provisioning transfer endpoints, Tauri IPC lockdown

## License

See [LICENSE](LICENSE) for details.
