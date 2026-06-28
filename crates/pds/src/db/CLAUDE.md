# Database Module

Last verified: 2026-03-25

## Latest Updates
- **V025**: Adds the admin-device data model for the operator companion app — three tables: `admin_pairing_codes` (single-use, short-TTL enrollment codes), `admin_devices` (per-device public keys as `did:key`, with a `scopes` growth hook defaulting to `full`), and `admin_nonces` (seen request nonces for anti-replay, FK→`admin_devices`). Status is derived, not stored (matching `claim_codes` V004): a pairing code is *pending* while `consumed_at IS NULL AND expires_at > now`; a device is *active* while `revoked_at IS NULL`. Query functions live in `admin_devices.rs`; no route wires them yet (Phase 3+).
- **V024**: Adds nullable `delete_after` TEXT column to `accounts` — records the optional `deleteAfter` instant from `com.atproto.server.deactivateAccount` (a requested permanent-deletion time). Set alongside `deactivated_at` on deactivation and cleared on reactivation; the reaper that acts on it is not yet implemented. `deactivated_at` (V008) records *that* an account is deactivated; this records *when it asked to be deleted*.
- **V023**: Adds `account_preferences` table (WITHOUT ROWID, keyed by `did`): a single JSON blob per account holding the user's `app.bsky` preferences array, stored locally on the PDS (user data sovereignty) instead of being proxied to the AppView. `updated_at` tracks the last write; FK→`accounts(did)`.
- **V022**: Adds `iroh_identity` table (WITHOUT ROWID, single-row, keyed by UUID id) storing the PDS's Iroh node Ed25519 secret key, AES-256-GCM encrypted with the signing-key master key (same scheme as `oauth_signing_key` (V012) and `jwt_signing_secret` (V015)). Keeps the PDS's Iroh node id stable across restarts.
- **V014**: Adds `password_reset_tokens` table: `token_hash` TEXT PK (SHA-256 hex digest — plaintext never stored), `did` TEXT (FK→accounts), `expires_at` TEXT (1-hour TTL, SQLite datetime), `used_at` TEXT nullable (set on consumption), `created_at` TEXT; index on `did`
- **V013**: Seeds the identity-wallet as a registered OAuth client (`dev.malpercio.identitywallet`) with native application type, DPoP-bound tokens, and custom URL scheme redirect URI (`dev.malpercio.identitywallet:/oauth/callback`); uses INSERT OR IGNORE for idempotency
- **V012**: Adds nullable `jkt` TEXT column to `oauth_tokens` (DPoP key thumbprint for DPoP-bound refresh tokens); creates `oauth_signing_key` table (WITHOUT ROWID, single-row, stores the server's persistent ES256 keypair with AES-256-GCM-encrypted private key)
- **V011**: Adds nullable `pending_share_{1,2,3}` TEXT columns to `pending_accounts` — stores pre-generated Shamir shares alongside `pending_did` so retried DID ceremony requests return the same shares (prevents Share 2 orphaning in accounts.recovery_share)
- **V010**: Adds nullable `recovery_share` column to `accounts` — stores Share 2 of the Shamir 2-of-3 split for PDS-side custody; base32-encoded (52 chars); NULL for pre-Shamir accounts
- **V009**: Rebuilt sessions with nullable device_id (devices are deleted at DID promotion) and added token_hash UNIQUE column for Bearer token authentication (same SHA-256 hex pattern as pending_sessions)
- **V008**: Rebuilt accounts with nullable password_hash (mobile accounts have no password); added pending_did column to pending_accounts for DID pre-store retry resilience

## Purpose
Owns SQLite connection lifecycle and schema migration for the PDS's server-level database.
Keeps database concerns out of handler code and provides a reusable pool+migration API
that can later serve per-user SQLite databases (Wave 3/4).

## Contracts
- **Exposes**: `open_pool(url: &str) -> Result<SqlitePool, DbError>`, `run_migrations(pool: &SqlitePool) -> Result<(), DbError>`, `DbError`
- **Guarantees**: Pool uses WAL journal mode and max 1 connection. The schema_migrations bootstrap DDL runs outside any transaction. Pending migrations and their bookkeeping inserts run inside a single transaction per call. Migrations are forward-only and idempotent. `schema_migrations` table tracks applied versions.
- **Expects**: Valid sqlx SQLite URL (e.g. `"sqlite::memory:"`, `"sqlite:path.db"`). Pool must be open before calling `run_migrations`.

## Dependencies
- **Uses**: sqlx (SqlitePool, SqliteConnectOptions), thiserror
- **Used by**: `main.rs` (startup sequence), `app::AppState` (holds the pool), test helpers
- **Boundary**: Handlers never call `open_pool`/`run_migrations` directly; they receive the pool via `AppState.db`

## Key Decisions
- Custom migration runner over sqlx's built-in `migrate!()`: gives control over transaction boundaries and avoids sqlx's `_sqlx_migrations` table
- Single connection pool (`max_connections(1)`): avoids SQLite write contention, sufficient for v0.1
- `open_pool` accepts `&str` (not Config/AppState): keeps the function reusable for future per-user DBs

## Invariants
- Migration SQL files are append-only; never modify an applied migration
- Migration versions are sequential positive integers starting at 1
- WAL mode is always enabled (set via SqliteConnectOptions, not raw PRAGMA)
- Foreign key enforcement is always on (set via SqliteConnectOptions .foreign_keys(true), not raw PRAGMA)

## Key Files
- `mod.rs` - Pool creation, migration runner, DbError, `is_unique_violation` helper, tests
- `accounts.rs` - `AccountRow` + `resolve_identifier` (handle/DID → account lookup); `SessionAccountRow` + `get_session_account` (DID → account + handle + DID doc, used by `getSession`)
- `oauth.rs` - OAuth client lookup, authorization code storage, PAR request storage, token read/write
- `migrations/V001__init.sql` - server_metadata table (WITHOUT ROWID)
- `migrations/V002__auth_identity.sql` - 12 Wave 2 tables: accounts, handles, did_documents, signing_keys, devices, claim_codes, sessions, refresh_tokens, oauth_clients, oauth_authorization_codes, oauth_tokens, oauth_par_requests
- `migrations/V003__relay_signing_keys.sql` - relay_signing_keys table (WITHOUT ROWID, keyed by did:key URI) for operator-level PDS signing keys (not tied to a specific account DID)
- `migrations/V004__claim_codes_invite.sql` - Rebuilds claim_codes: removes DID FK, adds redeemed_at; status derived not stored
- `migrations/V005__pending_accounts.sql` - pending_accounts table: pre-provisioned account slots (id, email, handle, tier, claim_code)
- `migrations/V006__devices_v2.sql` - Rebuilds devices: replaces did FK (accounts) with account_id FK (pending_accounts); adds platform, public_key, device_token_hash; also rebuilds sessions, oauth_tokens, refresh_tokens (cascade due to FK references)
- `migrations/V007__pending_sessions.sql` - pending_sessions table: id, account_id (FK→pending_accounts), device_id (FK→devices), token_hash (UNIQUE), created_at, expires_at; used by POST /v1/accounts/mobile to issue a pre-DID session for the DID-creation step
- `migrations/V008__did_promotion.sql` - Rebuilds accounts with nullable password_hash (mobile accounts have no password); adds pending_did column to pending_accounts for DID pre-store retry resilience
- `migrations/V009__sessions_v2.sql` - Rebuilds sessions: makes device_id nullable (devices are transient, deleted at DID promotion) and adds token_hash UNIQUE column for Bearer token auth via require_session
- `migrations/V010__recovery_shares.sql` - Adds nullable recovery_share TEXT to accounts: stores Share 2 of the Shamir 2-of-3 recovery split (base32, 52 chars); written atomically inside promote_account transaction
- `migrations/V011__pending_shares.sql` - Adds nullable pending_share_{1,2,3} TEXT columns to pending_accounts: idempotent share storage alongside pending_did; all three deleted when pending_accounts row is deleted at promotion
- `migrations/V012__oauth_token_endpoint.sql` - Adds `jkt` TEXT column to oauth_tokens (DPoP thumbprint); creates `oauth_signing_key` table (WITHOUT ROWID, keyed by UUID id) for persistent ES256 keypair storage (public JWK + AES-256-GCM encrypted private key)
- `migrations/V013__identity_wallet_oauth_client.sql` - Seeds identity-wallet OAuth client row (INSERT OR IGNORE): client_id `dev.malpercio.identitywallet`, native app type, DPoP required, custom scheme redirect URI
- `migrations/V014__password_reset_tokens.sql` - Adds `password_reset_tokens` table for `requestPasswordReset`/`resetPassword` flows; token stored as SHA-256 hex hash; 1-hour TTL; `used_at` nullable (status derived: valid = used_at IS NULL AND expires_at > now)
- `migrations/V022__iroh_identity.sql` - Adds `iroh_identity` table (WITHOUT ROWID, single-row, keyed by UUID id): the PDS's Iroh node Ed25519 secret key, AES-256-GCM encrypted with the signing-key master key. Persisted so the published node id (GET /v1/devices/:id/pds) stays stable across restarts
- `migrations/V023__account_preferences.sql` - Adds `account_preferences` table (WITHOUT ROWID, keyed by `did`, FK→accounts): one JSON blob per account storing the `app.bsky.actor.getPreferences`/`putPreferences` array locally on the PDS rather than proxying to the AppView; `updated_at` records the last write
- `migrations/V024__account_delete_after.sql` - Adds nullable `delete_after` TEXT column to `accounts`: the optional `deleteAfter` instant from `com.atproto.server.deactivateAccount`. Set with `deactivated_at` on deactivation, cleared on reactivation; no reaper acts on it yet
- `migrations/V025__admin_devices.sql` - Adds `admin_pairing_codes`, `admin_devices`, `admin_nonces` for the operator companion app's per-device signed-request auth; status derived from timestamp columns (pending/consumed/expired pairing codes; active/revoked devices); `admin_nonces.device_id` FK→`admin_devices(id)` with `idx_admin_nonces_seen_at` for the stale-nonce sweep
- `admin_devices.rs` - Query functions for V025: `insert_pairing_code`/`get_pairing_code`/`consume_pairing_code` (single-use, atomic), `insert_device`/`get_device`/`list_devices`/`revoke_device` (idempotent), `insert_nonce_if_absent` (replay-rejecting) + `sweep_stale_nonces`. Transactional ones are generic over the executor so the Phase 3 register-device flow can consume a code and insert the device atomically
