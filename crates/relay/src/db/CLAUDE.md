# Database Module

Last verified: 2026-03-11

## Purpose
Owns SQLite connection lifecycle and schema migration for the relay's server-level database.
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
- `mod.rs` - Pool creation, migration runner, DbError, tests
- `migrations/V001__init.sql` - server_metadata table (WITHOUT ROWID)
- `migrations/V002__auth_identity.sql` - 12 Wave 2 tables: accounts, handles, did_documents, signing_keys, devices, claim_codes, sessions, refresh_tokens, oauth_clients, oauth_authorization_codes, oauth_tokens, oauth_par_requests
- `migrations/V003__relay_signing_keys.sql` - relay_signing_keys table (WITHOUT ROWID, keyed by did:key URI) for operator-level relay signing keys (not tied to a specific account DID)
