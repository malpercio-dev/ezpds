---
title: Configuration reference
description: Generated TOML fields and environment controls for Custos operators.
---

> Generated from source for ezpds **v0.4.7**. Do not edit this page by hand.

Fields come from the validated Rust configuration types. Environment names come from the override loader; nested TOML fields use their containing table. Sensitive values are named but never rendered.

## TOML fields

| Table/type | Field | Rust type | Source description |
| --- | --- | --- | --- |
| `Config` | `bind_address` | `String` | No field-level description. |
| `Config` | `port` | `u16` | No field-level description. |
| `Config` | `data_dir` | `PathBuf` | No field-level description. |
| `Config` | `database_url` | `String` | No field-level description. |
| `Config` | `public_url` | `String` | No field-level description. |
| `Config` | `service_name` | `String` | Human-readable display name for this instance, surfaced to end users (e.g. the `resource_name` field of the RFC 9728 protected-resource metadata). Distinct from `telemetry.service_name` (the machine-facing OTel `service.name` attribute). Defaults to `"custos"`. |
| `Config` | `server_did` | `Option<String>` | No field-level description. |
| `Config` | `available_user_domains` | `Vec<String>` | No field-level description. |
| `Config` | `reserved_handles` | `Vec<String>` | Handle names (the first DNS label) that may never be claimed under a served domain — infrastructure hostnames living inside the user-handle wildcard space (e.g. `identitywallet`, the wallet's OAuth client_id host; `about`, a marketing subdomain). Compared case-insensitively against the first label. Defaults to [`default_reserved_handles`]; override via `reserved_handles` in TOML or the comma-separated `EZPDS_RESERVED_HANDLES` env var. |
| `Config` | `invite_code_required` | `bool` | No field-level description. |
| `Config` | `links` | `ServerLinksConfig` | No field-level description. |
| `Config` | `contact` | `ContactConfig` | No field-level description. |
| `Config` | `blobs` | `BlobsConfig` | No field-level description. |
| `Config` | `firehose` | `FirehoseConfig` | Persistent firehose event log (`repo_seq`) retention / pruning configuration. |
| `Config` | `accounts` | `AccountsConfig` | Account-lifecycle knobs (the scheduled-deletion reaper interval). |
| `Config` | `admin_devices` | `AdminDevicesConfig` | Operator companion-app admin-device knobs (the stale-nonce sweep interval and retention). |
| `Config` | `oauth` | `OAuthConfig` | No field-level description. |
| `Config` | `agent_auth` | `AgentAuthConfig` | auth.md agent-registration knobs (per-flow enablement, issuer trust list, TTLs). |
| `Config` | `iroh` | `IrohConfig` | No field-level description. |
| `Config` | `appview` | `AppViewConfig` | No field-level description. |
| `Config` | `chat` | `ChatConfig` | No field-level description. |
| `Config` | `crawlers` | `CrawlersConfig` | No field-level description. |
| `Config` | `rate_limit` | `RateLimitConfig` | Request rate-limiting knobs (global IP + per-endpoint IP + per-account write points). |
| `Config` | `telemetry` | `TelemetryConfig` | No field-level description. |
| `Config` | `email` | `EmailConfig` | Outbound email delivery (password reset, email confirmation, email update). |
| `Config` | `admin_token` | `Option<Sensitive<String>>` | No field-level description. |
| `Config` | `signing_key_master_key` | `Option<Sensitive<Zeroizing<[u8; 32]>>>` | No field-level description. |
| `Config` | `plc_directory_url` | `String` | No field-level description. |
| `ServerLinksConfig` | `privacy_policy` | `Option<String>` | No field-level description. |
| `ServerLinksConfig` | `terms_of_service` | `Option<String>` | No field-level description. |
| `ContactConfig` | `email` | `Option<String>` | No field-level description. |
| `BlobsConfig` | `max_blob_size` | `u64` | Maximum blob size in bytes. Default: 50 MiB. |
| `BlobsConfig` | `max_storage_per_account` | `u64` | Per-account storage quota in bytes. Default: 1 GiB. |
| `BlobsConfig` | `gc_interval_secs` | `u64` | How often the blob garbage collector runs, in seconds. Default: 1800 (30 min). |
| `BlobsConfig` | `temp_ttl_secs` | `u64` | Grace period, in seconds, before an unreferenced blob is deleted. Applies both to freshly uploaded blobs that are never referenced and to blobs that lose their last reference. Default: 21600 (6 hours). |
| `FirehoseConfig` | `gc_interval_secs` | `u64` | How often the `repo_seq` retention sweep runs, in seconds. Default: 3600 (1 hour). |
| `FirehoseConfig` | `log_retention_secs` | `u64` | Age-based retention: rows whose `sequenced_at` is older than this many seconds are prunable. Default: 604800 (7 days). Set to `0` to disable age-based pruning. |
| `FirehoseConfig` | `log_retention_count` | `u64` | Count-based retention: keep at most this many of the newest rows. `0` disables count-based pruning. Default: `0` (age-based only). |
| `AccountsConfig` | `deletion_reaper_interval_secs` | `u64` | How often the scheduled-deletion reaper runs, in seconds. The reaper permanently deletes accounts whose `deleteAfter` instant (recorded by `com.atproto.server.deactivateAccount`) has elapsed. Default: 3600 (1 hour). Must be > 0 (like the GC intervals, a zero period would panic `tokio::time::interval`). |
| `AdminDevicesConfig` | `nonce_sweep_interval_secs` | `u64` | How often the stale-nonce sweep runs, in seconds. Default: 3600 (1 hour). Must be > 0 (like the other periodic sweeps, a zero period would panic `tokio::time::interval`). |
| `AdminDevicesConfig` | `nonce_max_age_secs` | `u64` | Delete nonce rows whose `seen_at` is older than this many seconds. Default: 3600 (1 hour) — well beyond the validated minimum of `2 * ADMIN_TIMESTAMP_WINDOW_SECS` (120s), the worst-case span a captured request stays replayable after its nonce row is first inserted. Must also fit in `i64` (the sweep passes it to SQLite as a signed duration). |
| `RateLimitConfig` | `enabled` | `bool` | Master switch. When `false`, the middleware and write-point checks are pure pass-throughs. Default: `true`. |
| `RateLimitConfig` | `global_ip_per_5min` | `u64` | Global requests per IP per 5 minutes (reference: 3000). `0` disables. The global limiter exempts `com.atproto.sync.getRepo` and `com.atproto.sync.subscribeRepos` so relay backfill and firehose consumption are never throttled. |
| `RateLimitConfig` | `create_account_per_5min` | `u64` | `com.atproto.server.createAccount` requests per IP per 5 minutes (reference: 100). `0` disables. |
| `RateLimitConfig` | `create_session_per_5min` | `u64` | Password or sovereign full-session creation requests per IP per 5 minutes (reference: 30). Both endpoints share one budget. `0` disables. Complements the per-identifier failed-login sliding window already applied inside the password handler. |
| `RateLimitConfig` | `reset_password_per_5min` | `u64` | `com.atproto.server.resetPassword` requests per IP per 5 minutes (reference: 50). `0` disables. |
| `RateLimitConfig` | `update_handle_per_5min` | `u64` | `com.atproto.identity.updateHandle` requests per IP per 5 minutes (reference: 10). `0` disables. |
| `RateLimitConfig` | `transfer_accept_per_5min` | `u64` | `POST /v1/transfer/accept` requests per IP per 5 minutes. Default 30 (in line with createSession): the endpoint authenticates on a bare 6-char transfer code, so it warrants the tight per-endpoint cap rather than only the generous global one. `0` disables. |
| `RateLimitConfig` | `agent_claim_confirm_per_5min` | `u64` | `POST /agent/identity/claim/confirm` requests per IP per 5 minutes. Default 30: the body carries a guessable 6-digit `user_code` (the same short-code class as `transfer/accept`), so it warrants the tight per-endpoint cap even though the caller is session-authenticated. `0` disables. |
| `RateLimitConfig` | `write_points_hourly` | `u64` | Repo-write points per account per hour (reference: 5000). `0` disables the hourly budget. |
| `RateLimitConfig` | `write_points_daily` | `u64` | Repo-write points per account per day (reference: 35000). `0` disables the daily budget. |
| `AgentAuthConfig` | `service_auth_enabled` | `bool` | Enable the `service_auth` registration flow. Default `false`. |
| `AgentAuthConfig` | `anonymous_enabled` | `bool` | Enable the `anonymous` registration flow. Default `false`. |
| `AgentAuthConfig` | `trusted_issuers` | `Vec<TrustedIssuer>` | Issuers whose ID-JAGs are accepted by the `identity_assertion` flow. Empty (the default) means every `identity_assertion` request is refused with `issuer_not_enabled`. |
| `AgentAuthConfig` | `assertion_ttl_secs` | `u64` | Lifetime, in seconds, of a minted service `identity_assertion`. Default 3600 (1 hour). |
| `AgentAuthConfig` | `claim_token_ttl_secs` | `u64` | Lifetime, in seconds, of a claim token returned for a pending claim ceremony. Default 600. |
| `AgentAuthConfig` | `user_code_ttl_secs` | `u64` | Lifetime, in seconds, of a claim ceremony's user code. Default 600. |
| `AgentAuthConfig` | `auth_time_max_age_secs` | `u64` | Maximum age, in seconds, of an ID-JAG's `auth_time` before the flow returns `login_required` (the assertion is too stale to trust). Default 3600 (1 hour). |
| `AgentAuthConfig` | `granted_scopes` | `Vec<String>` | Scopes granted to a fully-registered agent identity. Defaults to a conservative granular profile — write-to-own-repo plus blob uploads, with AppView reads reaching the agent through the read-proxy (which any access-level token may use). See `default_agent_granted_scopes`.  **Operator warning:** these are enforced through the same granular scope grammar as OAuth tokens (`auth/oauth_scopes.rs`), so an agent token can only do what these scopes permit. Do **not** add `account:*` or `identity:*` (or the legacy `com.atproto.access` full-access scope, or `transition:generic`) unless you intend agents to change account settings, rotate handles/PLC identity, or otherwise hold account-lifecycle control — that hands an agent the same reach as the account owner's own wallet. |
| `AgentAuthConfig` | `pre_claim_scopes` | `Vec<String>` | Scopes carried by a pre-claim (anonymous) assertion. Defaults to the same conservative profile as `granted_scopes`. |
| `AgentAuthConfig` | `verification_uri` | `Option<String>` | The human-facing URL where a user enters the claim-ceremony `user_code`. When `None` (the default) the handler derives `{public_url}/agent/claim`. |
| `AgentAuthConfig` | `claim_sweep_interval_secs` | `u64` | How often the claim-attempt expiry sweep runs, in seconds. Default: 300 (5 minutes — the user-code TTL is 600, so a lapsed ceremony is marked expired within half its window). Must be > 0 (like the GC intervals, a zero period would panic `tokio::time::interval`). |
| `AgentAuthConfig` | `jwks_cache_ttl_secs` | `u64` | TTL, in seconds, of a fetched issuer JWKS before it is re-fetched (dynamic `jwks_url` trust). A rotated key whose `kid` isn't in the cached set triggers a re-fetch as soon as `jwks_refetch_cooldown_secs` allows, so this only bounds how long a *removed* key stays trusted. Default 3600 (1 hour). |
| `AgentAuthConfig` | `jwks_refetch_cooldown_secs` | `u64` | Minimum interval, in seconds, between JWKS fetch attempts for a given `jwks_url`. The requesting `kid` comes from an *unverified* JWT header on public endpoints, so without this cooldown a stream of bogus-`kid` tokens would force one outbound fetch per request. Within the cooldown an unknown `kid` resolves against the last fetched set and a failed fetch keeps failing fast; a genuine key rotation is picked up after at most one cooldown. Should stay well below `jwks_cache_ttl_secs`. `0` disables the cooldown. Default 30. |
| `IrohConfig` | `enabled` | `bool` | Whether to run the Iroh QUIC endpoint alongside the HTTP server. Off by default, so a relay (and the test suite) behaves exactly as before unless explicitly enabled. |
| `IrohConfig` | `endpoint` | `Option<String>` | Optional manual override for the advertised node id. When `None` (the default), the pds advertises its live endpoint's node id (present only while the tunnel is enabled); when set, this exact string is advertised instead. The override is read straight from config by the handler, so it applies even when `enabled` is false (i.e. with no live endpoint running). |
| `IrohConfig` | `ipv6` | `bool` | Whether to bind the IPv6 QUIC socket. Defaults to true. Set to false on hosts with no public IPv6 egress (e.g. Railway containers, which carry internal v6 addresses but can't route them): iroh's v6 relay probes would otherwise fail with `NetworkUnreachable` forever, one WARN every ~80s, drowning real errors. IPv4 paths carry all traffic either way — this only skips the doomed v6 socket. |
| `AppViewConfig` | `url` | `String` | Base URL of the AppView (scheme + authority, no trailing slash). |
| `AppViewConfig` | `did` | `String` | Service DID (with `#fragment`) of the AppView, sent as `atproto-proxy`. |
| `AppViewConfig` | `cdn_url` | `String` | Base URL of the AppView's image CDN (scheme + authority, no trailing slash), used to build avatar/banner/embed-image URLs for the account's own not-yet-indexed records. Defaults to Bluesky's public image CDN. |
| `ChatConfig` | `url` | `String` | Base URL of the chat service (scheme + authority, no trailing slash). |
| `ChatConfig` | `did` | `String` | Service DID (with `#fragment`) of the chat service, sent as `atproto-proxy`. |
| `CrawlersConfig` | `urls` | `Vec<String>` | No field-level description. |
| `TelemetryConfig` | `enabled` | `bool` | Whether to export traces via OTLP. Off by default — zero overhead when disabled. |
| `TelemetryConfig` | `otlp_endpoint` | `String` | OTLP gRPC endpoint for the trace exporter. |
| `TelemetryConfig` | `service_name` | `String` | `service.name` resource attribute reported to the trace backend. |
| `TelemetryConfig` | `metrics_enabled` | `bool` | Whether to register the metrics meter and serve `GET /metrics`. On by default; when off, no meter is registered and the route returns 404. |
| `TelemetryConfig` | `metrics_require_admin` | `bool` | Require admin auth on `GET /metrics`. Off by default so a plain Prometheus scraper works; operators exposing the endpoint beyond a private network can turn it on. |
| `TelemetryConfig` | `log_format` | `LogFormat` | Encoding of the stdout log stream (independent of OTLP export). |
| `EmailConfig` | `provider` | `EmailProvider` | No field-level description. |
| `EmailConfig` | `from` | `Option<String>` | From address on every message (e.g. `noreply@pds.example.com`). Required for SMTP. |
| `EmailConfig` | `from_name` | `Option<String>` | Optional display name paired with `from` (e.g. `Custos PDS`). |
| `EmailConfig` | `smtp_host` | `Option<String>` | SMTP relay host. Required when `provider = "smtp"`. |
| `EmailConfig` | `smtp_port` | `u16` | SMTP relay port. Default 587 (STARTTLS submission). |
| `EmailConfig` | `smtp_username` | `Option<String>` | SMTP AUTH username. When set (with a password), the sender authenticates. |
| `EmailConfig` | `smtp_password` | `Option<Sensitive<String>>` | SMTP AUTH password. Wrapped in [`Sensitive`] so it never appears in `Debug` output. |
| `EmailConfig` | `smtp_tls` | `SmtpTls` | Transport security mode. |
| `EmailConfig` | `smtp_timeout_secs` | `u64` | Connect/send timeout for the SMTP transport, in seconds. `send()` is awaited on the request path, so this bounds how long a slow or unresponsive relay can stall a handler. Default 15. |
| `EmailConfig` | `http_token` | `Option<Sensitive<String>>` | HTTP-API bearer token (e.g. the Mailtrap API token). Required when `provider = "mailtrap"`. Wrapped in [`Sensitive`] so it never appears in `Debug` output, like `smtp_password`. |
| `EmailConfig` | `http_api_url` | `Option<String>` | HTTP-API send endpoint. Defaults to the provider's production endpoint (`https://send.api.mailtrap.io/api/send` for Mailtrap) when unset; overridable so tests can point at a local mock server. |
| `EmailConfig` | `http_timeout_secs` | `u64` | Request timeout for the HTTP-API sender, in seconds. Bounds how long a slow or unresponsive email API can stall a handler (the `smtp_timeout_secs` precedent for the HTTPS path). Default 15. |

## Environment variables

- `EZPDS_ACCOUNTS_DELETION_REAPER_INTERVAL_SECS`
- `EZPDS_ADMIN_DEVICES_NONCE_MAX_AGE_SECS`
- `EZPDS_ADMIN_DEVICES_NONCE_SWEEP_INTERVAL_SECS`
- `EZPDS_ADMIN_TOKEN`
- `EZPDS_AGENT_AUTH_ANONYMOUS_ENABLED`
- `EZPDS_AGENT_AUTH_ASSERTION_TTL_SECS`
- `EZPDS_AGENT_AUTH_AUTH_TIME_MAX_AGE_SECS`
- `EZPDS_AGENT_AUTH_CLAIM_TOKEN_TTL_SECS`
- `EZPDS_AGENT_AUTH_JWKS_CACHE_TTL_SECS`
- `EZPDS_AGENT_AUTH_JWKS_REFETCH_COOLDOWN_SECS`
- `EZPDS_AGENT_AUTH_SERVICE_AUTH_ENABLED`
- `EZPDS_AGENT_AUTH_USER_CODE_TTL_SECS`
- `EZPDS_AGENT_AUTH_VERIFICATION_URI`
- `EZPDS_AGENT_CLAIM_SWEEP_INTERVAL_SECS`
- `EZPDS_APPVIEW_CDN_URL`
- `EZPDS_APPVIEW_DID`
- `EZPDS_APPVIEW_URL`
- `EZPDS_AVAILABLE_USER_DOMAINS`
- `EZPDS_BIND_ADDRESS`
- `EZPDS_BLOBS_GC_INTERVAL_SECS`
- `EZPDS_CHAT_DID`
- `EZPDS_CHAT_URL`
- `EZPDS_CRAWLERS`
- `EZPDS_DATABASE_URL`
- `EZPDS_DATA_DIR`
- `EZPDS_EMAIL_FROM`
- `EZPDS_EMAIL_FROM_NAME`
- `EZPDS_EMAIL_HTTP_API_URL`
- `EZPDS_EMAIL_HTTP_TIMEOUT_SECS`
- `EZPDS_EMAIL_HTTP_TOKEN`
- `EZPDS_EMAIL_PROVIDER`
- `EZPDS_EMAIL_SMTP_HOST`
- `EZPDS_EMAIL_SMTP_PASSWORD`
- `EZPDS_EMAIL_SMTP_PORT`
- `EZPDS_EMAIL_SMTP_TIMEOUT_SECS`
- `EZPDS_EMAIL_SMTP_TLS`
- `EZPDS_EMAIL_SMTP_USERNAME`
- `EZPDS_FIREHOSE_GC_INTERVAL_SECS`
- `EZPDS_INVITE_CODE_REQUIRED`
- `EZPDS_IROH_ENABLED`
- `EZPDS_IROH_ENDPOINT`
- `EZPDS_IROH_IPV6`
- `EZPDS_LOG_FORMAT`
- `EZPDS_METRICS_ENABLED`
- `EZPDS_METRICS_REQUIRE_ADMIN`
- `EZPDS_OTLP_ENDPOINT`
- `EZPDS_PLC_DIRECTORY_URL`
- `EZPDS_PORT`
- `EZPDS_PUBLIC_URL`
- `EZPDS_RATE_LIMIT_AGENT_CLAIM_CONFIRM_PER_5MIN`
- `EZPDS_RATE_LIMIT_CREATE_ACCOUNT_PER_5MIN`
- `EZPDS_RATE_LIMIT_CREATE_SESSION_PER_5MIN`
- `EZPDS_RATE_LIMIT_ENABLED`
- `EZPDS_RATE_LIMIT_GLOBAL_IP_PER_5MIN`
- `EZPDS_RATE_LIMIT_RESET_PASSWORD_PER_5MIN`
- `EZPDS_RATE_LIMIT_TRANSFER_ACCEPT_PER_5MIN`
- `EZPDS_RATE_LIMIT_UPDATE_HANDLE_PER_5MIN`
- `EZPDS_RATE_LIMIT_WRITE_POINTS_DAILY`
- `EZPDS_RATE_LIMIT_WRITE_POINTS_HOURLY`
- `EZPDS_RESERVED_HANDLES`
- `EZPDS_SERVER_DID`
- `EZPDS_SERVICE_NAME`
- `EZPDS_SIGNING_KEY_MASTER_KEY`
- `EZPDS_TELEMETRY_ENABLED`
- `OTEL_SERVICE_NAME`
- `PORT`

- `EZPDS_CONFIG` — path to the TOML configuration file (CLI source).
