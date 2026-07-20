---
title: Configuration reference
description: Generated TOML fields and environment controls for Custos operators.
---

> Generated from source for ezpds **v0.7.1**. Do not edit this page by hand.

Fields come from the validated Rust configuration types. Environment overrides come from the loader and are shown beside the TOML value they replace. A dash means that field has no direct environment override. Sensitive values are named but never rendered.

## TOML fields and overrides

| TOML key | Environment override | Rust type | Source description |
| --- | --- | --- | --- |
| `bind_address` | `EZPDS_BIND_ADDRESS` | `String` | No field-level description. |
| `port` | `EZPDS_PORT`, `PORT` | `u16` | No field-level description. |
| `data_dir` | `EZPDS_DATA_DIR` | `PathBuf` | No field-level description. |
| `database_url` | `EZPDS_DATABASE_URL` | `String` | No field-level description. |
| `public_url` | `EZPDS_PUBLIC_URL` | `String` | No field-level description. |
| `service_name` | `EZPDS_SERVICE_NAME` | `String` | Human-readable display name for this instance, surfaced to end users (e.g. the `resource_name` field of the RFC 9728 protected-resource metadata). Distinct from `telemetry.service_name` (the machine-facing OTel `service.name` attribute). Defaults to `"custos"`. |
| `server_did` | `EZPDS_SERVER_DID` | `Option<String>` | No field-level description. |
| `available_user_domains` | `EZPDS_AVAILABLE_USER_DOMAINS` | `Vec<String>` | No field-level description. |
| `reserved_handles` | `EZPDS_RESERVED_HANDLES` | `Vec<String>` | Handle names (the first DNS label) that may never be claimed under a served domain — infrastructure hostnames living inside the user-handle wildcard space (e.g. `identitywallet`, the wallet's OAuth client_id host; `about`, a marketing subdomain). Compared case-insensitively against the first label. Defaults to [`default_reserved_handles`]; override via `reserved_handles` in TOML or the comma-separated `EZPDS_RESERVED_HANDLES` env var. |
| `invite_code_required` | `EZPDS_INVITE_CODE_REQUIRED` | `bool` | No field-level description. |
| `links` | — | `ServerLinksConfig` | No field-level description. |
| `contact` | — | `ContactConfig` | No field-level description. |
| `blobs` | — | `BlobsConfig` | No field-level description. |
| `blob_mirror` | — | `BlobMirrorConfig` | Off-volume blob replication to an S3-compatible bucket (the Litestream analogue for blob bytes). Disabled unless a bucket is configured. |
| `blob_scrub` | — | `BlobScrubConfig` | Periodic blob-integrity scrub sweep (re-hash stored bytes against their CID/size, walk for orphans in both directions). |
| `firehose` | — | `FirehoseConfig` | Persistent firehose event log (`repo_seq`) retention / pruning configuration. |
| `accounts` | — | `AccountsConfig` | Account-lifecycle knobs (the scheduled-deletion reaper interval). |
| `recovery` | — | `RecoveryConfig` | Escrow-assisted recovery knobs (the cancellable release-delay window). |
| `admin_devices` | — | `AdminDevicesConfig` | Operator companion-app admin-device knobs (the stale-nonce sweep interval and retention). |
| `oauth` | — | `OAuthConfig` | No field-level description. |
| `agent_auth` | — | `AgentAuthConfig` | auth.md agent-registration knobs (per-flow enablement, issuer trust list, TTLs). |
| `iroh` | — | `IrohConfig` | No field-level description. |
| `appview` | — | `AppViewConfig` | No field-level description. |
| `chat` | — | `ChatConfig` | No field-level description. |
| `crawlers` | — | `CrawlersConfig` | No field-level description. |
| `labeler` | — | `LabelerConfig` | Labeler watching: flag hosted accounts carrying labels from watched labelers. |
| `rate_limit` | — | `RateLimitConfig` | Request rate-limiting knobs (global IP + per-endpoint IP + per-account write points). |
| `telemetry` | — | `TelemetryConfig` | No field-level description. |
| `email` | — | `EmailConfig` | Outbound email delivery (password reset, email confirmation, email update). |
| `admin_token` | `EZPDS_ADMIN_TOKEN` | `Option<Sensitive<String>>` | No field-level description. |
| `signing_key_master_key` | `EZPDS_SIGNING_KEY_MASTER_KEY` | `Option<Sensitive<Zeroizing<[u8; 32]>>>` | No field-level description. |
| `plc_directory_url` | `EZPDS_PLC_DIRECTORY_URL` | `String` | No field-level description. |
| `links.privacy_policy` | — | `Option<String>` | No field-level description. |
| `links.terms_of_service` | — | `Option<String>` | No field-level description. |
| `contact.email` | — | `Option<String>` | No field-level description. |
| `blobs.max_blob_size` | — | `u64` | Maximum blob size in bytes. Default: 50 MiB. |
| `blobs.max_storage_per_account` | — | `u64` | Per-account storage quota in bytes. Default: 1 GiB. |
| `blobs.gc_interval_secs` | `EZPDS_BLOBS_GC_INTERVAL_SECS` | `u64` | How often the blob garbage collector runs, in seconds. Default: 1800 (30 min). |
| `blobs.temp_ttl_secs` | — | `u64` | Grace period, in seconds, before an unreferenced blob is deleted. Applies both to freshly uploaded blobs that are never referenced and to blobs that lose their last reference. Default: 21600 (6 hours). |
| `blob_mirror.bucket` | `EZPDS_BLOB_MIRROR_BUCKET` | `Option<String>` | Bucket name. Setting this enables the mirror; leave unset to disable (the default). |
| `blob_mirror.endpoint` | `EZPDS_BLOB_MIRROR_ENDPOINT` | `Option<String>` | S3-compatible endpoint URL (e.g. `https://t3.storage.dev`). Required when `bucket` is set. |
| `blob_mirror.region` | `EZPDS_BLOB_MIRROR_REGION` | `String` | SigV4 signing region. S3-compatible providers commonly accept `auto` (the default); set the real region where the provider requires it. |
| `blob_mirror.access_key_id` | `EZPDS_BLOB_MIRROR_ACCESS_KEY_ID` | `Option<String>` | Access key id for the bucket. Required when `bucket` is set. |
| `blob_mirror.secret_access_key` | `EZPDS_BLOB_MIRROR_SECRET_ACCESS_KEY` | `Option<Sensitive<String>>` | Secret access key for the bucket. Required when `bucket` is set. Wrapped in [`Sensitive`] so it never appears in `Debug` output. |
| `blob_mirror.force_path_style` | `EZPDS_BLOB_MIRROR_FORCE_PATH_STYLE` | `bool` | Address the bucket as `{endpoint}/{bucket}/…` (path-style) instead of `https://{bucket}.{endpoint-host}/…` (virtual-hosted). Default `false`, matching the Litestream replica's `force-path-style: false` for the same bucket family. |
| `blob_mirror.key_prefix` | `EZPDS_BLOB_MIRROR_KEY_PREFIX` | `String` | Object-key prefix the mirror owns inside the bucket. Objects under it are managed by the sweep — including deletion of keys no `blobs` row references — so nothing else should write there. Default: `blobs/`. |
| `blob_mirror.sync_interval_secs` | `EZPDS_BLOB_MIRROR_SYNC_INTERVAL_SECS` | `u64` | How often the mirror sweep runs, in seconds. Default: 300 (5 min). |
| `blob_scrub.interval_secs` | `EZPDS_BLOB_SCRUB_INTERVAL_SECS` | `u64` | How often the scrub sweep runs, in seconds. Default: 21600 (6 hours) — re-hashing every stored blob is I/O-heavy, so it runs far less often than the reference-reconciling blob GC. |
| `blob_scrub.auto_heal` | `EZPDS_BLOB_SCRUB_AUTO_HEAL` | `bool` | Whether a bad file (hash/size mismatch, or a row whose file is missing) may be auto-healed from the blob-mirror bucket (`[blob_mirror]`) when it holds a verified-good copy. Default: true. Has no effect when the mirror itself is disabled — a bad file is then only ever flagged, never healed. |
| `firehose.gc_interval_secs` | `EZPDS_FIREHOSE_GC_INTERVAL_SECS` | `u64` | How often the `repo_seq` retention sweep runs, in seconds. Default: 3600 (1 hour). |
| `firehose.log_retention_secs` | — | `u64` | Age-based retention: rows whose `sequenced_at` is older than this many seconds are prunable. Default: 604800 (7 days). Set to `0` to disable age-based pruning. |
| `firehose.log_retention_count` | — | `u64` | Count-based retention: keep at most this many of the newest rows. `0` disables count-based pruning. Default: `0` (age-based only). |
| `accounts.deletion_reaper_interval_secs` | `EZPDS_ACCOUNTS_DELETION_REAPER_INTERVAL_SECS` | `u64` | How often the scheduled-deletion reaper runs, in seconds. The reaper permanently deletes accounts whose `deleteAfter` instant (recorded by `com.atproto.server.deactivateAccount`) has elapsed. Default: 3600 (1 hour). Must be > 0 (like the GC intervals, a zero period would panic `tokio::time::interval`). |
| `accounts.child_deletion_grace_secs` | `EZPDS_ACCOUNTS_CHILD_DELETION_GRACE_SECS` | `u64` | Grace window, in seconds, between a parent scheduling a sovereign child agent's deletion (`POST /agent/child/delete`) and the reaper permanently purging it. The child is deactivated immediately (so relays stop serving its repo) but the irreversible byte-purge waits this long, giving an undo window. Default: 86400 (24 hours). `0` means the next reaper tick purges. Unlike `deletion_reaper_interval_secs` this is not a `tokio::time` period, so a zero value is allowed. |
| `recovery.release_delay_secs` | `EZPDS_RECOVERY_RELEASE_DELAY_SECS` | `u64` | The cancellable delay, in seconds, between opening an escrow release (with a valid email OTP) and the Share 2 envelope becoming collectable. Default: 86400 (24 hours). `0` collapses the two-step flow to a single call that returns the share directly — appropriate only where the delay's protection isn't wanted (the operator's judgment). Not a `tokio::time` period, so `0` is allowed. |
| `admin_devices.nonce_sweep_interval_secs` | `EZPDS_ADMIN_DEVICES_NONCE_SWEEP_INTERVAL_SECS` | `u64` | How often the stale-nonce sweep runs, in seconds. Default: 3600 (1 hour). Must be > 0 (like the other periodic sweeps, a zero period would panic `tokio::time::interval`). |
| `admin_devices.nonce_max_age_secs` | `EZPDS_ADMIN_DEVICES_NONCE_MAX_AGE_SECS` | `u64` | Delete nonce rows whose `seen_at` is older than this many seconds. Default: 3600 (1 hour) — well beyond the validated minimum of `2 * ADMIN_TIMESTAMP_WINDOW_SECS` (120s), the worst-case span a captured request stays replayable after its nonce row is first inserted. Must also fit in `i64` (the sweep passes it to SQLite as a signed duration). |
| `rate_limit.enabled` | `EZPDS_RATE_LIMIT_ENABLED` | `bool` | Master switch. When `false`, the middleware and write-point checks are pure pass-throughs. Default: `true`. |
| `rate_limit.global_ip_per_5min` | `EZPDS_RATE_LIMIT_GLOBAL_IP_PER_5MIN` | `u64` | Global requests per IP per 5 minutes (reference: 3000). `0` disables. The global limiter exempts `com.atproto.sync.getRepo` and `com.atproto.sync.subscribeRepos` so relay backfill and firehose consumption are never throttled. |
| `rate_limit.create_account_per_5min` | `EZPDS_RATE_LIMIT_CREATE_ACCOUNT_PER_5MIN` | `u64` | `com.atproto.server.createAccount` requests per IP per 5 minutes (reference: 100). `0` disables. |
| `rate_limit.create_session_per_5min` | `EZPDS_RATE_LIMIT_CREATE_SESSION_PER_5MIN` | `u64` | Password or sovereign full-session creation requests per IP per 5 minutes (reference: 30). Both endpoints share one budget. `0` disables. Complements the per-identifier failed-login sliding window already applied inside the password handler. |
| `rate_limit.reset_password_per_5min` | `EZPDS_RATE_LIMIT_RESET_PASSWORD_PER_5MIN` | `u64` | `com.atproto.server.resetPassword` requests per IP per 5 minutes (reference: 50). `0` disables. |
| `rate_limit.update_handle_per_5min` | `EZPDS_RATE_LIMIT_UPDATE_HANDLE_PER_5MIN` | `u64` | `com.atproto.identity.updateHandle` requests per IP per 5 minutes (reference: 10). `0` disables. |
| `rate_limit.transfer_accept_per_5min` | `EZPDS_RATE_LIMIT_TRANSFER_ACCEPT_PER_5MIN` | `u64` | `POST /v1/transfer/accept` requests per IP per 5 minutes. Default 30 (in line with createSession): the endpoint authenticates on a bare 6-char transfer code, so it warrants the tight per-endpoint cap rather than only the generous global one. `0` disables. |
| `rate_limit.agent_claim_confirm_per_5min` | `EZPDS_RATE_LIMIT_AGENT_CLAIM_CONFIRM_PER_5MIN` | `u64` | `POST /agent/identity/claim/confirm` requests per IP per 5 minutes. Default 30: the body carries a guessable 6-digit `user_code` (the same short-code class as `transfer/accept`), so it warrants the tight per-endpoint cap even though the caller is session-authenticated. `0` disables. |
| `rate_limit.recovery_per_5min` | `EZPDS_RATE_LIMIT_RECOVERY_PER_5MIN` | `u64` | Escrow-recovery `POST /v1/recovery/initiate` + `POST /v1/recovery/release` requests per IP per 5 minutes. Default 30 (in line with createSession). The release endpoint validates an emailed OTP, so it carries the same code-guessing surface as the other short-code endpoints; initiate and release **share one limiter instance** so alternating between them cannot double an attacker's OTP-guess budget (the agent claim-pair precedent). `0` disables. |
| `rate_limit.oauth_consent_create_per_5min` | `EZPDS_RATE_LIMIT_OAUTH_CONSENT_CREATE_PER_5MIN` | `u64` | Wallet-confirmed OAuth consent request creations (`GET /oauth/authorize` for a passwordless or migrated account) per 5 minutes. Charged in-handler against **both** the requesting IP and the `client_id` (two independent counters, one limiter), so neither a single IP nor a single client can flood the pending-request table. Default 30. `0` disables. |
| `rate_limit.oauth_consent_action_per_5min` | `EZPDS_RATE_LIMIT_OAUTH_CONSENT_ACTION_PER_5MIN` | `u64` | Wallet-consent code-validating endpoints (`GET /oauth/authorize/consent-request` preview + `POST /oauth/authorize/approve`) per IP per 5 minutes. Default 30. Preview validates a guessable `user_code`, so it warrants the tight per-endpoint cap (the claim confirm/preview precedent); the two **share one limiter instance** so alternating them can't double the guess budget. `0` disables. |
| `rate_limit.write_points_hourly` | `EZPDS_RATE_LIMIT_WRITE_POINTS_HOURLY` | `u64` | Repo-write points per account per hour (reference: 5000). `0` disables the hourly budget. |
| `rate_limit.write_points_daily` | `EZPDS_RATE_LIMIT_WRITE_POINTS_DAILY` | `u64` | Repo-write points per account per day (reference: 35000). `0` disables the daily budget. |
| `agent_auth.service_auth_enabled` | `EZPDS_AGENT_AUTH_SERVICE_AUTH_ENABLED` | `bool` | Enable the `service_auth` registration flow. Default `false`. |
| `agent_auth.anonymous_enabled` | `EZPDS_AGENT_AUTH_ANONYMOUS_ENABLED` | `bool` | Enable the `anonymous` registration flow. Default `false`. |
| `agent_auth.trusted_issuers` | — | `Vec<TrustedIssuer>` | Issuers whose ID-JAGs are accepted by the `identity_assertion` flow. Empty (the default) means every `identity_assertion` request is refused with `issuer_not_enabled`. |
| `agent_auth.assertion_ttl_secs` | `EZPDS_AGENT_AUTH_ASSERTION_TTL_SECS` | `u64` | Lifetime, in seconds, of a minted service `identity_assertion`. Default 3600 (1 hour). |
| `agent_auth.claim_token_ttl_secs` | `EZPDS_AGENT_AUTH_CLAIM_TOKEN_TTL_SECS` | `u64` | Lifetime, in seconds, of a claim token returned for a pending claim ceremony. Default 600. |
| `agent_auth.user_code_ttl_secs` | `EZPDS_AGENT_AUTH_USER_CODE_TTL_SECS` | `u64` | Lifetime, in seconds, of a claim ceremony's user code. Default 600. |
| `agent_auth.auth_time_max_age_secs` | `EZPDS_AGENT_AUTH_AUTH_TIME_MAX_AGE_SECS` | `u64` | Maximum age, in seconds, of an ID-JAG's `auth_time` before the flow returns `login_required` (the assertion is too stale to trust). Default 3600 (1 hour). |
| `agent_auth.granted_scopes` | — | `Vec<String>` | Scopes granted to a fully-registered agent identity. Defaults to a conservative granular profile — write-to-own-repo plus blob uploads, with AppView reads reaching the agent through the read-proxy (which any access-level token may use). See `default_agent_granted_scopes`.  **Operator warning:** these are enforced through the same granular scope grammar as OAuth tokens (`auth/oauth_scopes.rs`), so an agent token can only do what these scopes permit. Do **not** add `account:*` or `identity:*` (or the legacy `com.atproto.access` full-access scope, or `transition:generic`) unless you intend agents to change account settings, rotate handles/PLC identity, or otherwise hold account-lifecycle control — that hands an agent the same reach as the account owner's own wallet. |
| `agent_auth.pre_claim_scopes` | — | `Vec<String>` | Scopes carried by a pre-claim (anonymous) assertion. Defaults to the same conservative profile as `granted_scopes`. |
| `agent_auth.verification_uri` | `EZPDS_AGENT_AUTH_VERIFICATION_URI` | `Option<String>` | The human-facing URL where a user enters the claim-ceremony `user_code`. When `None` (the default) the handler derives `{public_url}/agent/claim`. |
| `agent_auth.claim_sweep_interval_secs` | `EZPDS_AGENT_CLAIM_SWEEP_INTERVAL_SECS` | `u64` | How often the claim-attempt expiry sweep runs, in seconds. Default: 300 (5 minutes — the user-code TTL is 600, so a lapsed ceremony is marked expired within half its window). Must be > 0 (like the GC intervals, a zero period would panic `tokio::time::interval`). |
| `agent_auth.jwks_cache_ttl_secs` | `EZPDS_AGENT_AUTH_JWKS_CACHE_TTL_SECS` | `u64` | TTL, in seconds, of a fetched issuer JWKS before it is re-fetched (dynamic `jwks_url` trust). A rotated key whose `kid` isn't in the cached set triggers a re-fetch as soon as `jwks_refetch_cooldown_secs` allows, so this only bounds how long a *removed* key stays trusted. Default 3600 (1 hour). |
| `agent_auth.jwks_refetch_cooldown_secs` | `EZPDS_AGENT_AUTH_JWKS_REFETCH_COOLDOWN_SECS` | `u64` | Minimum interval, in seconds, between JWKS fetch attempts for a given `jwks_url`. The requesting `kid` comes from an *unverified* JWT header on public endpoints, so without this cooldown a stream of bogus-`kid` tokens would force one outbound fetch per request. Within the cooldown an unknown `kid` resolves against the last fetched set and a failed fetch keeps failing fast; a genuine key rotation is picked up after at most one cooldown. Should stay well below `jwks_cache_ttl_secs`. `0` disables the cooldown. Default 30. |
| `iroh.enabled` | `EZPDS_IROH_ENABLED` | `bool` | Whether to run the Iroh QUIC endpoint alongside the HTTP server. Off by default, so a relay (and the test suite) behaves exactly as before unless explicitly enabled. |
| `iroh.endpoint` | `EZPDS_IROH_ENDPOINT` | `Option<String>` | Optional manual override for the advertised node id. When `None` (the default), the pds advertises its live endpoint's node id (present only while the tunnel is enabled); when set, this exact string is advertised instead. The override is read straight from config by the handler, so it applies even when `enabled` is false (i.e. with no live endpoint running). |
| `iroh.ipv6` | `EZPDS_IROH_IPV6` | `bool` | Whether to bind the IPv6 QUIC socket. Defaults to true. Set to false on hosts with no public IPv6 egress (e.g. Railway containers, which carry internal v6 addresses but can't route them): iroh's v6 relay probes would otherwise fail with `NetworkUnreachable` forever, one WARN every ~80s, drowning real errors. IPv4 paths carry all traffic either way — this only skips the doomed v6 socket. |
| `appview.url` | `EZPDS_APPVIEW_URL` | `String` | Base URL of the AppView (scheme + authority, no trailing slash). |
| `appview.did` | `EZPDS_APPVIEW_DID` | `String` | Service DID (with `#fragment`) of the AppView, sent as `atproto-proxy`. |
| `appview.cdn_url` | `EZPDS_APPVIEW_CDN_URL` | `String` | Base URL of the AppView's image CDN (scheme + authority, no trailing slash), used to build avatar/banner/embed-image URLs for the account's own not-yet-indexed records. Defaults to Bluesky's public image CDN. |
| `chat.url` | `EZPDS_CHAT_URL` | `String` | Base URL of the chat service (scheme + authority, no trailing slash). |
| `chat.did` | `EZPDS_CHAT_DID` | `String` | Service DID (with `#fragment`) of the chat service, sent as `atproto-proxy`. |
| `crawlers.urls` | `EZPDS_CRAWLERS` | `Vec<String>` | No field-level description. |
| `labeler.watched` | `EZPDS_LABELER_WATCHED` | `Vec<WatchedLabeler>` | Labelers whose account-level labels flag hosted accounts. Empty (the default) disables labeler watching entirely. |
| `labeler.poll_interval_secs` | `EZPDS_LABELER_POLL_INTERVAL_SECS` | `u64` | How often the watcher polls each watched labeler's `com.atproto.label.queryLabels`, in seconds. Default: 900 (15 minutes). Must be > 0 (like the GC intervals, a zero period would panic `tokio::time::interval`). |
| `telemetry.enabled` | `EZPDS_TELEMETRY_ENABLED` | `bool` | Whether to export traces via OTLP. Off by default — zero overhead when disabled. |
| `telemetry.otlp_endpoint` | `EZPDS_OTLP_ENDPOINT` | `String` | OTLP gRPC endpoint for the trace exporter. |
| `telemetry.service_name` | `OTEL_SERVICE_NAME` | `String` | `service.name` resource attribute reported to the trace backend. |
| `telemetry.metrics_enabled` | `EZPDS_METRICS_ENABLED` | `bool` | Whether to register the metrics meter and serve `GET /metrics`. On by default; when off, no meter is registered and the route returns 404. |
| `telemetry.metrics_require_admin` | `EZPDS_METRICS_REQUIRE_ADMIN` | `bool` | Require admin auth on `GET /metrics`. Off by default so a plain Prometheus scraper works; operators exposing the endpoint beyond a private network can turn it on. |
| `telemetry.log_format` | `EZPDS_LOG_FORMAT` | `LogFormat` | Encoding of the stdout log stream (independent of OTLP export). |
| `email.provider` | `EZPDS_EMAIL_PROVIDER` | `EmailProvider` | No field-level description. |
| `email.from` | `EZPDS_EMAIL_FROM` | `Option<String>` | From address on every message (e.g. `noreply@pds.example.com`). Required for SMTP. |
| `email.from_name` | `EZPDS_EMAIL_FROM_NAME` | `Option<String>` | Optional display name paired with `from` (e.g. `Custos PDS`). |
| `email.smtp_host` | `EZPDS_EMAIL_SMTP_HOST` | `Option<String>` | SMTP relay host. Required when `provider = "smtp"`. |
| `email.smtp_port` | `EZPDS_EMAIL_SMTP_PORT` | `u16` | SMTP relay port. Default 587 (STARTTLS submission). |
| `email.smtp_username` | `EZPDS_EMAIL_SMTP_USERNAME` | `Option<String>` | SMTP AUTH username. When set (with a password), the sender authenticates. |
| `email.smtp_password` | `EZPDS_EMAIL_SMTP_PASSWORD` | `Option<Sensitive<String>>` | SMTP AUTH password. Wrapped in [`Sensitive`] so it never appears in `Debug` output. |
| `email.smtp_tls` | `EZPDS_EMAIL_SMTP_TLS` | `SmtpTls` | Transport security mode. |
| `email.smtp_timeout_secs` | `EZPDS_EMAIL_SMTP_TIMEOUT_SECS` | `u64` | Connect/send timeout for the SMTP transport, in seconds. `send()` is awaited on the request path, so this bounds how long a slow or unresponsive relay can stall a handler. Default 15. |
| `email.http_token` | `EZPDS_EMAIL_HTTP_TOKEN` | `Option<Sensitive<String>>` | HTTP-API bearer token (e.g. the Mailtrap API token). Required when `provider = "mailtrap"`. Wrapped in [`Sensitive`] so it never appears in `Debug` output, like `smtp_password`. |
| `email.http_api_url` | `EZPDS_EMAIL_HTTP_API_URL` | `Option<String>` | HTTP-API send endpoint. Defaults to the provider's production endpoint (`https://send.api.mailtrap.io/api/send` for Mailtrap) when unset; overridable so tests can point at a local mock server. |
| `email.http_timeout_secs` | `EZPDS_EMAIL_HTTP_TIMEOUT_SECS` | `u64` | Request timeout for the HTTP-API sender, in seconds. Bounds how long a slow or unresponsive email API can stall a handler (the `smtp_timeout_secs` precedent for the HTTPS path). Default 15. |

## Process-level environment variables

- `EZPDS_CONFIG` — path to the TOML configuration file (CLI source).
