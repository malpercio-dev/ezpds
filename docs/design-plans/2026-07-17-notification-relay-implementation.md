# Notification Relay — Implementation Plan (MM-311)

[MM-311](https://linear.app/malpercio/issue/MM-311) · implementation leg of
[docs/design-plans/2026-07-10-notification-relay.md](2026-07-10-notification-relay.md)
(design PR #207, merged — that doc remains the architecture source of truth; this doc pins
the implementation details against the codebase and decomposes the work into issues).

**Codebase verified: 2026-07-17** (migrations at V051, bruno seq at 123, iroh 1.0.0,
workspace 0.5.2).

## Refinements to the design doc

Three details discovered during codebase verification refine (not reverse) the design:

1. **Registrations key on the account DID, not `devices.id`.** The design says the
   registration lands in "new columns/table beside `devices`" — but `devices` is a
   *transient pre-DID artifact*: rows are deleted inside the DID-promotion transaction
   (`routes/create_did.rs`) and the table FKs to `pending_accounts`. A registration FK'd
   there would die exactly when the account starts mattering. Wallet notification
   registrations therefore key on `(did, device_uuid)` where `device_uuid` is an
   app-generated stable identifier, are created **post-promotion** over the OAuth/DPoP
   channel (through the `authenticate_access` seam — the auth-seam-check applies), and are
   purged in `account_delete::purge_account`'s explicit FK-ordered delete list.
   Admin-companion registrations are a separate table keyed by `admin_devices.id`,
   cleaned up alongside the revoke tombstone. Pending (pre-DID) accounts get no pushes —
   onboarding completes with promotion, and registration is one of the first
   post-promotion calls.
2. **The ciphersuite is forced to AES-256-GCM.** CryptoKit ships exactly one P-256 HPKE
   suite: `HPKE.Ciphersuite.P256_SHA256_AES_GCM_256`. So the wire suite is pinned to
   **DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM, mode_auth** — no
   negotiation, ever; `v` in the envelope names the whole suite. RFC 9180's appendix has
   no test vector for this exact combo (A.3 is AES-128), so golden fixtures are generated
   from the Rust implementation, pinned in `crates/crypto/tests/fixtures/`, and
   cross-verified against CryptoKit by an on-device XCTest in the wallet phase.
3. **The v1 back-channel is the RPC response, not a server-initiated stream.** The relay
   calls APNs synchronously inside the push RPC, so `410 Unregistered` (and throttle/size
   outcomes) return in the same request/response exchange over the already-open bidi
   stream. No relay-initiated streams in v1 — that machinery (delivery receipts) stays
   out of scope, as the design already decided.

CryptoKit's HPKE API requires **iOS 17**; the apps' deployment target currently rides
tauri-cli's default (13.0, nothing overridden in either `tauri.conf.json`). Decision:
raise `bundle > iOS > minimumSystemVersion` to `17.0` for both apps in the wallet phase.
Both apps are new (no installed base below 17), and a per-target split (NSE at 17, app
lower, runtime-gated registration) buys nothing but complexity.

## Wire formats

### Sealed payload (Custos → device, opaque to relay/Apple)

Plaintext (serde_json, camelCase):

```json
{ "type": "agent_claim_pending", "title": "…", "body": "…", "data": { … }, "pad": "…" }
```

`pad` is a string of `0x20` bytes sized so the **serialized APNs request** lands exactly
on a padding bucket (below). Sealed with HPKE mode_auth:

- suite: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM
- `info = b"ezpds/notify/1"`, `aad = b""` (version binding lives in `info` + envelope `v`)
- sender key: the instance's static notification sender keypair named by `kid`
- recipient key: the device's notification public key

### APNs payload (relay → Apple → device)

```json
{
  "aps": { "alert": { "title": "Custos", "body": "Encrypted notification" },
           "mutable-content": 1 },
  "ezpds": { "v": 1, "kid": 3, "enc": "<b64url encapsulated key>", "ct": "<b64url ciphertext>" }
}
```

Ping mode (later phase) replaces `aps` with `{ "content-available": 1 }` and omits
`ezpds` entirely.

### Padding buckets

Buckets are defined on the **serialized APNs JSON body**: `{1024, 2048, 3584}` bytes
(3584 keeps headroom under APNs' 4096 cap). Base64url expansion is deterministic
(`enc` = 65-byte uncompressed P-256 point → 87 chars; `ct` = plaintext + 16-byte tag),
so Custos computes the exact `pad` length that makes the final body hit the smallest
bucket ≥ the unpadded size, and refuses payloads that exceed the largest bucket. A
relay-side check enforces the same cap defensively, with a boundary test at exactly
4096 bytes.

### Custos ↔ relay RPC (`ezpds/notify/0`)

New ALPN beside `ezpds/iroh/0`. One JSON request per bidi stream, response JSON, stream
FIN delimits (the `iroh_tunnel.rs` pattern: `read_to_end` with a 64 KiB cap, 30 s
per-stream timeout). The dialing node's identity is `connection.remote_id()` — no
credential in the messages. Requests are a tagged enum:

| request | response | notes |
|---|---|---|
| `enroll { claimCode? }` | `ok` / `denied` | idempotent; `claimCode` required unless the relay runs open enrollment |
| `registerHandle { apnsToken, apnsTopic }` | `{ handle }` | topic must be in the relay's served-topic set; re-registering the same token rotates the handle |
| `dropHandle { handle }` | `ok` | idempotent |
| `push { handle, kid, enc, ct, priority, ttlSecs, ping }` | `{ outcome }` | outcome ∈ `delivered · unregistered · throttled · tooLarge · notEnrolled · unknownHandle · apnsError` |

`unregistered` is the APNs 410 feedback: Custos deletes the registration row on receipt.
Every request except `enroll` requires the node id to be enrolled; handles are only ever
resolvable by the node id that registered them.

The Custos side gains its first **outbound** iroh leg: a `notify_relay_client` module that
reuses the existing `IrohState` endpoint (an iroh `Endpoint` both accepts and dials),
dials by node id from config, opens one stream per RPC, and reconnects lazily with
exponential backoff. Sends are fire-and-forget from callers' perspective: triggers enqueue
into an in-process `tokio::sync::mpsc` worker so a dead relay never blocks a request path.
v1 queue is in-memory only (a missed push is a missed banner, not lost data — the app
reconciles from its Custos); durable queuing is an explicit non-goal.

## The relay: `crates/notify-relay/`

New workspace member; own binary, own SQLite DB, same stack (tokio + iroh + sqlx +
tracing; axum only if/when an HTTP surface appears — v1 has none). Modeled on the pds
crate's conventions: pattern comments, `db/` submodules own queries, migrations as
`VNNN__*.sql` with the same manifest/runner pattern (copied small, not shared — the
runner is ~50 lines and the crates' migration histories are independent).

**Schema:**

```sql
enrollment_codes(code TEXT PK, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                 consumed_at TEXT, consumed_by_node TEXT)          -- V001
enrollments(node_id TEXT PK, enrolled_at TEXT NOT NULL, code_used TEXT)
handles(handle TEXT PK,                    -- 128-bit random, base64url
        node_id TEXT NOT NULL REFERENCES enrollments(node_id),
        apns_token TEXT NOT NULL, apns_topic TEXT NOT NULL,
        created_at TEXT NOT NULL, last_push_at TEXT)
```

Status is derived from timestamps (the `claim_codes` doctrine); enrollment-code redemption
is the same atomic guarded-UPDATE shape as `consume_pairing_code`. `(node_id, apns_token)`
unique — re-registration rotates the handle in place.

**Config** (TOML + env, mirroring `config_loader.rs` posture): iroh secret key path
(file-persisted — the relay has no master-key hierarchy; 0600 perms), `open_enrollment: bool`
(default false), APNs: `.p8` path, key id, team id, served topics list, endpoint override
(`EZPDS_NOTIFY_APNS_URL` — the wiremock seam, same trick as `EZPDS_PLC_DIRECTORY_URL`),
sandbox/production toggle. Enrollment codes are minted by a CLI subcommand
(`notify-relay mint-code --ttl 60m`) — operator-local, no remote admin surface in v1.

**APNs client:** reqwest (workspace 0.13, rustls — ALPN-negotiates h2 against real APNs,
h1 against wiremock). Token auth is a hand-rolled ES256 JWT over the existing `p256`
dep (header `{alg, kid}` + claims `{iss: team_id, iat}`, base64url, ECDSA-sign — ~30
lines; avoids `jsonwebtoken`'s `ring` dependency), cached and refreshed at 50 minutes
per Apple's 20–60 min rule. Headers per push: `apns-topic` (from the handle row),
`apns-push-type: alert` (or `background` for ping), `apns-priority` (10 alert / 5 ping),
`apns-expiration` (now + ttlSecs).

**Rate limits:** in-memory token buckets (no persistence — restart forgiveness is fine),
two keys: per node id (default 1 000/h, burst 50) and per handle (default 60/h, burst 10);
exceeded → `throttled`. Registration RPCs get a per-node bucket too (default 100/h).

**Deploy:** a second binary means the root single-binary Dockerfile doesn't cover it; the
relay ships its own `crates/notify-relay/Dockerfile` (same builder pattern,
`cargo build --release --locked -p notify-relay`) deployed as a Railway service beside
pds/mcp-sidecar, Litestream optional (state is re-derivable by re-enrollment — the design
already accepts relay state loss). Ops docs in the final phase.

## The Custos side (`crates/pds`)

**Config:** `[notifications]` in `common::Config` — `relay: Option<String>` (node id;
default `None` → feature off, the `[iroh]` posture), `enrollment_code: Option<String>`
(consumed on first successful enroll), `ping_mode: bool` (later phase). Env:
`EZPDS_NOTIFICATIONS_RELAY`, `EZPDS_NOTIFICATIONS_ENROLLMENT_CODE`. Requires
`[iroh] enabled` (validation error otherwise — the endpoint is the dialer).

**Migrations (V052+):**

```sql
notification_sender_keys(kid INTEGER PK AUTOINCREMENT,
                         secret_key_encrypted TEXT NOT NULL,   -- AES-GCM under master key, iroh_identity scheme
                         created_at TEXT NOT NULL, retired_at TEXT, revoked_at TEXT)
notification_registrations(did TEXT NOT NULL REFERENCES accounts(did),
                           device_uuid TEXT NOT NULL,
                           notification_public_key TEXT NOT NULL,  -- did:key multibase, validate_device_public_key
                           apns_token TEXT NOT NULL, apns_topic TEXT NOT NULL,
                           push_handle TEXT,                       -- NULL until relay registration succeeds
                           created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                           PRIMARY KEY (did, device_uuid))
admin_notification_registrations(admin_device_id TEXT PK REFERENCES admin_devices(id),
                                 notification_public_key TEXT NOT NULL,
                                 apns_token TEXT NOT NULL, apns_topic TEXT NOT NULL,
                                 push_handle TEXT,
                                 created_at TEXT NOT NULL, updated_at TEXT NOT NULL)
```

Sender secret keys are `SecretFamily` variants in `db/kek.rs` so `rewrap-master-key`
covers them. Retired = still published for verification, no longer used for sealing;
revoked = removed from the published set immediately (the design's compromise path).
`purge_account` gains `DELETE FROM notification_registrations WHERE did = ?` (plus a
relay `dropHandle` best-effort); `revoke_admin_device` cleanup deletes the admin row
the same way.

**Routes** (each with a `.bru`, seq 124+):

| route | auth | purpose |
|---|---|---|
| `POST /v1/notifications/register` | `authenticate_access` (DPoP) | body `{deviceUuid, notificationPublicKey, apnsToken, apnsTopic}`; upserts, triggers relay (re-)registration |
| `DELETE /v1/notifications/register/{deviceUuid}` | `authenticate_access` | drop registration + relay handle |
| `GET /v1/notifications/sender-keys` | `authenticate_access` | `{ keys: [{kid, publicKey}] }` — the re-pin surface, fetched on every app↔Custos contact |
| `POST /v1/admin/notifications/register` | `require_admin` (signed envelope) | admin-device analog, keyed by the authenticated device id |
| `GET /v1/admin/notifications/sender-keys` | `require_admin` | re-pin surface for the admin app |

**Sending:** `notifications.rs` module owns `notify_device(did, payload)` /
`notify_admin_devices(payload)`: load registrations, fetch active sender key, pad + seal
per device (fan-out, one seal per registration), enqueue to the relay worker. First
trigger: **agent claim pending** (the auth.md ceremony awaiting confirmation). The
MM-414 labeler trigger lands with admin-companion adoption.

## Crypto (`crates/crypto`)

New `hpke.rs` module wrapping the `hpke` crate (0.14.0, RustCrypto-based, MIT/Apache-2.0):
`seal_notification(sender_keypair, recipient_pubkey, plaintext) -> {enc, ct}` and
`open_notification(recipient_keypair, sender_pubkey, enc, ct)` (the open side exists for
tests and future non-NSE consumers), suite and `info` fixed as above, keys as the crate's
existing P-256 types. Check at implementation time that `hpke` 0.14 unifies on the
workspace's `p256` 0.13 / `aes-gcm` 0.10 / `hkdf` 0.12 line — if it drags a second major,
add a `deny.toml` guard-ban entry with rationale per the dependency-hygiene convention.
Padding arithmetic (`pad_len_for_bucket(unpadded_serialized_len) -> Option<usize>`) is a
pure function here too, with the 4 KB boundary among its table tests. Golden fixtures:
seal with pinned keys/nonce-free API, store `{keys, plaintext, enc, ct}` JSON in
`tests/fixtures/`, assert `open` round-trips — CryptoKit cross-verification happens
on-device in the wallet phase.

## The wallet (`apps/identity-wallet`)

- **Xcode template:** the forked `scripts/ios/project.yml` gains an NSE target
  (`{{app.name}}_NSE`, `type: app-extension`, Swift-only — no second Rust staticlib;
  decryption is CryptoKit, ~200 lines of Swift), `keychain-access-groups` entitlement on
  both targets (shared group), and both apps' `minimumSystemVersion` goes to 17.0.
  `just ios-template-check` learns the new invariants (NSE target present, entitlements
  wired) so a template re-render can't silently drop them.
- **Keys:** app generates the per-device notification P-256 keypair in Rust, stores the
  private key + the pinned sender-key set in the **shared access group** with
  `kSecAttrAccessibleAfterFirstUnlock` (net-new keychain surface next to `keychain.rs`'s
  current default-group items). `device_uuid` generated once, stored alongside.
- **Registration:** at onboarding completion (post-promotion) and on every APNs token
  change callback; re-pins sender keys on every successful Custos contact (the design's
  short-compromise-window property).
- **NSE:** loads keys from the shared group, HPKE-opens with `authenticatedBy:` the pinned
  sender key named by `kid`, replaces title/body. Any failure (unknown `kid`, open failure,
  post-reboot locked keychain) → the explicit unverified notice ("Couldn't verify a
  notification from your Custos instance") and a diagnostic breadcrumb written to a shared
  app-group container the app surfaces in Settings.

## Admin-companion

`Pairing` (the versioned `admin-pairings` keychain document) gains
`notification_sender_keys: Vec<{kid, publicKey}>` — a compatible addition (serde default;
doc version stays 1), refreshed per contact through `relay_client.rs`. One shared
notification keypair per device across pairings (the admin key model), registered
per-relay via the signed `POST /v1/admin/notifications/register`. The NSE target reuses
the template work verbatim (the template is shared by both apps). Server-side ops
triggers land here: labeler flags (MM-414's subset-of-upserts diff + seeding suppression,
batched per pass) and the health alerts from the mobile spec.

## Phasing → issues

Order pins the dependency spine; each issue is independently green (fmt, clippy, tests,
bruno parity where routes change).

1. **HPKE + padding in `crates/crypto`** — `hpke.rs`, suite pin, golden fixtures,
   padding arithmetic + 4 KB boundary test, deny.toml check.
2. **`crates/notify-relay` skeleton: iroh RPC + enrollment + handle store** — crate,
   migrations, ALPN accept loop + framing, `enroll`/`registerHandle`/`dropHandle`,
   claim-code CLI + open-enrollment mode, rate limits, loopback tests. (No APNs yet;
   `push` returns `apnsError`.)
3. **Relay APNs pipeline** — ES256 JWT client, push RPC end-to-end, serialized-size
   validation, 410 → `unregistered`, wiremock APNs tests incl. the 4 KB boundary.
4. **Custos sender** — `[notifications]` config, V052 migrations, sender-key set +
   rotation semantics, the five routes + bruno, outbound relay client + send worker,
   purge/revoke cleanup, agent-claim-pending trigger, full loopback e2e (pds ↔ relay ↔
   mock APNs).
5. **Wallet keys + registration** — shared keychain group, keypair + device_uuid,
   onboarding registration, sender-key re-pinning, iOS 17 minimum.
6. **Wallet NSE** — template NSE target + entitlements + template-check invariants,
   decrypt-and-render, unverified notice, diagnostics surface, CryptoKit↔Rust fixture
   cross-check, on-device demo.
7. **Admin-companion adoption** — pairing-doc pinning, admin registration routes/table
   consumption, admin NSE, labeler-flag + health triggers (unblocks MM-414).
8. **Ping mode** — per-registration `ping` preference, content-available sends, wake
   fetch.
9. **Relay deploy + operator docs** — relay Dockerfile + Railway service, self-relay
   runbook (deploy.md sibling), enrollment-ceremony docs.
