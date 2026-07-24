# MM-395 did:web migration rehearsal — record

**Status: COMPLETE — rehearsal identity migrated staging → production 2026-07-24 ~23:5x
UTC; cleanup pending.** A throwaway did:web identity
(`did:web:rehersal-production.up.railway.app`, handle = the same domain) was created on
staging Custos (`https://ezpds-staging.up.railway.app`) via the wallet's did:web ceremony
and then migrated to production Custos (`https://pds.obsign.org`) via the wallet's
outbound migration flow — the first live run of either did:web leg. The run surfaced
**five wallet defects**, all found only because the flow ran live against a real did:web
identity, all fixed and merged the same day (PRs #418, #419, #420, #422). The server-side
did:web pipeline needed no changes.

This is the did:web sibling of
[2026-07-17-mm-394-real-identity-migration.md](2026-07-17-mm-394-real-identity-migration.md)
(did:plc, real identity) and the dress rehearsal for the real
`did:web:malpercio.dev` migration off `pds.malpercio.dev`.

- Ticket: [MM-395](https://linear.app/malpercio/issue/MM-395)
- Design: [ADR-0002](../architecture/decisions/0002-wallet-authorized-account-migration.md)
  (path 1, self-signed identity leg — for did:web the "identity leg" is a hand-published
  document edit, not a PLC op)
- Tooling: the Obsign wallet (on device, three TestFlight cycles), a disposable Caddy
  static host on Railway serving the DID documents (`tools/didweb-rehearsal/`, PR #414),
  `curl`/`cmp` for byte-exactness and pass-condition checks

## Why a Caddy host on Railway

A did:web identity *is* its domain, so the rehearsal needed a domain with a fast,
scriptable file drop — which malpercio.dev's hosting is not, at the moment. A Railway
service's generated domain (`rehersal-production.up.railway.app`) served as the throwaway
DID itself: one container serves both `/.well-known/did.json` (`application/did+json`)
and `/.well-known/atproto-did` (handle proof), documents are **committed files** on the
branch Railway watches (PR #414, kept open as the deploy source), and the
paste → commit → push → `cmp` loop doubles as rehearsal for the real run's hand-edit of
the self-hosted `did.json`. Byte-exactness discipline: the wallet serializes
`JSON.stringify(doc, null, 2) + '\n'` and both the ceremony and the migration identity
leg verify the **live** document byte-for-byte, so every publish was validated with
`python3` (round-trip equality) before push and `cmp` against the live URL after deploy
(~20–60 s propagation).

## Leg 0 — did:web ceremony (staging)

The wallet's "sovereign domain identity" ceremony against staging: reserve pending
account → compose `did.json` → operator publishes it → wallet verifies the live copy →
`POST /v1/dids` promotes. First attempt failed with an opaque 400 (bug 1 below); after
PR #418 the ceremony completed. Server-side validation (structural checks + byte-exact
live fetch via the SSRF-hardened client) behaved exactly as designed — it correctly
rejected the mis-encoded document and accepted the corrected one.

Post-ceremony detours, both worth keeping for the real run:

- **Bluesky showed `handle.invalid`**: the first handle
  (`rehersal1.ezpds-staging.up.railway.app`) is a **two-label** subdomain under Railway's
  **single-label** wildcard cert (`*.up.railway.app`), so the AppView's TLS verification
  of the handle-proof fetch fails. Fixed by making the handle the domain itself. The real
  run is unaffected (malpercio.dev controls its own certs) but the class of failure —
  handle verification is a TLS client too — is a useful check.
- **did.json republish + `refreshIdentity`**: changing `alsoKnownAs` in the live document
  and force-refreshing on staging propagated the handle to the network (an `#identity`
  firehose frame) — the exact "edit the document by hand, then tell the PDS" loop the
  real migration's identity leg uses. The wallet, however, kept showing the stale handle
  (finding 7 below).

## Leg 1 — outbound migration (staging → production)

Wallet outbound flow on device: prepare → password source login (staging) → deactivated
destination account on `pds.obsign.org` via service auth + production claim code →
`importRepo` → blob drain → preferences → verify-import → did:web review screen → export
composed post-migration `did.json` → operator publishes byte-exactly → wallet verifies
live copy → submit → finalize (activate dest → persist destination session → deactivate
source).

Three successive wallet failures blocked the flow before it could start, each fixed in
its own PR and TestFlight cycle (bugs 2–5 below). Once past prepare, the transfer,
review, publish, verify, and finalize legs all passed on the first attempt.

**Identity leg** (published `dc9ed40` on the rehearsal branch, verified byte-exact live
before submission):

- `verificationMethod #atproto`: → `zDnaeSgAtvr87PFDbCWvVCHb9t9Npa6ik5QcpGVXEz7B7xSeW`
  (production's issued repo signing key; staging's key drops out — expected)
- `service #atproto_pds`: → `https://pds.obsign.org`
- `verificationMethod #device` (`zDnaeY2jnoijCdfj9zkZXrf2ZZ2Yct9Z4KZdgxAtRe3T1u52r`) and
  `alsoKnownAs` (`at://rehersal-production.up.railway.app`): **unchanged** — the did:web
  analogue of "wallet key stays at `rotationKeys[0]`"

## Pass conditions (recorded 2026-07-24 ~23:55 UTC)

```
GET https://pds.obsign.org/xrpc/com.atproto.sync.getRepoStatus?did=did:web:rehersal-production.up.railway.app
→ {"active": true, "rev": "3mrg6fgpjs7rk"}

GET https://ezpds-staging.up.railway.app/xrpc/com.atproto.sync.getRepoStatus?did=…
→ {"active": false, "status": "deactivated", "rev": "3mrg6fgpjs7rk"}   ← clean handoff, same rev

GET https://rehersal-production.up.railway.app/.well-known/did.json
→ serviceEndpoint https://pds.obsign.org, #atproto = production's key (byte-exact vs wallet export)

GET https://rehersal-production.up.railway.app/.well-known/atproto-did
→ did:web:rehersal-production.up.railway.app
```

Identical `rev` on both sides is the no-divergence proof: nothing was written to the
source after the import snapshot.

## Bugs found (all fixed and merged 2026-07-24)

| # | Defect | Where it bit | Fix |
|---|---|---|---|
| 1 | **`#device` encoded as bare base58 multibase** instead of the multicodec-prefixed did:key form — the server byte-compares against the stripped did:key, so `POST /v1/dids` 400'd a structurally valid, correctly published document. Both `prepare_did_web_ceremony` and `build_did_web_migration_document_cmd` had it | ceremony, first submission | PR #418 (merged) |
| 2 | **`detect_migration_path` was PLC-only** — fetched the plc.directory audit log unconditionally, so a did:web start died with "couldn't verify this identity's keys". Fix short-circuits did:web to `SelfSigned` via the wallet's own device key | migration entry | PR #419 (merged) |
| 3 | **Unmanaged did:web fail-open** (found by CodeRabbit review on #419): an `IdentityNotFound` for a did:web would have silently become `SelfSigned`; there is no interop fallback for did:web, so unmanaged → `CannotDetermine` | review of fix 2 | #419 follow-up `f1b568e` (merged) |
| 4 | **`discover_pds` was PLC-only** — `prepare_migration` resolved every DID via plc.directory, so the Migrate screen failed with a generic "network error". Fix resolves did:web from `https://<host>/.well-known/did.json` (hostname-form only; `:`/`/`/`@` shapes refused) | Migrate screen, attempt 1 | PR #420 (merged) |
| 5 | **`finalize_migration`'s durable-credential mint was PLC-only** — the sovereign session is rotation-key-signed, which a did:web account can never satisfy; the cutover would have failed at the last step, after transfer. Fix persists the migration-issued destination Bearer pair (sub/aud-validated) to the Keychain before source deactivation, same resume-safe idempotency as the sovereign path | found by audit while fixing 4 (same PR, saved a TestFlight cycle) | PR #420 (merged) |
| 6 | **`into_plc_doc` keyed services by bare-fragment ids only** — plc.directory serves `"#atproto_pds"`, a did:web document carries `"did:web:host#atproto_pds"`, so the `atproto_pds` lookup missed and `discover_pds` failed with the same generic "network error" (masking fix 4 until it was isolated) | Migrate screen, attempt 2 | PR #422 (merged) |

The lesson across all six: **the wallet's did:plc paths were load-bearing assumptions,
not abstractions** — every place that touched plc.directory, rotation keys, or
bare-fragment W3C ids broke on first did:web contact, and only a live run found them.

## Findings without code changes (backlog)

| Finding | Note |
|---|---|
| Stale `CUSTOS_BASE_URL` release default | `http.rs` still defaults to `https://obsign.org`, which stopped being a PDS when #409 moved production to `pds.obsign.org` (marketing now owns the apex — its `/xrpc/*` is a static 404) |
| `set_custos_client` OnceLock trap | Changing the PDS URL in-app doesn't take effect until a force-quit relaunch; cost one debugging detour ("couldn't reach the server to load handle domains") |
| Diagnostics gaps | The breadcrumb log missed every failure in this rehearsal: non-2xx branches in `get_available_user_domains` and `/v1/dids` (`DID_CREATION_FAILED` discards the server error body), and parse/`InvalidResponse` verdicts (bug 6) record nothing. Every wallet bug above was diagnosed from outside the app |
| Wallet caches the did:web document | After the `alsoKnownAs` republish + `refreshIdentity`, the network updated but the wallet kept the stale handle — no re-resolution of the live document |
| No did:web tamper monitoring | `plc_monitor` watches plc.directory only; a did:web identity's document (and its host) has no equivalent watch |
| did:web re-auth after refresh expiry | Open product question: the migrated account's only credential is the migration-issued Bearer chain (no rotation keys → no sovereign re-mint). When the refresh chain dies, re-auth needs an app password minted now, or a server-side did:web proof-of-domain login |
| Railway wildcard-TLS gotcha | Two-label subdomains of `*.up.railway.app` fail AppView handle verification (documented in the rehearsal README) |

## Post-run state / remaining steps

- Rehearsal identity live on production, staging source deactivated, documents live on
  the Caddy host. PR #414 stays open while the host is needed.
- **Cleanup (pending, operator-timed):** delete the throwaway account on production (and
  the deactivated staging remnant), delete the Railway rehearsal service, close PR #414.
- **Then the real run:** `did:web:malpercio.dev` from `pds.malpercio.dev` to
  `https://pds.obsign.org`, on a wallet build ≥ the #422 merge. Everything this
  rehearsal exercised transfers directly; the deltas to respect are the source being a
  reference PDS (password + email delivery under operator control, per MM-394) and the
  document edit landing on malpercio.dev's own hosting instead of the Caddy loop —
  byte-exactness discipline identical.
