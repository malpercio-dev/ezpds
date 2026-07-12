# E2E-Encrypted Notification Relay for Self-Hosted Custos

Status: **design exploration** — not yet scheduled into a wave. Captures the architecture
discussion of 2026-07-10 so it survives the session (capture-before-close).

## Problem

Self-hosted Custos instances need to deliver push notifications to the official iOS apps —
Obsign (identity-wallet) and the admin-companion. The mobile architecture spec already
anticipates APNs pushes for PDS health alerts ("desktop offline", "storage cap approaching",
docs/mobile-architecture-spec.md §6.3), and the agent-auth surface adds more triggers (claim
ceremonies awaiting confirmation, agent activity, revocations).

APNs is structurally centralizing: pushes to a bundle ID can only be sent by a party holding
an APNs auth key (`.p8`) issued under the app's Apple developer account. A self-host operator
can never hold the key for the official Obsign bundle ID. So push delivery for the official
apps **requires a relay** operated by whoever holds the APNs key — and the design question is
how to make that relay *untrusted for everything except availability*:

1. **Confidentiality** — the relay (and Apple) must not be able to read notification content;
   only the Custos operator's instance and the receiving app can.
2. **Integrity** — the relay must not be able to forge or alter a notification.
3. **Sovereignty** — the relay is open source, any operator can run their own, and a Custos
   instance chooses its relay by configuration.

## Shape

Three parties:

```text
┌──────────────┐  iroh QUIC (ezpds/notify/0)  ┌───────────────┐  HTTP/2 + .p8 JWT  ┌──────┐
│ Custos (PDS) │ ───────────────────────────▶ │ notify-relay  │ ─────────────────▶ │ APNs │
│  self-hosted │      sealed ciphertext       │ holds APNs key│    ciphertext      └──┬───┘
└──────▲───────┘                              └───────────────┘     envelope          │
       │ device enrolls {apns_token, hpke_pubkey}                                     ▼
       │ over the existing authenticated device channel               ┌────────────────────────┐
       └──────────────────────────────────────────────────────────── │ iOS app + Notification  │
                                                                      │ Service Extension (NSE) │
                                                                      │ decrypts on delivery    │
                                                                      └────────────────────────┘
```

The relay never sees a key that can decrypt, and never sees an identity (DID/handle) — only
an opaque push handle, ciphertext, and timing.

### 1. Device enrollment (app ↔ its own Custos)

- The app generates a dedicated **per-device notification HPKE keypair** (P-256). It is a
  *software* keychain key — not Secure Enclave — stored in a **shared keychain access group**
  with `kSecAttrAccessibleAfterFirstUnlock`, because the Notification Service Extension must
  decrypt while the device is locked and without a biometric prompt. This is the standard
  Signal-style NSE pattern; the key protects notification content only, never identity
  material, so software custody is proportionate.
- The app obtains its APNs device token from iOS and registers
  `{apns_token, apns_topic, notification_public_key}` with its own Custos over the existing
  authenticated device channel (new route; new columns/table beside `devices`, which already
  stores a per-device P-256 public key). The **APNs topic** (the app's bundle ID) travels
  with the registration because the relay serves more than one app (Obsign and the
  admin-companion have distinct topics) and APNs requires the `apns-topic` header on every
  token-authenticated request — the relay must know which topic each handle routes to.
- **Post-reboot gap:** `AfterFirstUnlock` keys are unavailable between a reboot and the
  first unlock, so a push landing in that window renders the placeholder text (iOS shows
  the original payload when an NSE fails); the app reconciles the actual content from its
  Custos on next unlock. Accepted for v1 — the window is rare and short, and the
  alternative (`Always` accessibility) is deprecated and weaker at rest.
- In the same exchange the app **pins the instance's notification sender public key set**
  (served by Custos). Each sender key carries a **key id**, and sealed payloads name the
  key id that authenticates them. Pinning is not one-shot: the app re-fetches the current
  sender-key set over the authenticated device channel whenever it talks to its Custos, so
  rotation and revocation propagate without re-enrollment (see Key lifecycle).

### 2. Instance enrollment (Custos ↔ relay, over iroh)

- Opt-in via config: `[notifications] relay = "<relay node id>"` (default unset → feature
  off, matching the `[iroh]` opt-in posture).
- Custos dials the relay over **iroh** on a new ALPN, e.g. `ezpds/notify/0`. This reuses
  what already exists: the workspace has iroh, the PDS persists a stable Ed25519 node
  identity (`iroh_identity`, V022), and `iroh_tunnel.rs` establishes the accept-loop pattern.
  The **node id is the instance's identity** at the relay — stable, self-certifying mutual
  authentication with no TLS certificates, DNS names, or public routability required on the
  Custos side (important: Custos instances are mobile-first and often behind NAT).
- Custos registers each device's `{apns_token, apns_topic}` once and receives back an
  opaque, random **push handle bound to that instance's node id**. The relay stores
  `handle → (apns_token, apns_topic)` and holds an APNs key valid for each topic it serves;
  Custos stores only the handle and never retransmits the raw token. Binding handles to the
  registering node id means one enrolled instance cannot push to (or probe for) another
  tenant's devices even if it learns their APNs tokens.

### 3. Sending (Custos → relay → APNs)

- On a notification-worthy event, Custos builds a plaintext JSON payload
  (`{type, title, body, data}`), **pads it to a fixed-size bucket**, and seals it with
  **HPKE (RFC 9180), DHKEM(P-256, HKDF-SHA256) + AES-GCM, in Auth mode** using the
  instance's static notification sender key. P-256 keeps us inside the existing stack
  (CryptoKit on iOS ≥17 ships an HPKE API with authenticated modes; the Rust `hpke` crate
  covers the server side; `crates/crypto` already owns P-256 + AES-256-GCM primitives).
- Custos sends `{push_handle, ciphertext, encapsulated_key, priority, ttl}` to the relay
  over the iroh connection. Multi-device accounts fan out as one seal per device — no shared
  group keys needed at this scale.
- The relay validates size and rate limits per node id, then wraps the ciphertext into an
  APNs request. **Size budgets are defined on the fully serialized APNs payload** — the
  `aps` envelope, custom keys, and base64 expansion of the ciphertext fields all count
  toward APNs' 4 KB cap, so the padding buckets are chosen so the *encoded request* lands
  on a bucket boundary under the cap (with a boundary test at exactly 4 KB in phase 1),
  not the sealed plaintext alone:

  ```json
  {
    "aps": { "alert": { "title": "Custos", "body": "Encrypted notification" },
             "mutable-content": 1 },
    "ezpds": { "v": 1, "enc": "<b64 encapsulated key>", "ct": "<b64 ciphertext>" }
  }
  ```

  The `aps.alert` text is a generic placeholder — Apple never sees plaintext either.

### 4. Receiving (NSE decrypts on the fly)

- `mutable-content: 1` routes the push through the app's **Notification Service
  Extension**. The NSE loads the notification private key and the pinned sender public key
  from the shared keychain, HPKE-opens the payload, verifies origin, and replaces the
  placeholder title/body with the decrypted content before the banner is shown. This is
  exactly "the app decrypts payloads on the fly."
- **Failure handling** — an important iOS constraint frames this: an NSE **cannot
  suppress** an alert push. If the extension fails, times out, or declines to attach
  content, iOS displays the original payload (our generic placeholder) anyway. So
  "suppress invalid payloads" is not on the menu; the design instead controls *what*
  surfaces. A payload that fails decryption or origin verification is rendered as an
  explicitly-marked **unverified** generic notice ("Couldn't verify a notification from
  your Custos instance") — never as authentic-looking content — and the app records a
  local diagnostic surfaced in-app so repeated failures (key desync, misbehaving relay)
  are visible and debuggable rather than mysterious.

## Trust model

What the relay **can** do (and what we accept):
- Deliver, drop, delay, or reorder notifications — it is trusted for **availability only**.
- Observe metadata: sender node id, target push handle/APNs token, timing, frequency, and
  padded size. Padding buckets + no persistent per-send logs (beyond rate-limit counters)
  keep this to the minimum APNs itself already observes.

What the relay **cannot** do:
- Read content — HPKE-sealed to the device key; the relay holds no decryption key.
- Forge or alter **authenticated content** — HPKE **Auth mode** binds the ciphertext to
  the instance's pinned sender key, so nothing the relay fabricates or modifies ever
  renders as content from the user's Custos. Two honest qualifications:
  - **It can still generate noise.** The relay holds the APNs key, so it can always send
    junk pushes (with or without our envelope), and iOS will not let the NSE suppress
    them — they surface as the explicitly-marked unverified notice, never as authentic
    content. That is detectable spam and grounds for switching relays, not impersonation.
  - **It can replay.** HPKE adds no anti-replay guarantee, so a captured sealed payload
    can be redelivered. v1 explicitly accepts duplicate authenticated notifications as
    benign (a repeated banner, no state change — notifications drive no writes); a
    per-device monotonic counter inside the sealed payload is the upgrade path if that
    stops being acceptable (see Open questions).
- Correlate handles to identities — Custos never sends DIDs, handles, or account data to
  the relay.

A compromised **Custos instance** can read/forge its own users' notifications — but the
instance is the operator's own trust root already; nothing new is ceded.

**Metadata-minimizing mode (optional, per user or per instance):** send a content-free
`content-available` ping instead of a sealed payload; the app fetches the actual events from
its Custos over HTTPS/iroh on wake. Maximum privacy (the relay sees only "something
happened"), but iOS aggressively throttles background pushes, so visible-alert quality
suffers. Offering both modes lets users pick their point on the privacy/UX curve; the sealed
payload is the default.

## Sovereignty and openness

- The relay is a new open-source crate in this workspace (working name
  `crates/notify-relay/`): the same axum + iroh + SQLite stack, reusing the persisted-node-
  identity pattern. Anyone can run it.
- Any Custos instance can point at any relay via `[notifications] relay = "<node id>"` — the
  official one, a friend's, or the operator's own.
- **Honest caveat:** a self-run relay can only push to apps whose APNs key it holds. Pushing
  to the *official* Obsign/admin-companion bundle IDs requires the official relay. Full
  end-to-end self-hosting of notifications means shipping your own build of the app (own
  bundle ID + APNs key) — possible, since everything is open source, but not the default
  path. The E2E encryption is precisely what makes the default acceptable: the official
  relay is a **blind courier**, trusted for availability and nothing else.
- Enrollment/abuse control at the relay: the **official relay requires explicit
  enrollment authorization** — an operator-issued claim-code ceremony mirroring the
  admin-device pairing flow, binding the instance's node id to an enrollment grant.
  Rate limits alone are not authorization: freshly minted iroh identities are free, so an
  unauthenticated attacker could otherwise register attacker-controlled tokens and burn
  the relay's APNs quota and topic reputation (the E2E design means this gate protects
  quota and reputation, not user data — content was never at risk). Per-node-id rate
  limits and payload caps remain as supplemental controls, and **open enrollment stays
  available as a relay config option** for private/self-run relays where the operator and
  the tenants are the same party. APNs `410 Unregistered` feedback flows back over the
  same iroh connection so Custos prunes dead registrations — one concrete reason the
  bidirectional iroh channel beats fire-and-forget HTTPS POSTs from NATed instances.

## Key lifecycle

| Event | Handling |
|---|---|
| APNs token changes (restore, reinstall) | App re-registers with Custos; Custos re-enrolls at the relay; old handle expires. |
| Notification key rotation (device) | App generates a new keypair, re-registers; Custos seals to the new key immediately. Old key deleted after overlap window. |
| Sender key rotation (instance) | Sender keys are versioned by **key id**; payloads name the key id that seals them. Custos publishes the new key alongside the old on the authenticated device channel; devices re-pin on their next contact; Custos switches to sealing with the new key once devices have had the overlap window (or immediately, accepting placeholder renders for stale devices until they re-pin). The old key is then removed from the published set. |
| Sender key compromise (instance) | Custos removes the compromised key id from the published set (no overlap); devices drop it at next re-pin and treat payloads naming it as unverified from that moment. Pre-re-pin, a compromised sender key + colluding relay could forge content for that window — which is why re-pinning happens on every device↔Custos contact, keeping the window short. |
| Device revoked / transferred | Existing device-revocation paths also delete the notification registration and tell the relay to drop the handle. |
| Instance changes relay | Re-enroll all tokens at the new relay; nothing at the old relay decrypts anything anyway. |
| Relay key/state loss | Handles are re-derivable by re-enrollment; no user data at stake. |

## Why iroh for the Custos↔relay leg

1. **NAT traversal** — self-hosted (and eventually mobile-hosted) Custos instances rarely
   have a public address; iroh dials by node id and holepunches, and the relay needs a
   channel *back* to the instance (delivery feedback, `Unregistered` pruning).
2. **Mutual auth for free** — stable Ed25519 node ids on both ends; no cert management, no
   DNS, no shared secrets to provision. The instance's persisted iroh identity already
   exists (`iroh_identity` table).
3. **Already in the stack** — dependency, config surface (`[iroh]`), accept-loop pattern,
   and offline loopback test harness all exist in `crates/pds/src/iroh_tunnel.rs`.

The payload security does **not** depend on the transport: sealed payloads are protected
end-to-end regardless. Iroh is defense-in-depth plus reachability, so a plain-HTTPS relay
API could be added later for instances that prefer it, without touching the crypto.

## Open questions

- **Enrollment grant distribution** — how operators of the official relay hand out
  claim codes (manual request? tied to a listing of known instances?); the ceremony
  itself mirrors admin-device pairing.
- **Admin-companion** — same mechanism (it's the natural consumer of the ops alerts); its
  pairing flow already exchanges per-device keys with each paired server, so
  notification-key pinning slots into the existing pairing document. Needs its own bundle-ID topic at the relay.
- **Android/FCM later** — the sealed envelope is push-provider-agnostic; an FCM leg is a
  relay-side addition, not a protocol change.
- **Replay hardening** — v1 accepts duplicate authenticated notifications as benign (see
  Trust model); open whether a later version adds a per-device monotonic counter inside
  the sealed payload (NSE rejects non-monotonic), which needs a durable replay window on
  the device.
- **Delivery receipts** — the iroh back-channel could carry them; deliberately out of scope
  for v1 (APNs itself gives no end-delivery guarantee).

## Suggested phasing (when scheduled)

1. **Relay crate + Custos sender.** `crates/notify-relay/` (claim-code enrollment grants,
   handle store with per-handle APNs topic, APNs HTTP/2 client, per-node rate limits,
   serialized-request size validation with a 4 KB boundary test) + Custos `[notifications]`
   config, device notification-key registration route, versioned sender-key set, sealed-send
   queue on the first trigger (agent claim pending). Loopback iroh tests end-to-end with a
   mock APNs.
2. **Wallet NSE.** Keypair + shared keychain group, registration in onboarding, the
   decrypt-and-render extension, failure fallback copy. On-device demo.
3. **Admin-companion adoption + operator docs.** Ops alert triggers, self-relay runbook
   (docs/deploy.md sibling), metadata-minimizing ping mode.
