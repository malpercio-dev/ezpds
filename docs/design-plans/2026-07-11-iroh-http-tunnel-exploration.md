# Exploration: apps ↔ Custos over iroh tunnels (HTTP-over-iroh)

**Status: exploration / assessment — no commitment.** Written to durably capture a research
session on whether the two iOS apps should talk to Custos over iroh instead of (or alongside)
public HTTPS. Verdict up front: **not the general API, not now** — but there is one narrow,
genuinely valuable pilot (admin-companion break-glass transport), and the door is already
half-open.

## What already exists (this is not greenfield)

- `iroh = "1"` is a workspace dependency; the PDS binds an opt-in QUIC endpoint
  (`crates/pds/src/iroh_tunnel.rs`, `[iroh] enabled` / `EZPDS_IROH_ENABLED`) with a
  persistent encrypted node identity (`iroh_identity`, V022) so the node id is stable
  across restarts. Design plan: `docs/archive/design-plans/2026-06-26-MM-119.md`.
- The node id is already advertised to devices: `GET /v1/devices/:id/pds` returns
  `irohEndpoint` (`crates/pds/src/routes/get_device_pds.rs`).
- The current ALPN `ezpds/iroh/0` speaks only a v0.1 echo/liveness protocol; the module
  comment reserves future ALPNs for "real repo-sync / push protocols".
- The roadmap already assigns iroh **purpose-built** roles, not API tunneling:
  device↔device LAN transfer with PDS-mediated fallback (`docs/data-migration-spec.md`)
  and desktop-enrolled blob forwarding (`docs/blob-handling-spec.md`).
- iroh 1.0 shipped 2026-06-15 (stable wire protocol, official Swift/Kotlin/Python/Node
  bindings), so the dependency bet is materially safer than when MM-119 landed.
- Railway compatibility is already documented: iroh needs only **outbound** UDP plus the
  n0 discovery/relay servers (`docs/deploy.md`) — no inbound UDP port required.

## What "apps talk HTTP over iroh" would look like

**Server.** Add an `ezpds/http/0` ALPN next to the echo protocol. For each accepted bidi
stream, serve the *same* axum `Router` via hyper's `serve_connection` (HTTP/1.1 over the
stream, using a small `AsyncRead + AsyncWrite` adapter over iroh's send/recv halves). No
third-party bridge required. (The community `iroh-h3` crates do HTTP/3-over-iroh for axum,
but they're a small-maintainer dependency; a hand-rolled h1 bridge is ~100 lines and keeps
the supply chain unchanged.) Route parity, auth guards, rate limiting, and Bruno coverage
all carry over because it is literally the same `Router`.

**Client.** Each Tauri Rust backend binds its own iroh `Endpoint` and gains a
"dial-by-node-id" HTTP path beside reqwest: try iroh (if a node id is known), fall back to
HTTPS on dial failure/timeout. reqwest can't dial iroh, so this is either a custom hyper
client over the iroh stream, or a loopback forwarder (less clean). Both apps do all HTTP
from Rust (never the webview), so the change is confined to `http.rs` / `relay_client.rs`.

**Discovery.**
- admin-companion: add the relay's iroh node id to the pairing QR / pairing record
  (alongside `relayUrl`) or fetch it post-pairing; per-relay storage already exists
  (multi-relay pairings, ADR-0017).
- identity-wallet: `GET /v1/devices/:id/pds` already returns `irohEndpoint`, but it's
  device-token-authed; a pre-auth spot (e.g. `describeServer` or a `.well-known`) would be
  needed for first contact.

**Auth composes cleanly — no changes needed.** The admin signed-request envelope binds
`method + path + timestamp + nonce + body-hash` and deliberately **not** scheme/host
(ADR-0018), so a signed request is valid over either transport. The wallet's DPoP-bound
access tokens similarly bind method+URI at the proof layer. Bonus: the relay's node id in
the pairing record is effectively **certificate pinning** — the QUIC channel is
authenticated by the relay's key, independent of WebPKI/DNS.

**Hard limits — why this can never replace HTTPS:**
- The **OAuth ceremony cannot ride iroh**: identity-wallet auth runs in
  ASWebAuthenticationSession (a system browser), which speaks HTTPS to the real origin.
  Only post-auth API traffic could tunnel.
- **Federation requires the public HTTPS endpoint regardless**: relay crawling,
  plc.directory, handle resolution, service proxying, other PDSes. iroh is additive,
  never a removal of public exposure for a hosted deployment.
- n0 relay/discovery infrastructure becomes an availability + metadata dependency for the
  tunnel path (~10% of connections relay when holepunching fails).
- A second transport is a second code path to test, plus iOS background-socket/battery
  behavior to validate on-device.

## Assessment

**General API tunneling for both apps against the hosted Railway deployment: not worth it.**
The public HTTPS endpoint must exist anyway (federation + OAuth), TLS is already rustls
against a Railway-terminated edge, and the marginal wins (QUIC connection migration across
Wi-Fi↔cellular, DNS/CA independence) don't pay for a parallel transport in both apps.

**Where it is worth something, in descending order:**

1. **admin-companion as a break-glass transport (the pilot, if any).** An operator console
   that still reaches the relay when DNS is broken, the cert expired, or the edge is
   misconfigured is a real ops story — exactly the moments an operator needs the console.
   Smallest surface: one client, transport-agnostic signed auth, no browser flows, per-relay
   pairing records ready to carry a node id, and `/v1/admin/health` over iroh doubles as an
   out-of-band liveness check. This is a bounded, honest version of the feature.
2. **The already-planned purpose-built protocols** (device transfer, blob desktop mode,
   possibly firehose push to devices) — this is the existing trajectory and remains the
   best use of the endpoint; keep investing there rather than generalizing to HTTP.
3. **Self-hosted/home relays behind NAT** (no domain, no public IP, no cert) — the scenario
   where iroh-as-primary-transport is transformative and on-ethos. But it collides with the
   full-PDS federation posture (ADR-0007): a crawlable PDS needs public HTTPS. Park until a
   "private relay" deployment mode is a real product question.

**Recommendation.** Don't build HTTP-over-iroh now. Keep the echo ALPN + purpose-built
protocol direction. If appetite emerges, scope the admin-companion break-glass pilot as its
own issue: `ezpds/http/0` ALPN + hyper bridge on the server, node id in the pairing
document, iroh-then-HTTPS fallback in `relay_client.rs`, and an explicit "transport" note in
the security docs (node-id pinning vs WebPKI).
