# Running your own notification relay

**Last verified:** 2026-07-27

Pushing to an iOS app requires an APNs auth key belonging to the Apple developer team that
owns that app's bundle id. A self-hosted Custos instance has no such key for someone else's
app, so it cannot push directly and a relay is structurally required. This runbook takes an
operator from nothing to a working relay of their own — and explains, honestly, where that
stops short.

Crate internals: [`crates/notify-relay/AGENTS.md`](../../crates/notify-relay/AGENTS.md).
Deploying the whole stack: [`docs/deploy.md`](../deploy.md).

## Read this first: what a self-run relay can and cannot reach

A relay can only push to an app whose bundle id its Apple team owns. A token-auth key is
team-scoped — one key can serve every topic under your team (or a chosen subset, if you
created a topic-specific key) — but no key of yours authenticates a bundle id registered to
somebody else's team. So:

| You want to push to… | Works with your own relay? |
|---|---|
| Your own build of the wallet (your bundle id, your APNs key) | **Yes** — the whole path is yours. |
| A sandbox topic for testing (your bundle id, development build) | **Yes** — set `apns.sandbox = true`. |
| The official Obsign / admin-companion apps from the App Store | **No** — those bundle ids belong to another team, so only the official relay's key authenticates them. |

That is a fact about Apple's provider API rather than a choice this project made, and it is
why the official relay exists and why it is built as a **blind courier**. Payloads
arrive HPKE-sealed to a per-device key; the relay decrypts nothing, stores no DID, handle,
or account data, and holds no key material belonging to any instance or device. Concretely:

- **The official relay holds:** its own iroh node secret, its own APNs `.p8`, and a row per
  registered device — an opaque 128-bit handle, the APNs device token, the bundle-id topic,
  and timestamps. Plus, unavoidably, the metadata Apple sees anyway: which node id sent
  what volume, when, at what padded size.
- **The official relay cannot:** read notification content, forge authenticated content
  (HPKE Auth mode binds ciphertext to the instance's pinned sender key), or correlate a
  handle back to a person. It *can* drop, delay, or replay pushes, and it can emit junk
  that renders as the explicitly-marked unverified notice — availability failures and
  detectable spam, not impersonation.

If you run your own relay, you hold all of that for your own users, and you are the only
party who can.

## What you need

- A host that can run a container, or just a machine with the repo and `cargo`. **No
  inbound port is required** — the relay is dialed over QUIC by iroh node id and stays
  reachable through iroh's relay servers, so it works fine behind NAT.
- An Apple Developer account, and from it:
  - a **token-auth key** (`.p8`) created under Keys → Apple Push Notifications service,
  - its **Key ID** (the `kid`), and your **Team ID** (the `iss`),
  - the **bundle id** of the app build you will push to — that string is the APNs topic.
- A Custos instance with `[iroh] enabled = true` (the iroh endpoint is what dials the
  relay; Custos refuses to start with `notifications.relay` set and iroh off).

## 1. Configure and start the relay

Settings come from `notify-relay.toml` overlaid by `EZPDS_NOTIFY_*` environment variables,
which always win. A local file is the easiest starting point:

```toml
# notify-relay.toml
database_url = "notify-relay.db"
secret_key_path = "notify-relay-node.key"
# Enroll any instance that asks, with no code. Right when you and your tenants are the
# same party; see "Open enrollment" below before turning it on for anyone else.
open_enrollment = false

[apns]
key_path = "AuthKey_ABC1234567.p8"
key_id = "ABC1234567"
team_id = "DEF7654321"
# Bundle ids this relay is willing to push to. An empty list means "any topic" — fine when
# you own every app that could register, a footgun when you do not.
topics = ["dev.example.myapp"]
# Apple's sandbox host. Development builds get sandbox device tokens; a sandbox token sent
# to production (or the reverse) fails with BadDeviceToken, which is the single most
# common first-run mistake.
sandbox = true
```

Then:

```bash
cargo run -p notify-relay
```

It prints the line that matters:

```text
notify-relay node id: <64 hex characters>
```

That node id is your relay's address. Hand it to instances.

Two startup behaviours worth knowing:

- **Credentials are all-or-nothing and validated at startup.** A missing or malformed
  `.p8` makes the relay refuse to start, rather than coming up healthy and failing every
  push. With *no* APNs config at all it serves everything except `push`, which answers
  `apnsError` — the deliberate posture for standing a relay up before its key exists.
- **The node secret key file is created 0600 and refused if wider.** It is the relay's
  identity: lose it and the relay silently re-addresses itself, every enrolled instance
  keeps dialing the old node id, and nothing reports an error. Back this file up. The
  database, by contrast, is disposable — every row in it is re-derivable by re-enrollment.

## 2. The enrollment ceremony

Enrollment is closed by default: a fresh iroh identity costs nothing, so without a gate
anyone could register attacker-controlled device tokens and burn your APNs quota and topic
reputation. (Content was never at risk — this gate protects quota and reputation.) The
ceremony mirrors admin-device pairing, and in v1 it is deliberately manual.

**Operator side.** Mint one single-use code per instance, at the relay's own shell:

```bash
notify-relay mint-code --ttl 24h
```

```text
enrollment code: A3F9KD-8HZQ2M-XR4TVN-9WEB6C
expires at:      2026-07-28 18:04:11 UTC
single use — the first node to redeem it is enrolled, and it cannot be reused
```

There is no remote admin surface, by design: codes are minted where the relay runs, not
over the network. Twenty-four base32 characters in groups of six so a code can be read
aloud or pasted into a chat without transcription errors. Hand it to the instance operator
over a channel you already trust — it is a bearer grant, so anyone holding it can enroll a
node of their choosing.

**Instance side.** The operator adds it to their Custos config and restarts:

```toml
[notifications]
relay = "<the relay's node id>"
enrollment_code = "A3F9KD-8HZQ2M-XR4TVN-9WEB6C"
```

or, as environment variables:

```bash
EZPDS_NOTIFICATIONS_RELAY=<node id>
EZPDS_NOTIFICATIONS_ENROLLMENT_CODE=A3F9KD-8HZQ2M-XR4TVN-9WEB6C
```

The code is consumed on the first successful enroll. Leaving it configured afterward is
harmless — enrollment is idempotent for a node that is already enrolled — but it is not a
recovery mechanism: if the relay loses its database, the code goes with it, and the
instance's stored copy is then an unknown code that answers `denied`. Recovering from that
means minting fresh codes (see below).

**Refusals are shape-uniform on purpose.** An unknown code, a spent one, an expired one,
and an enroll with no code at all all answer `denied`. That is not an unhelpful error
message; it is what keeps probing from teaching an attacker which codes you have minted.
When an instance reports `denied`, the diagnosis is on your side: check the relay log and
`enrollment_codes` for the code's `consumed_at`.

### Open enrollment

`open_enrollment = true` (or `EZPDS_NOTIFY_OPEN_ENROLLMENT=true`) drops the gate entirely:
any node that asks is enrolled. This exists for the operator-is-the-tenant case — your own
relay serving your own instances — where minting a code to hand to yourself is ceremony
with no security content. Do not run it open on a relay whose node id is public and whose
APNs key you care about: rate limits bound the damage, but they are not authorization.

## 3. Verify end to end

1. **Relay is up.** The startup log line `notification relay listening` with your node id.
2. **The instance enrolled.** On the relay, `sqlite3 notify-relay.db 'select node_id,
   enrolled_at from enrollments;'` shows the instance's node id.
3. **A device registered.** Install your app build, complete onboarding (which registers
   the device's notification key with its Custos), and check `select handle, apns_topic,
   created_at from handles;` — one row, with your bundle id as the topic. The handle is
   opaque; there is nothing in that table identifying a person.
4. **A push lands.** Trigger a notification on the instance and watch the relay log. The
   push outcome names the failure when there is one:

| Outcome | Meaning | Usual cause |
|---|---|---|
| `unknownHandle` | No handle by that name owned by this node | Registration never landed, or the device was dropped |
| `notEnrolled` | The sending node has no enrollment here | The code was never redeemed, or you revoked it |
| `throttled` | A token bucket is empty | A send loop; defaults are 1 000/h per node, 60/h per handle |
| `unregistered` | Apple returned 410 | App uninstalled — Custos prunes the registration on this feedback |
| `apnsError` | Everything else from Apple, or no credentials configured | `BadDeviceToken` (sandbox/production mismatch), `TopicDisallowed`, expired `.p8` |
| `tooLarge` | The serialized request exceeded Apple's 4 KB | A payload that outgrew its padding bucket — a bug, not a config error |

## 4. Deploying it as a container

The relay ships its own image — the repo-root `Dockerfile` builds only the pds binary:

```bash
docker build -f crates/notify-relay/Dockerfile -t notify-relay .
```

Note the build context is the **repo root**: cargo resolves every workspace member even
for a single `-p notify-relay`.

The image runs as a non-root user, mounts state at `/data`, and takes both secrets as
environment variables that the entrypoint materializes into files — because platforms hand
out secrets as env vars while the relay reads them as paths:

| Variable | Holds |
|---|---|
| `EZPDS_NOTIFY_NODE_SECRET` | The 64-hex node secret key. **Set this.** Without it the key exists only on the volume, and a re-created volume silently re-addresses your relay. |
| `EZPDS_NOTIFY_APNS_KEY_P8` | The `.p8` PEM text, pasted verbatim (newlines and all). Written to `/run`, never to the volume. |
| `EZPDS_NOTIFY_APNS_KEY_ID`, `EZPDS_NOTIFY_APNS_TEAM_ID`, `EZPDS_NOTIFY_APNS_TOPICS`, `EZPDS_NOTIFY_APNS_SANDBOX` | The rest of the APNs block; topics is comma-separated. |
| `EZPDS_NOTIFY_OPEN_ENROLLMENT` | As above. |

If `EZPDS_NOTIFY_NODE_SECRET` disagrees with a key already on the volume, the container
refuses to start rather than pick one — silently overwriting would re-address a working
relay, and silently ignoring it would discard the secret you just set. Resolve it
deliberately: unset the variable to keep the volume's identity, or delete the file to
adopt the variable's, knowing every enrolled instance must then be re-pointed.

Minting a code against a deployed relay runs the same binary through the same entrypoint:

```bash
docker run --rm -v relay-data:/data notify-relay mint-code --ttl 24h
```

### On Railway

The official relay runs as a separate Railway service beside the PDS, the sites, and the
MCP sidecar. See [`docs/deploy.md`](../deploy.md) → "Notification relay" for the service
settings; the two that are easy to get wrong:

- **Railway Config File** → `crates/notify-relay/railway.toml`, with **Root Directory** left
  at the repo root. Otherwise the service inherits the repo-root `railway.toml`, which is
  PDS-specific.
- **No public networking, no health check path.** The relay serves no TCP port at all, so
  there is nothing to route to and nothing to probe. Liveness is the process plus the
  restart policy; the startup log line is the readiness signal.

There is deliberately no Litestream sidecar here. Everything in the relay's database is
rebuilt when instances re-enroll and devices re-register, so a volume is a convenience that
saves that round of re-enrollment — the node secret key is the only thing worth backing up.

## 5. Ongoing operations

**Rotating the APNs key.** Create the new `.p8` in the Apple developer portal, update
`EZPDS_NOTIFY_APNS_KEY_P8` and `_KEY_ID` together, and restart. The provider JWT is
re-derived at startup and refreshed every 50 minutes; there is no cached credential to
purge. Revoke the old key at Apple only after the new one has pushed successfully.

**Moving instances to a different relay.** The instance changes
`[notifications] relay` and re-enrolls; every device token re-registers at the new relay.
Nothing at the old relay decrypts anything anyway, so the migration leaks nothing — but do
tell the old relay's operator, since the stale handles there will keep receiving pushes
until they are dropped.

**Losing the relay's database.** No user data is at stake, but recovery is not automatic:
the enrollment codes are gone too, so every instance's stored code now reads as unknown.
Mint a fresh code per instance and have each operator set it before restarting — then
instances re-enroll and devices re-register on their next contact. (On a relay running
`open_enrollment`, this really is a plain restart.) Losing the *node secret key* is the one unrecoverable
case, and it is unrecoverable in a quiet way: the relay comes up healthy on a new identity
and simply never hears from anyone again. If it happens, generate the new identity, publish
the new node id, and have every instance operator update their config.

**Revoking an instance.** Delete its handles, then its enrollment row — in that order, since
`handles.node_id` references `enrollments`:

```sql
DELETE FROM handles WHERE node_id = '<node id>';
DELETE FROM enrollments WHERE node_id = '<node id>';
```

Every RPC but `enroll` requires enrollment, so the instance is cut off on its next request,
and any code it still holds is already spent. There is no remote revocation surface, for
the same reason there is no remote minting surface. Take the relay down, or accept that you
are writing to a live single-writer database, before running this against a deployment.
