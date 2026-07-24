# didweb-rehearsal — throwaway did:web document host

A minimal Caddy static file server for standing up a **throwaway did:web identity**
on a Railway-generated domain, so the did:web migration flow can be rehearsed
end-to-end without touching `malpercio.dev`'s hosting or `pds.malpercio.dev`.

The service serves exactly two meaningful paths:

| Path | Purpose |
|---|---|
| `/.well-known/did.json` | The did:web DID document (`application/did+json`) |
| `/.well-known/atproto-did` | ATProto handle verification (`text/plain`, body = the DID) |

Because a did:web DID *is* its hostname, deploying this on a Railway domain like
`didweb-rehearsal-production-xyz.up.railway.app` yields the identity
`did:web:didweb-rehearsal-production-xyz.up.railway.app`, whose handle is the same
domain — no DNS records, no separate hosting, nothing owned by the real identity.

## Railway setup (once)

1. Railway → New Service → GitHub repo `malpercio-dev/ezpds`.
2. Service settings → **Root Directory**: `tools/didweb-rehearsal` (the Dockerfile
   builder is auto-detected). Set the watched **branch** to whichever branch these
   files live on, so a push redeploys the documents.
3. Settings → Networking → **Generate Domain**. The generated hostname is the
   identity: `did:web:<generated-domain>`.
4. Sanity check: `curl https://<domain>/.well-known/did.json` returns the
   placeholder; `/` answers `did:web rehearsal document host`.

No environment variables, no start command; the Caddy image's default command
runs the committed `Caddyfile`. TLS terminates at Railway's edge (`auto_https off`
inside — the resolvers follow no redirects, so the container must answer plain
200s on `$PORT`).

## The byte-exactness rule (read before editing)

The wallet verifies the published `did.json` **byte-for-byte** against the
document it composed (`submit_did_web_migration_document_cmd` compares
`live.as_bytes()`; the ceremony completion does the same). The wallet serializes
documents as `JSON.stringify(doc, null, 2)` **plus a trailing newline**.

So: when the wallet shows you the document to publish, replace
`site/.well-known/did.json` with **exactly** that text — 2-space indentation,
key order untouched, one trailing newline, no editor "formatting help".
`file_server` serves file bytes verbatim, and git preserves them, which is the
reason this setup uses committed files instead of env-var-injected bodies.

## Rehearsal loop

1. **Create the throwaway** (wallet did:web ceremony, "new identity ×
   self-hosted", against staging): when the wallet presents the composed
   document, paste it into `site/.well-known/did.json`, put the DID into
   `site/.well-known/atproto-did` (single line, trailing newline is fine — the
   resolver trims), commit, push, wait for the Railway deploy (~30–60 s), then
   let the wallet verify and promote.
2. **Seed content**: a few posts and 2–3 blobs (avatar + images) so the
   migration has a repo and a blob drain to exercise.
3. **Rehearse the migration** (staging → production per the MM-395 sequence):
   at the identity leg, the wallet composes the post-migration document
   (endpoint → the destination, `#atproto` → the destination's recommended
   key). Same loop: paste, commit, push, wait, verify. This edit-and-republish
   cycle is itself rehearsal for the real run's hand-edit of
   `malpercio.dev/.well-known/did.json`.
4. **Clean up**: delete the throwaway account on the destination, then delete
   the Railway service. The DID dies with the domain — that impermanence is
   fine for a rehearsal and exactly why a `*.up.railway.app` DID must never
   hold a real identity.

## Non-goals

Not part of `just ci`, not a workspace crate, never deployed alongside the PDS
services. This is disposable rehearsal scaffolding; keep it boring.
