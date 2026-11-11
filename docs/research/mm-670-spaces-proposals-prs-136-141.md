# Spaces proposal PRs 136–142 vs. our space-repo MAC decisions

Researched 2026-11-10 (US time; GitHub timestamps below are UTC and run into 2026-11-11). Sources are the PRs, diffs, and review threads on `bluesky-social/proposals`, read with `gh pr view`/`gh pr diff`/`gh api`, plus the matching `bluesky-social/atproto` PRs. All the PRs edit a single file, `0016-permissioned-data/README.md`.

Our pin: proposals `9e86df3`, atproto `permissioned-data` @ `a620ad3`.

## What we decided to build

1. A per-account P-256 `#atproto_kem` Multikey in the DID doc. The repo host holds the private key.
2. The shared secret is ECDH between a fresh ephemeral syncer key and the KEM key, then HKDF-SHA256 with the RFC 9180 §4.1 DHKEM(P-256) labels (`eae_prk`, `shared_secret`).
3. Headers: the request carries `Atproto-Space-Want-Mac: type=…, ver=1, key_share="did:key:…"`. The response carries `Atproto-Space-Mac` with the base64 HMAC, plus `Vary`.
4. MAC inputs:
   - commit: `HMAC(ss, "atproto-space-repo-v1" || u16be-prefixed(space, repo, rev) || data)`
   - record: `HMAC(ss, "atproto-space-record-v1" || u16be-prefixed(uri) || cid_bytes)`

## Upstream movement since the pin

- **Proposals `main`** is now `5bae1ca`. #132 (moderation) and #139 (access control) merged after `9e86df3`, and neither touches KEM or MAC text. `gh api compare 9e86df3...5bae1ca` shows no `kem`/`mac`/`Want-Mac`/`shared_secret` lines.
- **atproto `permissioned-data`** is now `8459446`, 23 commits ahead of `a620ad3`. It merged #5800 ("lexicon review") and #5812 ("Refactor SDK") on 2026-11-11 at about 00:05 and 00:20 UTC. **The reference implementation already ships the lexicon renames from proposals #136 and #137, which are still unmerged in the spec.**

## Per-PR findings

| PR | Title | State | Touches our decisions? | Landing signal |
|---|---|---|---|---|
| 136 | 0016: Lex refactor | open, approved | **No.** Renames only (see below) | Re-approved by bnewbold 2026-11-06. It is a re-open of #133, which merged and was reverted by #135 as an accident. The impl, atproto#5800, merged. Very likely to land. |
| 137 | 0016: Tweaks from SDK refactor | **draft** | **No** | Includes #136's commit. Its impl, atproto#5812, merged. Likely, once #136 merges. |
| 138 | 0016: Continuous notification registration | open, approved | **No** | bnewbold approved the direction but objected to the "credential lifespan + 1 notification" rule as less reliable than an explicit expiry. Likely, possibly reworked. |
| 139 | 0016: access control in applications | **merged** 2026-11-11 00:50 | **No** | Done. Prose only. |
| 140 | 0016: Webhook notifications | open, no approval | **No** | Stacked on #138. bnewbold: "I don't really love this change, though I would not block it." Uncertain. |
| 141 | 0016: Move MACs to HTTP Signatures | open, **approved ×2** | **Yes:** header names, MAC inputs, credential-signature label | Approved by matthieusieben (2026-11-10) and bnewbold (2026-11-11: "I think this is a big improvement!"). Author dholms opened the impl, atproto#5862, the same day. Very likely to land. |
| 142 | 0016: HPKE Secret Export | open, no reviews yet | **Yes:** derivation output bytes | Stacked on #141 (base `0016/macs-http-signatures`), opened 2026-11-11 02:02. No impl PR yet. Uncertain but plausible: the same author with the same momentum. |

No other open proposals PR touches KEM or MAC. The only other open PR is #91, "0015 repo migration pds". Every PR above is by dholms except #139, which is by bnewbold.

### #136: Lex refactor
It renames:

- `credentialKid` → `credentialKey` in the `getSpaceCredential` body
- `notifyWrite` → `notifyRepoUpdate`
- `notifySpaceDeleted` → `notifySpaceStatus` with `status: deleted`
- `notifyCredentialRevoked` → `notifyCredentialsRevoked`
- `listRepos` → `listWriters`
- `putMember`/`removeMember` → `putMembers`/`removeMembers`
- `checkUserAccess` → `checkAccess`

It also makes small wording changes to the `personalspace` and `managedspace` policies. It changes nothing in KEM or MAC. Its impl, atproto#5800, merged. (Main's takedown text from #134 already says `listWriters`.)

### #137: SDK refactor errata (draft)
Space-type `name`/`name:lang` becomes `title`/`title:lang`, and the field is now optional. The writer-value `rev` becomes `repoRev`. #137 also carries #136's renames. It changes nothing in KEM or MAC. Its impl, atproto#5812, merged, including the "make title optional" commit.

### #138: Continuous notification registration
It drops `registerNotify`/`unregisterNotify`. Instead, `getSpaceCredential` takes an optional `notifyService`, and each credential request renews the registration until "credential lifespan + 1 notification". A syncer unregisters by letting the registration lapse or by answering a notification with a permanent HTTP error. It changes nothing in KEM or MAC.

### #139: Access control in applications (merged)
It adds a section saying applications must enforce their space type's access semantics and the protocol-level rules in the views they serve. Prose only.

### #140: Webhook notifications
It replaces service-endpoint + service-auth notification with `notify: { endpoint, token }`, an opaque bearer token chosen by the syncer, so syncers no longer need a DID. It changes nothing in KEM or MAC.

### #141: Move MACs to HTTP Signatures

The commit and record MACs become RFC 9421 HTTP Message Signatures using `hmac-sha256`, keyed with `shared_secret`.

The syncer requests a MAC with:
```http
Accept-Signature: mac=("atproto-space-commit";sf);keyid="did:key:zDna...";tag="atproto-space-repo"
```

The host answers with:
```http
Atproto-Space-Commit: ver=1, repo="did:…", space="at://…", rev="3mwcj3b6uak2f", data=:q3J0...=:
Signature-Input: mac=("atproto-space-commit";sf);keyid="did:key:zDna...";tag="atproto-space-repo"
Signature: mac=:…32 bytes…:
Vary: Accept-Signature
```

Records use the `atproto-space-record` tag. The covered header is `Atproto-Space-Record: uri="at://…", cid="bafyrei..."`, where the CID is a **string**, not binary.

Against our decisions:

- **KEM key in DID doc: unchanged.** `#atproto_kem` and the host holding the private key are the same.
- **Derivation: unchanged.** Only the transport field is renamed, `key_share` → `keyid`, still a P-256 `did:key`, still fresh per request, retry, and page.
- **Header names: replaced.** `Atproto-Space-Want-Mac`/`Atproto-Space-Mac` are gone. The new set is `Accept-Signature` → `Atproto-Space-{Commit,Record}` + `Signature-Input` + `Signature`, with `Vary: Accept-Signature`. The response reuses the label and parameters the syncer requested, and the syncer finds the MAC by `tag`. The request may carry only `keyid`, `tag`, and `alg`, and `alg` must be `hmac-sha256` if present. The host must error when the header is missing or malformed, has more than one request with the profile's tag, or names an invalid key.
- **MAC inputs: replaced.** The HMAC input is now the RFC 9421 signature base over the `sf`-normalised covered header, not our u16be framing. The PR body says the point is not having to specify concatenation. The commit `ver` moves into the covered dictionary, and the `-v1` context strings disappear. bnewbold floated putting `-v1` suffixes on tags but called it possibly unnecessary.
- **`listRepoOps`: changed.** Every page now carries the commit and a MAC. The old "pages without a commit have no MAC" rule is dropped. The syncer verifies after the last page, the one without a `cursor`.
- **Space-credential signature: also changed.** Its label is now `sig`. The host selects the signature by `tag="atproto-space-credential"`, not by label, because "intermediaries may relabel signatures". If `keyid` is present it must equal `cnf.kid`, and other parameters are ignored.

Review threads still open as of this writing:

- Copilot (high severity), seconded by bnewbold: the record path must explicitly recompute the CID from the returned record's canonical DRISL encoding, because the MAC now authenticates only the header.
- bnewbold: commit verification should also check that `rev` matches.
- matthieusieben: argued for a mandatory `alg`. bnewbold disagreed, so `alg` stays optional and implied by the profile.

**Reference implementation:** atproto#5862 "Atproto Spaces: Move MACs to HTTP Signatures" (branch `atproto-spaces-mac-http-sigs` → `permissioned-data`, opened 2026-11-11 01:35, no reviews yet). It rewrites `packages/space/src/mac.ts` and `http-signature.ts`, the PDS handlers, and the lexicon error descriptions. `kem.ts` changes only by a comment, so the derivation is unchanged. Its changeset says the new headers "replace" the old pair, and that the PDS exposes them through `Access-Control-Expose-Headers`.

### #142: HPKE Secret Export (stacked on #141)
The hand-rolled ECDH+HKDF becomes HPKE base-mode Secret Export:

- ciphersuite: KEM `0x0010`, KDF `0x0001`, AEAD `0xFFFF` (export-only)
- `info="atproto-space-mac"`, `exporter_context=""`, `L=32`
- `enc`, the ephemeral P-256 public key, is sent as the `keyid` `did:key`

A non-normative appendix spells out the plain ECDH/HKDF steps. The PR body calls it "functionally very similar".

**But the output bytes differ from ours.** Our `shared_secret` is the DHKEM `ExtractAndExpand` output. Under #142 that value becomes only the HPKE `kem_secret`. On top of it run:

- the base-mode key schedule: `psk_id_hash` and `info_hash`, then `secret`, then `exporter_secret`
- the export: `LabeledExpand(suite_id, exporter_secret, "sec", "", 32)`

A host built to our derivation would produce MACs that a #142 syncer rejects. The wire shape stays the same: the ephemeral key travels as `keyid`, the DID-doc key and the ECDH are unchanged, and the KEM key itself is unaffected. No atproto implementation PR exists yet: no `hpke` branch, and #5862 has no HPKE references.

## Recommendation: (b) build behind a seam

#141 has two approvals, including bnewbold's, and its author has a reference implementation open. It will very likely land and replace both our header names and our MAC input encoding. #142 sits on top of it and would change the derivation's output. Building exactly as pinned guarantees a rewrite. Waiting is unnecessary, because the KEM key, ECDH, and HMAC-SHA256 core is stable across every PR here.

The seam must abstract three things:

1. **Secret derivation:** `(ephemeral P-256 pubkey, KEM private key) → [u8; 32]`. Pinned DHKEM-only now, HPKE export if #142 lands. Pin it with an RFC 9180 test vector.
2. **MAC request parsing:** request headers → `{profile, ephemeral key, echo label/params}`. Today that is `Atproto-Space-Want-Mac`; under #141 it is `Accept-Signature` selected by `tag`.
3. **MAC response emission:** a commit `{ver, space, repo, rev, data}` or a record `{uri, cid}` → response headers. Today that is `Atproto-Space-Mac` over the u16be context. Under #141 it is the covered SF header + `Signature-Input`/`Signature` over the RFC 9421 base, plus the per-page commit on `listRepoOps`. Both cases add `Vary` and the CORS expose list.

The fixed core underneath is `#atproto_kem` key management, ECDH, and HMAC-SHA256. #141 also reshapes the space-credential signature: label `sig`, selected by tag. Its RFC 9421 base and structured-field codec should be shared with the MAC path, not built twice.

## Also noticed

- Custos's credential verifier (`crates/custos-spaces/src/auth/http_signature.rs`) looks the signature up by the fixed label `SIGNATURE_LABEL = "atproto-space"` and does not check `tag`. The pinned spec at `9e86df3` already uses label `atproto-space-credential` with `tag="atproto-space-credential"`, and #141 moves to label `sig` with selection by tag. The verifier appears to reject spec-conformant clients today. This is separate from the MAC work.
- atproto `permissioned-data` moved past our pin today, ahead of the spec. A conformance pass pinned to `a620ad3` will miss the #136/#137 renames that the reference now emits.
