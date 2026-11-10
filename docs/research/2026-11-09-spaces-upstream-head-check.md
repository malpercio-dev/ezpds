# Spaces upstream head check past the 2026-11-06 pin

Researched 2026-11-09 for MM-660. Sources are blobless clones of
`bluesky-social/proposals` (`main`) and `bluesky-social/atproto`
(`permissioned-data`), read with `git log`/`git diff`, plus two atproto.com
blog posts. The pins being checked are the ones recorded in §0 "2026-11-06
weekly watch" of
[`docs/design-plans/2026-07-17-permissioned-data-gap-analysis.md`](../design-plans/2026-07-17-permissioned-data-gap-analysis.md):
proposals `9e86df3`, atproto `a620ad3`.

Anything not read directly from a primary source is marked **unverified**.

## Summary

| Question | Answer |
|---|---|
| Proposals moved past `9e86df3`? | Yes, to `0634c26` (PR #132, merged 2026-11-06). One file, +58/−12: a new normative **Moderation** section. |
| atproto branch moved past `a620ad3`? | Yes, by one commit, `98ef3a6b`. TypeScript-only refactor of `packages/space`; `lexicons/` is unchanged. |
| Any of the eleven deltas altered? | No. PR #132 adds a twelfth item (label records, takedown baseline) and restates one sentence of delta 10. |
| `listWriters` | Prose only. Not a lexicon at head. It is the reference PDS's internal store method behind `com.atproto.space.listRepos`. |
| Sandbox | A hosted alpha PDS exists behind an invite code (hostname not public); a Docker image and a local multi-PDS dev-env are documented. |

## 1. What moved

### `bluesky-social/proposals`, `0016-permissioned-data/`

Head of `main` is `0634c26f7a922f696e2e6b50d36a35d68c4bca09` (2026-11-06
14:48 −08:00), "Merge pull request #132 from
bluesky-social/bnewbold/space-moderation". `git log 9e86df3..HEAD`:

| Commit | Date | Subject |
|---|---|---|
| `270e37a` | 2026-11-03 | 0016: space labeling and takedowns |
| `7a1a687` | 2026-11-03 | add reference link |
| `7a82fca` | 2026-11-03 | describe the actual label record type |
| `4a1a3ee` | 2026-11-04 | updates from review |
| `df2c192` | 2026-11-04 | try to clarify ambiguity around account labels |
| `f28b325` | 2026-11-06 | fold in recent addition from main branch |
| `fcad6b9` | 2026-11-06 | Merge branch 'main' into bnewbold/space-moderation |
| `0634c26` | 2026-11-06 | Merge pull request #132 |

All eight belong to PR #132. `git diff 9e86df3 0634c26` touches only
`0016-permissioned-data/README.md` (58 insertions, 12 deletions). The old
non-normative "Moderation" subsection under the closing cross-cutting
discussion is deleted and replaced by a top-level `## Moderation` section
placed between space deletion and OAuth scopes. What it says:

- A moderation service is just another reader: it must hold a space
  credential, so the authority has to admit it under the normal access rules.
  No universal reporting interface is specified.
- A space authority can exclude an account. In restricted spaces that covers
  reading and writing; in public-access spaces it only means keeping the
  account out of the sync writer set.
- **Label records.** Labels on space data are records of type
  `com.atproto.label.record` written by the labeler's account into **the same
  space** as the subject. Fields: `uri` (required), `cid` (optional), `val`
  (required), `cts` (required), `exp` (optional). They are not individually
  signed; the repo they sit in authenticates them. Labels that reference a
  record across a space boundary must be ignored. For duplicate
  `(uri, cid, val)` in one repo, indexers use the newest by `cts`.
- A labeler's account must be in the space's writer set for its labels to
  sync. The authority is implicitly in the writer set and can always publish
  labels; by convention it may publish `!takedown` labels, which syncers and
  clients should respect.
- Labelers should not publish public labels (`subscribeLabels`) for records in
  non-public spaces.
- How labels on whole accounts work is left open. Label records must only be
  used with space data for now.
- **Takedowns** baseline. Account hosts: account takedown affects all spaces
  and space repos; blob takedown works on space blobs as on public ones.
  Space repo sync errors use the public names (`RepoTakendown`,
  `RepoDeactivated`). Space hosts: taking down an authority account should
  affect all its spaces. App services: account, per-space and per-record
  takedown.

There is no `com.atproto.label.record` lexicon file on the atproto branch at
`98ef3a6b`; `lexicons/com/atproto/label/` holds only `defs.json`,
`queryLabels.json` and `subscribeLabels.json`. The record type exists in
proposal prose only.

Not merged, not analysed: `git ls-remote` shows pull refs #136 to #141 on the
proposals repo. Their heads match the branches `0016/lex-refactor` (#136),
`0016/sdk-refactor` (#137), `0016/continuous-notify-register` (#138),
`bnewbold/app-access-control` (#139), `webhook-notifs` (#140) and
`0016/macs-http-signatures` (#141). Whether each is open or closed is
**unverified** (a pull ref does not say). #136 is a second attempt at the
lexicon refactor that #133 landed and #135 reverted, so the next watch should
expect lexicon renames.

### `bluesky-social/atproto`, branch `permissioned-data`

Head is `98ef3a6b9d1364f0543f137dd024de9651b21c4c` (2026-11-06 15:43 +01:00),
"Remove `zod` from `@atproto/space`s public interface". It is the only commit
in `a620ad3..HEAD`, and the only one touching `packages/space`. No commit in
that range touches `lexicons/com/atproto/`
(`git diff --stat a620ad3 HEAD -- lexicons` is empty).

The commit changes five files: a changeset, a new `constants.ts`, a new
`schemas.ts`, and edits to `index.ts` and `types.ts`. The zod schemas move
into an unexported module and are exposed through a `Def<T>` wrapper; `Commit`
becomes a plain type instead of a zod inference. Constant values are unchanged
(`REPO_STAR_TYPE = 'atproto-space-repo'`,
`SPACE_META_STAR_TYPE = 'atproto-space-meta'`, `SPACE_META_VERSION = 1`), as
are the three metadata shapes (`{$type, ver, repo, space, rev, data}`,
`{$type, ver, space}`, `{rev, data, spaceRev}`) and the STAR limits. No wire
or digest behaviour changes.

Lexicon file counts at head match the 2026-11-06 entry: 31
`com.atproto.space.*`, 5 `memberspace`, 2 `managedspace`, 1 `personalspace`.

### Effect on the eleven deltas

| # | Delta | Altered? |
|---|---|---|
| 1 | KEM shared secret + MAC | No |
| 2 | Space-authority resolution | No |
| 3 | Credential request/presentation | No |
| 4 | Public spaces | No. #132 restates that in a public-access space, exclusion only removes the account from the writer set. |
| 5 | Pluggable policies | No. The "authority is always authorized to write" rule is now also stated as "implicitly included in the writer set". |
| 6 | STAR repo format | No. `98ef3a6b` refactors the metadata schemas without changing them. |
| 7 | `clearRecords` | No |
| 8 | `removeWriter` | No. New consequence: a labeler dropped from the writer set stops having its labels synced. |
| 9 | Account migration | No |
| 10 | Deletion hardening and suspension | No. The `RepoTakendown`/`RepoDeactivated` sentence moved into the new Takedowns subsection with the same meaning. The suspension paragraph is untouched. |
| 11 | `listSpaces` includes authority spaces | No |

New since the pin and belonging to none of the eleven: space label records and
the takedown baseline, described above. For Custos the immediate points are
that `com.atproto.label.record` is one more collection a space repo may hold
(it has no lexicon to validate against yet), and that blob takedown is
expected to cover space blobs.

## 2. `listWriters`

Prose only, and a leftover name for `listRepos`.

- The string appears once in the proposal at head (README line 1015, the
  suspension paragraph: the space host answers `getSpaceCredential` and
  `listWriters` with `RepoTakendown` or `RepoDeactivated`). It also appeared
  once at `9e86df3`; PR #132 did not touch it. Everywhere else, including the
  XRPC method table (line 802) and the writer-set section (line 597), the
  proposal says `com.atproto.space.listRepos`.
- No `listWriters.json` exists under `lexicons/com/atproto/` at `98ef3a6b`.
- In the reference PDS, `listWriters` is the actor-store method that reads the
  `space_writer` table (`packages/pds/src/actor-store/space/reader.ts:277`).
  The `com.atproto.space.listRepos` handler calls it
  (`packages/pds/src/api/com/atproto/space/listRepos.ts:16`), as does the
  policy manager (`packages/pds/src/space-policy/manager.ts:157`).
- The two lexicons that declare the suspension errors are exactly
  `getSpaceCredential.json` and `listRepos.json` (each lists `RepoTakendown`
  and `RepoDeactivated`).

So the suspension sentence means `listRepos`. Custos should return the two
errors from `getSpaceCredential` and `listRepos` and implement no
`listWriters` endpoint.

## 3. A target for an interop CLI

**Hosted.** The proposal README names no sandbox; it links only the
implementation PR (`bluesky-social/atproto#5187`) for draft lexicons and calls
the implementation "very much a work in progress". The alpha announcement
(<https://atproto.com/blog/atproto-spaces-alpha>, 2026-08-20) says to get an
invite code and a link to the alpha PDS from a Bluesky Protocol Services
account page (<http://bsky.network/account>). No hostname is published in the
post. It also points at a demo app, <https://bulletin.my/>, with source at
`bluesky-social/bulletin`. This was read through a summarising fetch tool, so
the wording is **unverified** against the raw page, and the account page was
not opened (it needs a login). Whether the hosted alpha PDS tracks branch head
(KEM/MAC, STAR, policies) or an older snapshot is **unverified**; the post
warns the branch "may temporarily diverge" from what is published.

**Docker image.** The same post names
`ghcr.io/bluesky-social/atproto:pds-spaces-alpha`, described as compatible
with the reference PDS distribution (`bluesky-social/pds`) with no new
configuration, and npm packages under the `alpha` dist-tag. The image was not
pulled, so which commit it was built from is **unverified**.

**Local, from the branch.** `packages/dev-env` at `98ef3a6b` has a multi-PDS
entry point, `src/bin-multi-pds.ts`, run by the package script
`start:multi-pds` (`node --enable-source-maps dist/bin-multi-pds.js`, optional
PDS count argument, default 3). It is not documented in the package README,
which covers only the single-network REPL, and there is no Makefile target for
it (`make run-dev-env` runs the plain `start` script). From the source, it
starts:

- a PLC server on port 2582 and an introspection server on 2581;
- a primary PDS at `http://localhost:2583` plus extra PDSes on free ports with
  handle domains `.test2`, `.test3`, …;
- a `lex-authority.test` account on the primary PDS that hosts lexicon
  documents, including space declarations, with each PDS's
  `lexiconDidAuthority` pointed at it;
- seeded accounts `alice`, `bob` and `carol` on every PDS, with fixed
  passwords printed at startup.

Unlike `start`, the `start:multi-pds` script does not wrap itself in
`dev-infra/with-test-redis-and-db.sh`. No environment gate for spaces was
found in `packages/pds/src/config/`. This is the closest thing to a
cross-PDS spaces target, and it is the only option known to match branch
head. The PDSes serve plain `http://localhost` and resolve handles and DIDs
through mocked network utilities, so an interop CLI aimed at it needs to
accept http loopback origins and the local PLC URL. It was read, not run:
that it builds and boots at `98ef3a6b` is **unverified**.

The 2026-11-06 post "A Jetstream for Spaces"
(<https://atproto.com/blog/space-sync>) names no hosted sync endpoint; its
sample reads the URL from an environment variable (also read through the
summarising fetch tool).

## Sources

- `git clone --filter=blob:none https://github.com/bluesky-social/proposals.git`, `main` @ `0634c26`
- `git clone --filter=blob:none --single-branch --branch permissioned-data https://github.com/bluesky-social/atproto.git` @ `98ef3a6b`
- `git ls-remote https://github.com/bluesky-social/proposals.git` (branch and pull refs)
- <https://atproto.com/blog/atproto-spaces-alpha>
- <https://atproto.com/blog/space-sync>
