# Spaces alpha watch routine

**Last verified:** 2026-08-20

A cloud-hosted Claude Code Routine (fresh remote session per run, surviving any
one machine — unlike the machine-local routines in
[`scheduled-agents.md`](scheduled-agents.md)) that tracks the **Atproto Spaces
alpha** release cadence. The alpha ships updates on **Thursdays**
([announcement](https://atproto.com/blog/atproto-spaces-alpha)); this routine
runs **Fridays at 14:00 UTC** and re-diffs the spec so the gap analysis and the
Wave 10: Spaces implementation issues never silently drift from upstream.

- **Schedule:** `0 14 * * 5` (Fridays 14:00 UTC)
- **Mode:** fresh session per fire, in the ezpds remote environment; push
  notification on completion.
- **Watches:** the `0016-permissioned-data` proposal in
  `bluesky-social/proposals` (the canonical spec, kept in sync with the
  reference implementation) and the `permissioned-data` branch of
  `bluesky-social/atproto` (lexicons + `packages/space`).
- **Output:** nothing when the week is quiet; otherwise a PR updating
  [`docs/design-plans/2026-07-17-permissioned-data-gap-analysis.md`](../design-plans/2026-07-17-permissioned-data-gap-analysis.md)
  (dated entries in its §0 spec-delta log + corrections to affected sections)
  with implementation impact on the Wave 10 issues named in the PR body.
- **Retirement:** delete the Routine when Spaces reaches its official launch
  and the gap analysis is superseded by implementation docs (or fold the watch
  into a release-note check at that point).

**Prompt (recreate verbatim if the Routine is lost):**

> You are the weekly Atproto Spaces alpha watcher for the ezpds repository
> (Custos PDS). The Spaces alpha ships updates on Thursdays; you run on Friday
> to catch this week's changes.
>
> Context: `docs/design-plans/2026-07-17-permissioned-data-gap-analysis.md` is
> the living gap analysis pinned to the Spaces spec. Its §0 is a dated
> spec-delta log naming the proposals-repo commits it was last synced against.
> Implementation is tracked in Linear (team MM, project ezpds, label "Wave 10:
> Spaces", issues MM-506…MM-518); the issue breakdown is §7 of that doc.
>
> Steps:
> 1. In the ezpds checkout, `git fetch origin main` and read the gap-analysis
>    doc from `origin/main`. Note the newest proposals-repo commit its §0
>    references.
> 2. `git clone --filter=blob:none
>    https://github.com/bluesky-social/proposals` into scratch space and diff
>    `0016-permissioned-data/` from that last-synced commit to HEAD.
> 3. If the proposal changed, also sparse-clone the `permissioned-data` branch
>    of `bluesky-social/atproto` (paths `lexicons/` and `packages/space/`) and
>    check whether the lexicon file set, golden test vectors, or endpoint
>    surface moved relative to what the doc claims.
> 4. If there are NO material changes: finish with a one-line "no spec changes
>    this week" report. Do not commit, push, or open a PR.
> 5. If there ARE material changes: update the doc — append dated entries to
>    §0 and correct every affected section (repo format, auth, endpoints,
>    scopes, phasing, risks, §7 issue rows). Branch
>    `claude/spaces-alpha-watch-YYYYMMDD` from `origin/main`, run
>    `scripts/docs-check.sh`, commit, push, and open a PR titled "Spaces alpha
>    watch: spec deltas for YYYY-MM-DD". In the PR body, summarize each delta
>    and name the Wave 10 issues it affects. Docs-only changes need no
>    changelog fragment.
> 6. If the Linear connector is available in your session, also comment the
>    relevant deltas on the affected Wave 10 issues; if it is not, the PR body
>    is the record.
>
> Follow the repo conventions in CLAUDE.md / AGENTS.md throughout.
