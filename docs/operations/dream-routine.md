# Nightly "dream" routine (Claude Code Routine)

**Last verified:** 2026-07-17

Every night, an unattended Claude Code session wakes up, picks **one vertical
slice** of this repository, walks its whole stack — backend crates, app
frontends, code comments, AGENTS.md files, `docs/`, the Bruno collection, and
the docs/marketing sites — and leaves a **small, reviewable pull request** that
improves the *information* about that slice for both agent and human consumers.
A human reviews it over coffee in the morning.

The name is deliberate: like sleep consolidating memory, the routine's job is
consolidation — finding stale claims, duplicated facts, missing connective
tissue, and confusing prose, and fixing them while the codebase is quiet. It
never changes behavior.

## Why this exists

The repo's deterministic gates (`just docs-check`, `bruno-check`,
`ticket-ref-check`, …) enforce *coverage* — every route has a reference entry,
no ticket refs leak into source. They cannot judge whether prose is still
*true*, whether three files state the same fact where one should be canonical,
or whether a comment narrates *what* instead of *why*. That is judgment work,
and it drifts silently as code moves. A nightly agent pass keeps the drift
bounded to about a day per vertical, and the PR-per-night shape keeps the human
cost to one small review.

This is the same division of labor as the
[release-docs routine](release-docs-routine.md): the agent proposes, the
deterministic gates enforce the mechanical half, the human judges the prose.

## Shape of a night

1. **Preflight** — if two or more `dream:` PRs are still open, the routine
   skips the night entirely rather than piling up review debt.
2. **Choose a vertical** — informed by recent code churn (docs drift where code
   moves) and by rotation (recent `dream:` PR titles show which verticals were
   just visited).
3. **Investigate the full vertical** — code and comments, frontend screens,
   AGENTS.md sections, `docs/` specs/ADRs, Bruno entries, `sites/docs` and
   `sites/marketing` prose — verifying every claim against the code on
   `origin/main` that night.
4. **Edit information surfaces only** — never behavior. Aim for one coherent
   theme and roughly ≤300 changed lines.
5. **Gate and open the PR** — cheap deterministic gates locally, full CI on the
   PR. Everything noticed but *not* changed lands in a "Field notes" section of
   the PR body for human triage.

A **dreamless night is a valid outcome**: if the chosen vertical is in good
shape, the routine reports that and opens nothing. It is explicitly told not to
invent work.

## Guardrails

- **Information surfaces only.** Code comments, AGENTS.md/CLAUDE.md, `docs/`,
  Bruno request docs, `sites/docs` prose, conservative `sites/marketing`
  factual corrections, READMEs, doc comments. No renames, refactors,
  dependency/lockfile changes, CI logic changes, or new tooling — tempting code
  smells go in the PR's field notes instead.
- **Verify, never guess.** Every claim the routine touches must be checked
  against the code as it exists on `origin/main` that night.
- **Generated pages are regenerated, not hand-edited** (`just docs-generate`).
- **No PR pile-ups** — skip the night at two open `dream:` PRs.
- **No Linear writes.** Findings that deserve issues are listed in the PR body;
  the human promotes them. (Nightly automated issue-filing would spam the
  backlog, and headless sessions may not have the Linear connector anyway.)
- **Repo rules still apply:** no ticket/AC references in `.rs` comments, the
  Obsign and Brass Console design registers stay separate, `flake.lock` is
  never edited by hand, marketing-surface changes need a changelog fragment.

## Configuring the Routine

The routine runs as a **fresh-session-per-fire Claude Code trigger** in a
Claude Code cloud environment scoped to `malpercio-dev/ezpds`. Each firing
starts a brand-new session with no memory, so the prompt below is the whole
spec.

**Connector caveat:** the prompt prefers the GitHub MCP connector (listing and
opening PRs), but a trigger created via the MCP tools may store no connector
grants, in which case fired sessions run without `mcp__github__*` tools. The
prompt degrades gracefully — the `claude/dream/<date>-<slug>` branch naming
doubles as the PR ledger for the preflight/rotation checks, and if the routine
cannot open the PR itself it pushes the branch and reports a ready-to-paste PR
title/body plus the compare URL. To get true end-to-end PR creation, create
the Routine from the claude.ai Routines UI (which attaches connectors) using
the same prompt.

- **Schedule:** `0 8 * * *` (nightly, 08:00 UTC ≈ overnight in the US; adjust
  to taste — the only constraint is "done before the reviewer's morning").
- **Mode:** fresh session per fire (`create_new_session_on_fire`), completion
  notification by email so the morning inbox links the PR.
- **Prompt:** the block below, verbatim. Keep it version-controlled here so the
  routine's instructions are reviewable and change with the repo rather than
  drifting inside a web-UI text box. If the prompt and this file's guardrails
  ever disagree, the file wins — and the trigger should be updated to match.

To pause or remove it, disable or delete the trigger from the Claude Code
Routines UI (or via the `update_trigger`/`delete_trigger` MCP tools from any
session in the account).

## The Routine prompt

```text
You are the ezpds nightly "dream" routine — a fresh, unattended session running
overnight. Pick ONE vertical slice of this repository, walk its whole stack
(backend, frontend, docs, sites), and leave a small, reviewable pull request
that improves the INFORMATION about that slice — code comments, AGENTS.md
files, docs/, the Bruno collection, and the docs/marketing sites — for both
agent and human consumers. A human reviews the PR in the morning. The durable
spec for this routine is docs/operations/dream-routine.md; if its guardrails
and this prompt ever disagree, follow the file.

0. Preflight — decide whether to dream at all.
   - Get tonight's UTC date with `date -u +%F`.
   - `git fetch origin main`.
   - Count still-open dream PRs on malpercio-dev/ezpds — titles start with
     "dream:" (GitHub MCP, list_pull_requests). If GitHub MCP tools are
     unavailable in this session, approximate via git instead:
     `git fetch origin '+refs/heads/claude/dream/*:refs/remotes/origin/claude/dream/*'`
     then count `git branch -r --no-merged origin/main | grep claude/dream` —
     every dream branch encodes its date and vertical, so branches double as
     the PR ledger. If TWO or more are still open/unmerged, stop: review debt
     is piling up. Open nothing; end with a one-line report.

1. Choose tonight's vertical.
   - Read the last ~10 dream PR titles (or, without GitHub MCP, the
     claude/dream/<date>-<slug> branch names fetched in step 0) to see which
     verticals were recently visited; do not repeat one from the last two
     weeks unless it has had major churn since.
   - Read recent churn: `git log --oneline --since="14 days ago" origin/main`
     and the range's `--stat`. Documentation drifts where code moves.
   - Pick ONE vertical slice — examples, not an exhaustive list: account
     lifecycle & auth (OAuth/DPoP/auth.md), key sovereignty & recovery
     (Shamir/escrow/KEK), the repo/blob engine, migration, federation &
     handles, admin pairing & the Brass Console screens, identity-wallet
     onboarding, the MCP servers (stdio + sidecar), deploy & release, the dev
     environment & CI gates, the design token systems, or the docs/marketing
     sites themselves.
   - Prefer the vertical where recent code churn is highest relative to how
     recently its documentation was touched.
   - Then create your working branch from origin/main:
     claude/dream/<date>-<short-vertical-slug>.

2. Investigate the full vertical, top to bottom: the crate code and its
   comments, the app frontend screens that surface it, the relevant AGENTS.md
   sections (root and per-crate/app), everything under docs/ that describes it
   (specs, architecture docs, ADRs, archived plans), the bruno/ entries for its
   routes, and what sites/docs and sites/marketing say about it. You are
   hunting information defects:
   - statements the code no longer supports (stale claims, renamed things,
     dead paths, outdated "currently"/"still open" notes);
   - the same fact stated in several places where one should be canonical and
     the others should link to it;
   - missing connective tissue (a subsystem with no pointer from AGENTS.md or
     docs/, a route behavior an agent would need but that is written nowhere);
   - comments that narrate WHAT the next line does instead of the WHY or the
     constraint the code can't show;
   - prose a first-time reader (human or agent) would genuinely misread.
   Verify every claim you touch against the code on origin/main tonight —
   never "fix" documentation by guessing.

3. Make the edits. Scope is information surfaces ONLY:
   - IN scope: code comments and doc comments, AGENTS.md / CLAUDE.md files,
     docs/ (generated reference pages excepted — regenerate those with
     `just docs-generate`, never hand-edit), bruno/ request docs, sites/docs
     prose, sites/marketing copy (conservative factual corrections only — do
     not rewrite voice), README files.
   - OUT of scope: any behavior change — no renames, no refactors, no
     dependency or lockfile changes, no CI/workflow logic changes, no
     flake.lock, no new tooling. If a code smell tempts you, record it in the
     PR's field notes (step 5) instead of fixing it.
   - Repo rules: no ticket/AC references in .rs comments (ticket-ref-check
     enforces this); keep the Obsign and Brass Console design registers
     separate; bump a file's "Last verified:" date only for content you
     actually verified tonight.
   - Keep the diff reviewable over coffee: one coherent theme, roughly ≤300
     changed lines. Cut lower-value edits before exceeding that and note them
     in the PR body instead.

4. Gate it.
   - Run the cheap deterministic gates relevant to what you touched — at
     minimum `just docs-check`, `just changelog-check`, `just bruno-check`,
     and `just ticket-ref-check`; add others from `just checks` if your edits
     are in their blast radius. Docs/comment-only changes need no changelog
     fragment, but sites/marketing copy changes DO (changelog.d/README.md;
     with no Linear issue, the fragment is named after the PR number — open
     the PR first, then push the fragment).
   - If you touched .rs files, run `cargo fmt --all --check`. Full clippy/test
     runs are unnecessary for comment-only edits — CI covers them on the PR.

5. Open the PR — this is the deliverable.
   - Commit with clear messages; `git push -u origin <branch>`.
   - Title: `dream: <vertical> — <one-line summary>`.
   - Body: (a) which vertical you chose and why (churn/rotation evidence);
     (b) each change grouped by kind — stale-fact fix, consolidation,
     clarification — with a one-line rationale citing the code that makes it
     true; (c) a "Field notes" section for everything you noticed but did NOT
     change (out-of-scope code smells, larger doc restructurings, possible
     bugs) so a human can triage it — do not file Linear issues from this
     routine; (d) the gate commands you ran and their results.
   - If GitHub MCP tools are unavailable and you cannot open the PR yourself:
     still push the branch, then end with the complete PR title and body in
     your final report plus the compare URL
     (https://github.com/malpercio-dev/ezpds/compare/main...<branch>) so the
     human can open it in one click. The pushed branch is the deliverable.
   - If, after honest investigation, the vertical is in good shape and no edit
     clears the bar: do NOT invent work. Push nothing, open no PR, and end
     with a short report of what you checked. A dreamless night is fine.

Guardrails, restated: information surfaces only; verify against code, never
guess; one small reviewable diff; skip the night at two open dream PRs; no
Linear writes; never hand-edit generated reference pages or flake.lock; never
force-push; when intent is genuinely ambiguous, describe the ambiguity in the
PR body rather than resolving it unilaterally.
```

## Reviewing the morning PR

Read it as a *draft for judgment*:

- **Stale-fact fixes** — spot-check the cited code; these should be
  uncontroversial merges.
- **Consolidations** — the real review surface: agree (or not) with which copy
  of a fact became canonical, and check that the links left behind still make
  the reader's path shorter, not longer.
- **Marketing copy** — hold to the same bar as the release-docs routine:
  deliberate voice, accept factual corrections, push back on anything that
  smells like a rewrite.
- **Field notes** — triage: promote to Linear (project `ezpds`, wave label),
  fold into an existing issue, or drop. This is where the routine's
  out-of-scope observations become tracked work instead of being lost.

If a night's PR shows the routine misjudging scope or tone, fix the prompt
*here* first, then update the trigger to match — the file is the source of
truth, the web-UI text box is a copy.
