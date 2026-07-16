# Release-time docs/marketing review pass (Claude Code Routine)

**Last verified:** 2026-07-16

The release ritual gains one agentic step: at release time, an agent regenerates
the *derived* documentation and screenshots, reads what actually shipped in the
release range, drafts the *hand-authored* prose that needs to move with it, and
opens a pull request. A human **reviews** that PR rather than authoring the docs
pass from scratch.

This is Phase 5 (Level 2 — agentic) of the documentation-sites design
([`docs/design-plans/2026-07-14-documentation-sites.md`](../design-plans/2026-07-14-documentation-sites.md),
docs.AC6). It lands last, on purpose: the deterministic generators and parity
gates from Phases 1–4 are the safety net that keeps the agent honest. The agent
proposes; `docs-check`, the changelog gate, and the screenshot visual-diff
enforce coverage; the human judges the prose.

## Where it fits in the release flow

The ordered documentation steps are documented in the release runbook
([`docs/deploy.md`](../deploy.md) → *Release-time documentation pass*):

1. **Roll the changelog** — `just set-version X.Y.Z` folds `changelog.d/`
   fragments into a dated `## [X.Y.Z]` section of `CHANGELOG.md`.
2. **Regenerate derived docs + screenshots (gates green)** — `just docs-generate`
   and `just docs-screenshots`, then confirm `just docs-check` and
   `just docs-screenshots-check` pass.
3. **Docs/marketing review pass** — decide which hand-authored guides and
   marketing pages need edits for this release, and draft them.

This Routine performs steps 2 and 3 (and drafts any missing step-1 fragment) as a
single reviewed PR. It deliberately does **not** run `set-version`, `release`, or
`deploy-production` — cutting the tag and promoting production stay human,
deliberate acts (see *Guardrails* below).

## What the gates catch (and what they don't)

`docs-check` enforces *coverage* — every registered route, config field, and IPC
command has a reference entry — exactly like `bruno-check`. It does **not** verify
the prose is correct. The screenshot visual-diff catches unintended UI drift, not
whether the caption still describes the screen. Prose accuracy is precisely what
the human reviewer is for; the generators shrink the hand-authored surface so
there is less to get wrong. The Routine leans on the gates for the mechanical
half and asks a human to judge the rest.

## Prerequisites

- A **Claude Code on the web** session/environment scoped to this repository
  (`malpercio-dev/ezpds`), with the GitHub and Linear MCP connectors available —
  the same surface this Routine's prompt is written against.
- Phases 1–4 landed and trustworthy: `changelog.d/` discipline, the `sites/docs/`
  Starlight surfaces, the `generate-docs-reference.mjs` generator + `docs-check`,
  and `docs-screenshots` all present and green on `main`.
- The Node/pnpm toolchain the docs build and screenshot harness need (provided by
  the dev shell; the screenshot recipe is Linux-runnable, no macOS/Tauri).

## Configuring the Routine

Create a Claude Code Routine (a scheduled or manually-triggered Claude Code web
session) against this repo. A Routine is **triggered per release**, not on a
fixed cron — kick it off when you are ready to cut `vX.Y.Z`, passing the release
range and target version. Configure it with:

- **Repository:** `malpercio-dev/ezpds`.
- **Branch:** a fresh branch from `origin/main`, e.g.
  `claude/release-docs-vX.Y.Z`.
- **Inputs (in the trigger message):** the release range `vLast..HEAD` (the last
  released tag to the release candidate) and the target version `X.Y.Z`.
- **Prompt:** the block below, verbatim. Keep it version-controlled here so the
  Routine's instructions are reviewable and change with the repo rather than
  drifting inside a web-UI text box.

## The Routine prompt

Paste this as the Routine's instructions, filling in the release range and target
version in the first line.

```text
You are performing the release-time docs/marketing review pass for ezpds,
release range <vLast>..HEAD, target version <X.Y.Z>. This is Phase 5 of
docs/design-plans/2026-07-14-documentation-sites.md (docs.AC6). Your output is a
single pull request for a human to review — you draft, a human decides.

Work on a fresh branch from origin/main named claude/release-docs-<X.Y.Z>.

1. Understand what shipped.
   - Read the commit log and diff for the range: `git log --oneline <vLast>..HEAD`
     and `git diff <vLast>..HEAD --stat`, then read the diffs of shipped surfaces
     (crates/*/src, both apps' frontends/native/config, sites/marketing,
     runtime manifests/Dockerfile/NixOS module).
   - Read the merged Linear issues for the release. Use the Linear MCP:
     `linear_wave_status` (team MM, label_prefix "Wave") for the current wave's
     Done tally, and `list_issues` filtered by the relevant Wave label to read the
     titles/descriptions of what merged. These are the human-facing "why" behind
     the diff.

2. Regenerate the derived docs and screenshots.
   - `just docs-generate`  (reference pages: routes, operator config, IPC, version)
   - `just docs-screenshots`  (per-scenario PNGs, happy + error/rare states)
   - Confirm the parity gates are green: `just docs-check`,
     `just changelog-check`, and `just docs-screenshots-check`. If `docs-check`
     fails, a shipped route/config field/command lacks a reference entry — fix the
     generator input or the reference, not the check. Do NOT edit generated
     reference pages by hand; regenerate them.

3. Draft the hand-authored prose (this is the review-pass judgement call).
   - Changelog: if a shipped change in the range has no `changelog.d/` fragment
     and none is folded into CHANGELOG.md's `## [<X.Y.Z>]` section, draft a
     concise, user/operator-facing fragment (see changelog.d/README.md for naming
     `<id>.<type>.md` and the one-statement-no-heading rule). Do NOT run
     `just set-version` — leave rolling the changelog to the human release step.
   - User/operator guides in sites/docs/: update the hand-authored guides
     (onboarding, recovery, Shamir backup, migration, running a relay,
     moderation) where a shipped feature changed the described behavior or a new
     screen/flow needs documenting. New screenshots are already regenerated in
     step 2 — reference them.
   - Marketing site (sites/marketing/): update copy on the Obsign/Custos pages
     only where a shipped, user-visible capability changed the pitch. Be
     conservative here — marketing copy is deliberate; propose, don't rewrite.
   - Keep the two design registers separate (Obsign vs Brass Console); never
     cross-apply one app's visual system to the other. Do not publish the internal
     docs/ tree — it is source material, not the published product.

4. Open the PR.
   - Commit with clear messages; push the branch.
   - Open a pull request titled "Release <X.Y.Z>: docs/marketing review pass".
     In the body: summarize what shipped (linking the merged Linear issues), list
     the derived docs + screenshots regenerated, and enumerate each hand-authored
     prose edit you drafted with a one-line rationale, so the reviewer can accept
     or override each independently. Note explicitly that `just set-version`,
     `just release`, and `just deploy-production` are the human's to run.
   - The PR must be green on docs-check and the changelog gate before you hand it
     off. If a gate is red, fix it or, if you cannot, say so plainly in the PR
     body and stop rather than papering over it.

Guardrails: you draft, a human reviews and authors the final call. Never run
set-version/release/deploy-production, never force-push over others' work, never
edit generated reference pages by hand (regenerate them), and never invent a
user-facing claim the diff doesn't support. When the prose intent is genuinely
ambiguous, leave a TODO in the PR body for the reviewer instead of guessing.
```

## Reviewing the Routine's PR

The PR is a *draft for judgement*, not a rubber stamp. Read it as:

- **Derived docs + screenshots** — mechanically correct if the gates are green;
  skim for surprises (an unexpected screenshot diff means a real UI change worth a
  second look).
- **Changelog fragments** — accept, tighten, or recategorize; these become the
  release notes.
- **Guide and marketing edits** — the real review surface. Accept per-edit,
  override where the agent misjudged tone or overreached on marketing copy, and
  resolve any TODOs the agent left for ambiguous intent.

Once the PR is merged, continue the normal release flow in
[`docs/deploy.md`](../deploy.md): `just set-version` (if not already done) →
`just release` → `just deploy-production`.
