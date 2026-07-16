# Scheduled Claude agents (routines)

**Last verified:** 2026-07-15

Some maintenance sweeps run as **Claude Code scheduled tasks** ("routines")
rather than CI jobs — checks that need judgment (reading Linear state, weighing
"is this shipped and unreferenced?") rather than a deterministic pass/fail on a
diff. A routine is a fresh, headless Claude Code session fired on a cron
schedule.

**Why this file exists.** These routines are stored **outside the repository**,
per-developer, at `~/.claude/scheduled-tasks/<taskId>/SKILL.md`. They are not
version-controlled and do not sync between machines. If that directory is lost
(new machine, wiped `~/.claude`, etc.) the routine is gone with no trace. This
page is the durable record so any routine can be recreated verbatim.

**Operational notes.**

- A routine only fires while the Claude Code app is open. If the app was closed
  when it was due, it runs on next launch.
- It runs on **one developer's machine** (whoever created it) — it is a
  convenience sweep, not shared infra. If that person is away, it doesn't run.
  Anything that must always run belongs in CI (`.github/workflows/`), not here.
- Recreate a routine by asking Claude Code (in this repo) to create a scheduled
  task with the `taskId`, `cronExpression`, and `prompt` recorded below — or via
  the `/schedule` skill. The prompt must be pasted exactly; each run starts with
  no memory of the session that created it, so the prompt is the whole spec.
- List/manage current routines from the **Scheduled** section of the Claude Code
  sidebar. After recreating one, click **Run now** once to pre-approve the tools
  it uses (Linear MCP, git) so future runs don't pause on permission prompts.

---

## `ezpds-archive-discipline-sweep`

- **Schedule:** `0 9 * * 1` (Mondays, 09:00 local time)
- **Purpose:** enforce the archive-discipline rule from `AGENTS.md` /
  `docs/archive/README.md` — a design plan whose work has fully shipped and is no
  longer referenced by active work must move into `docs/archive/`. This is the
  judgment-based counterpart to the deterministic `just` gates; it is
  deliberately **not** a CI check (deciding "shipped and unreferenced" needs
  Linear state + history, not a diff).
- **Behavior:** reports shipped-but-unarchived plans and, only when it finds any,
  files/updates a single Low `Code Organization` Linear issue with the evidence.
  It **reports rather than auto-moves** — archiving needs careful inbound-link
  updates (AGENTS.md / README cross-links) that a human should review.
- **Prompt (recreate verbatim, substituting your own checkout path):** replace
  `<EZPDS-MAIN-CHECKOUT>` with the absolute path to your local ezpds main
  checkout (not a worktree) — it is machine-specific, which is why it is a
  placeholder here rather than a baked-in path.

> You are running a weekly archive-discipline sweep for the ezpds repository.
>
> Repository (main checkout, NOT a worktree): <EZPDS-MAIN-CHECKOUT>
> First `cd` there and run `git fetch origin main` so you evaluate against the latest merged state. Do all git reads against `origin/main`. Read-only git only — do not modify, commit, or push anything.
>
> BACKGROUND — the rule you are enforcing (from AGENTS.md and docs/archive/README.md):
> When a design plan's work has fully shipped (merged to main) and it is no longer referenced by active in-flight work, its whole design/test/implementation triad must move from docs/{design,test,implementation}-plans/ into docs/archive/{design,test,implementation}-plans/ (moved together so their relative cross-links keep working). Plans still in flight stay put. Exploration/“not scheduled” plans that have no corresponding shipped code also stay put.
>
> STEPS:
> 1. List every plan in `docs/design-plans/*.md`. For each, read its header to find: its title, its tracking issue (an `MM-###` identifier, usually on a "Tracking issue:" line), and any explicit Status line.
> 2. For each plan, decide whether its work has SHIPPED:
>    - Check the tracking issue's state in Linear. Read access is via the `LINEAR_API_KEY` in `.env.local` (team is MM, project ezpds). A `Done`/`Completed` issue is a strong shipped signal. (Do NOT write to Linear during this sweep unless step 5 says to.)
>    - Corroborate with git: `git log --oneline origin/main -- <paths the plan describes>` and search merged commit subjects for the `MM-###` or the feature name. A merged PR implementing the plan = shipped.
>    - Also check whether the plan is still referenced by ACTIVE work: `git grep -l "<plan-basename>" -- docs/implementation-plans docs/test-plans` and whether any referencing implementation/test plan is itself unshipped. If an active, unshipped implementation triad references the design plan, it is NOT ready to archive even if a sub-part shipped.
> 3. A plan is a VIOLATION if: its work has demonstrably shipped to origin/main, it is not referenced by active unshipped work, AND it still lives outside `docs/archive/`. Explicitly EXCLUDE plans whose own Status says "design / exploration / not scheduled" and that have no corresponding shipped code — those correctly stay.
> 4. Produce a concise report: for each plan, one line — `ARCHIVE-DUE` (with the shipping PR/commit + tracking issue), `ACTIVE` (still in flight, why), or `EXPLORATION` (unscheduled, no shipped code). Put the `ARCHIVE-DUE` ones first.
> 5. If and only if there is at least one `ARCHIVE-DUE` plan: create ONE Linear issue in team MM, project ezpds, labels ["Code Organization"], priority 4 (Low), titled "Archive discipline: N shipped design plan(s) awaiting move to docs/archive/". Body: the list of ARCHIVE-DUE plans with their shipping evidence and the reminder to move the whole triad + update inbound links (AGENTS.md / README cross-links). Linear writes go through the Linear MCP (`save_issue`). First check the ezpds backlog for an existing open issue with that title (`list_issues`) — if one exists, update it instead of creating a duplicate. Do NOT move any files or edit links yourself; archiving needs careful inbound-link updates that a human should review.
> 6. If there are zero ARCHIVE-DUE plans, just report "clean — no shipped plans awaiting archive" and create no issue.
>
> Keep the final message to the report plus a one-line note of any Linear issue you created or updated.
