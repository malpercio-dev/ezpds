# Issue tracker: Linear

Issues and specs for this repo live in **Linear**, team `MM` ("Mal's Machinations"),
project **`ezpds`**. Use the Linear MCP connector for every operation; there is no
CLI, and `gh issue` is not used (the GitHub repo carries PRs only).

## Conventions

- **Identifiers**: issues are `MM-<n>`. A bare number in conversation means an
  `MM-` issue unless the user says "PR".
- **Create an issue**: `save_issue` with `team: MM` and **`project: ezpds`**
  (the project field is easy to miss and a wave label does *not* attach the issue
  to the project). Tag it with its wave label on creation (`Wave 11: v2 In Place`
  is the current wave; see the AGENTS.md "Project Status / Planning" section).
  Set `Bug` / `Feature` / `Improvement` as the category label.
- **Read an issue**: `get_issue` (body, labels, status, relations) + `list_comments`.
- **List issues**: `list_issues` with `team`, `label`, `state`, `project`, or
  `parentId` filters and `limit` of 50+ for exhaustive scans. Its `query`
  parameter is title/description text search: good for keyword lookups, wrong
  for "every issue in Wave N" (filter by `label` for that).
- **Sub-issues**: Linear has native parent/child. Create the child with
  `parentId` set to the parent, or update the child afterwards. No "Part of"
  body line is needed.
- **Comment**: `save_comment` on the issue.
- **Apply / remove labels**: `save_issue` with `addLabels` / `removeLabels`
  (incremental). `labels` replaces the whole set, so avoid it for a state change.
- **Close**: move the status to `Done` (shipped) or `Canceled` (won't do) with
  `save_issue`; add a comment saying why when it isn't obvious from a linked PR.
- **Statuses**: `Backlog` → `Todo` → `In Progress` → `In Review` → `Done`, plus
  `Canceled` and `Duplicate`. There is no Linear "Triage" status; triage state
  is carried by labels (see `triage-labels.md`). The `linear-workflow` skill
  moves an issue to `In Progress` when work starts and `In Review` when a PR
  opens.
- **Branch + PR**: branch names come from Linear's branch-name field; the PR
  title or body cites `MM-<n>` so Linear auto-links it. Never put `MM-<n>` in
  Rust source or AGENTS.md (`just ticket-ref-check` fails the gate).

## Pull requests as a triage surface

**PRs as a request surface: no.** _(Set to `yes` if this repo should treat
external PRs as feature requests; `/triage` reads this flag.)_

## When a skill says "publish to the issue tracker"

Create a Linear issue as in **Create an issue** above. If several issues come
from one design plan, create a parent issue for the plan and the rest as its
children, all in project `ezpds` with the same wave label.

## When a skill says "fetch the relevant ticket"

`get_issue` + `list_comments` for the `MM-<n>` the user named, or the one in the
current branch name.

## Wayfinding operations

Used by `/wayfinder`. The **map** is a parent issue; **tickets** are its
children.

- **Map**: one issue titled `Wayfinder: <topic>`, holding the Notes /
  Decisions-so-far / Fog body. Project `ezpds`, current wave label.
- **Child ticket**: a sub-issue of the map (`parentId` = map). Put the ticket
  type (`research` / `prototype` / `grilling` / `task`) as the title prefix,
  e.g. `research: ...`; there are no `wayfinder:*` labels in Linear and creating
  four more is not worth it.
- **Blocking**: Linear's native **blocked-by** relation on the child
  (`save_issue` with `blockedBy`), one entry per blocker. A ticket is unblocked when every blocker is `Done` or
  `Canceled`.
- **Frontier query**: `list_issues` for the map's open children, drop any with
  an open blocker or an assignee; first in map order (creation order) wins.
- **Claim**: assign the ticket to yourself and move it to `In Progress`, the
  session's first write.
- **Resolve**: comment the answer, move to `Done`, then append a context pointer
  (gist + link) to the map's Decisions-so-far.
