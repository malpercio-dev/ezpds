-- V083: a removed writer keeps its writer-set row.
--
-- `removeWriter`, `removeMembers` and `putMembers` with `write: false` take a repo out of a
-- space's writer set. The row stays, with `removed_at` set and a new `space_rev`, so `listWriters`
-- can report the removal as a `repoRemoved` and the stale-rev check still refuses an older report
-- for the repo. A later write with a newer `rev` clears `removed_at`, which puts the repo back.
ALTER TABLE space_writers ADD COLUMN removed_at TEXT;
