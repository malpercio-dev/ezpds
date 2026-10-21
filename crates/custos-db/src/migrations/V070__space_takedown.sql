-- V070: per-space operator takedown.
--
-- `deleted_at` (V065) is the *owner's* tombstone, written by
-- `simplespace.deleteSpace`. This is the operator's, and the two are
-- independent: a takedown is a reversible refusal to serve, never the spec's
-- durable `SpaceDeleted` "drop your copy" signal, so it must not reuse
-- `deleted_at` and must not destroy members, registrations, or repos.
--
-- On `spaces` rather than a separate refuse-to-serve list because the row
-- already exists for every space this host stores anything in — including one
-- whose *authority* is a foreign server, which `space_record_write` records on
-- a member's first write. That is exactly the liability edge the operator needs
-- a lever for, and a column reaches it without inventing a second table whose
-- only extra power would be naming spaces this host stores nothing for.
--
-- Design: docs/architecture/decisions/0035-per-space-operator-takedown.md
ALTER TABLE spaces ADD COLUMN takendown_at TEXT;

-- Serves the operator listing's `status=takendown` filter. Partial: the column
-- is NULL for all but a handful of rows.
CREATE INDEX idx_spaces_takendown ON spaces (takendown_at) WHERE takendown_at IS NOT NULL;
