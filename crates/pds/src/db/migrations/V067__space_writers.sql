-- V067: the space host's writer set — what `com.atproto.space.listRepos` answers.
--
-- The sync boundary, not an access-control list: a row means "this repo has written into the
-- space", never "this DID may read it". The authority's claim is second-hand for every repo it
-- does not itself host — a repo's host is the source of truth — so `rev`/`hash` are "as last
-- reported" and may lag.
--
-- Deliberately NOT `space_repos`: that table's `account_did` has an FK to `accounts`, because it
-- carries a locally-hosted repo's full 2048-byte LtHash state. Most of the writer set is foreign
-- repos learned from inbound `notifyWrite`, which have no local account row and report only the
-- derived 32-byte commit hash. Keeping them apart also makes `listRepos` one index scan instead
-- of a union over two differently-shaped tables.
--
-- Rows are written only when this host is the space's authority (`spaces.policy IS NOT NULL`);
-- see `db::space_notify::upsert_writer`.
--
-- Design: docs/design-plans/2026-07-17-permissioned-data-gap-analysis.md (§3 W5).
CREATE TABLE space_writers (
    space_uri  TEXT NOT NULL REFERENCES spaces (uri),
    repo_did   TEXT NOT NULL,
    rev        TEXT NOT NULL,
    hash       BLOB NOT NULL CHECK (length(hash) = 32),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (space_uri, repo_did)
) WITHOUT ROWID;
