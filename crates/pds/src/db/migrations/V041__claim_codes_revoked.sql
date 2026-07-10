-- V041: Operator revocation for claim codes + a stable inventory cursor
--
-- A minted-but-unredeemed claim code is a live signup credential; the operator needs to be
-- able to kill one (a code shared to the wrong channel, a batch minted by mistake) without
-- waiting out its expiry. Following the derived-status doctrine (V004: pending/redeemed/
-- expired from timestamps; V025: admin-device active/revoked from `revoked_at`), revocation
-- is a nullable timestamp, not a status column: NULL = never revoked. Every redemption path
-- (the atomic single-use UPDATEs and the `claim_code_valid` preflight) additionally requires
-- `revoked_at IS NULL`, so revocation closes redemption exactly like expiry does — and the
-- row survives as the audit record of the kill.
--
-- The table is rebuilt (rather than ALTERed) to also gain an explicit
-- `id INTEGER PRIMARY KEY`: the inventory endpoint pages newest-first by insertion order,
-- and with a TEXT primary key the implicit rowid is NOT stable — VACUUM may renumber it,
-- which could skip or duplicate pagination pages. An INTEGER PRIMARY KEY is a true rowid
-- alias and survives VACUUM (same doctrine as `repo_seq`, V028). `code` keeps its
-- uniqueness via a UNIQUE constraint. Existing rows keep their current rowid as `id`, so
-- insertion order is preserved across the rebuild. Rows are never deleted (revocation is a
-- tombstone), so plain INTEGER PRIMARY KEY monotonicity is sufficient — AUTOINCREMENT's
-- no-reuse guarantee would only matter after a delete of the max row.

CREATE TABLE claim_codes_v2 (
    id          INTEGER PRIMARY KEY,
    code        TEXT NOT NULL UNIQUE,
    expires_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    redeemed_at TEXT,
    revoked_at  TEXT
);

INSERT INTO claim_codes_v2 (id, code, expires_at, created_at, redeemed_at)
SELECT rowid, code, expires_at, created_at, redeemed_at FROM claim_codes ORDER BY rowid;

DROP TABLE claim_codes;
ALTER TABLE claim_codes_v2 RENAME TO claim_codes;

-- Supports expiry sweeps and redemption validity checks (recreated: DROP TABLE removed it).
CREATE INDEX idx_claim_codes_expires_at ON claim_codes (expires_at);
