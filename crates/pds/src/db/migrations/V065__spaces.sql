-- V065: Atproto Spaces — the permissioned repo store.
--
-- Permissioned repos have no MST: `space_records` rows are the record store,
-- and repo integrity is the incrementally maintained LtHash multiset state on
-- `space_repos` (crypto::space; commit signatures are produced per reader at
-- serving time and never stored). Every write flows through the single choke
-- point in `space_record_write.rs`.
--
-- Design: docs/design-plans/2026-07-17-permissioned-data-gap-analysis.md (§3 W2).

-- Every space this PDS interacts with, as space host (authority anchored on a
-- local account) or, later, as repo host for a foreign authority's space. The
-- URI is the canonical identity: at://{authority}/space/{spaceType}/{skey}.
--
-- `policy`/`app_access` are the simplespace config and are meaningful only when
-- this PDS answers for the space (local authority); NULL means the config lives
-- with a foreign authority. Both are open unions at the schema layer — the
-- CHECK pins the values this host implements, and createSpace/updateSpace must
-- reject anything else anyway (spec requirement).
--
-- Deliberately NO FK from `authority_did` to `accounts`: a foreign authority
-- has no local row, and purging a local authority account must NOT destroy the
-- space row — members' records are their own (the space simply stops answering,
-- which is exactly the spec's deletion semantics). Lifecycle is derived:
-- `deleted_at` set = deleted (refuses writes, credential renewals answer
-- SpaceDeleted).
CREATE TABLE spaces (
    uri           TEXT PRIMARY KEY,
    authority_did TEXT NOT NULL,
    space_type    TEXT NOT NULL,
    skey          TEXT NOT NULL,
    policy        TEXT CHECK (policy IN ('public', 'member-list', 'managing-app')),
    app_access    TEXT CHECK (app_access IN ('open', 'allowList')),
    managing_app  TEXT,
    created_at    TEXT NOT NULL,
    deleted_at    TEXT,
    UNIQUE (authority_did, space_type, skey)
) WITHOUT ROWID;

-- One user's permissioned repo within one space. `rev` is a TID, strictly
-- increasing per repo (the write choke point CASes on it); `lthash_state` is
-- the full 2048-byte LtHash multiset state (the commit `hash` the wire carries
-- is sha256(state), derived — never stored).
CREATE TABLE space_repos (
    space_uri   TEXT NOT NULL REFERENCES spaces (uri),
    account_did TEXT NOT NULL REFERENCES accounts (did),
    rev         TEXT NOT NULL,
    lthash_state BLOB NOT NULL CHECK (length(lthash_state) = 2048),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (space_uri, account_did)
) WITHOUT ROWID;

-- Purge path + blob-GC reference walk both scan by account.
CREATE INDEX idx_space_repos_account ON space_repos (account_did);

-- The record store: path -> current record block. `value` is the canonical
-- DAG-CBOR block whose CID is `cid` (the same block shape an MST repo stores;
-- getRepo/getRecord serve these bytes verbatim).
CREATE TABLE space_records (
    space_uri   TEXT NOT NULL,
    account_did TEXT NOT NULL,
    collection  TEXT NOT NULL,
    rkey        TEXT NOT NULL,
    cid         TEXT NOT NULL,
    value       BLOB NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (space_uri, account_did, collection, rkey),
    FOREIGN KEY (space_uri, account_did) REFERENCES space_repos (space_uri, account_did)
) WITHOUT ROWID;

-- Blob GC decodes each account's space records to union their blob references
-- with the public MST's; the purge path deletes by account too.
CREATE INDEX idx_space_records_account ON space_records (account_did);

-- The per-repo oplog behind listRepoOps: one row per record mutation, ops of
-- one atomic batch sharing a rev. `cid` NULL = delete, `prev` NULL = create.
-- A transport optimization by spec — droppable and compactable (age-based
-- pruning below the head, the firehose_gc pattern; the sync surface wires the
-- sweep), and reset on migration.
CREATE TABLE space_repo_ops (
    space_uri   TEXT NOT NULL,
    account_did TEXT NOT NULL,
    rev         TEXT NOT NULL,
    collection  TEXT NOT NULL,
    rkey        TEXT NOT NULL,
    cid         TEXT,
    prev        TEXT,
    created_at  TEXT NOT NULL,
    FOREIGN KEY (space_uri, account_did) REFERENCES space_repos (space_uri, account_did)
);

-- listRepoOps pages `rev > since` per repo; the purge path deletes by account.
CREATE INDEX idx_space_repo_ops_repo ON space_repo_ops (space_uri, account_did, rev);
CREATE INDEX idx_space_repo_ops_account ON space_repo_ops (account_did);

-- The simplespace member list for `member-list` policy spaces this PDS
-- answers for. Members are arbitrary network DIDs — no FK to `accounts`.
CREATE TABLE space_members (
    space_uri  TEXT NOT NULL REFERENCES spaces (uri),
    member_did TEXT NOT NULL,
    added_at   TEXT NOT NULL,
    PRIMARY KEY (space_uri, member_did)
) WITHOUT ROWID;

CREATE INDEX idx_space_members_member ON space_members (member_did);

-- Write-notification registrations (registerNotify/unregisterNotify): a syncer
-- subscribing to a whole space (on the space host) or to one repo (on a repo
-- host). `repo_did` is '' for a whole-space registration — a sentinel rather
-- than NULL so the primary key covers both shapes (NULLs are never equal, so a
-- nullable PK column would admit duplicate rows). Registrations expire;
-- re-registration refreshes `expires_at`.
CREATE TABLE space_notify_registrations (
    space_uri      TEXT NOT NULL REFERENCES spaces (uri),
    subscriber_did TEXT NOT NULL,
    repo_did       TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    PRIMARY KEY (space_uri, subscriber_did, repo_did)
) WITHOUT ROWID;

-- Single-use `jti` replay protection for the three spaces token surfaces:
-- delegation tokens (~60 s single-use), client attestations, and the
-- per-request DPoP proofs on credential-authed sync calls (the high-volume
-- class). One table, scope-discriminated, so a jti spent on one surface can
-- never be replayed on another. `expires_at` is set by the writer to the
-- token's own acceptance horizon; rows past it are reclaimed by the periodic
-- sweep (`space_jti_sweep.rs`) — the PK is the replay defense, the sweep is
-- storage reclamation only.
CREATE TABLE space_jti_replay (
    scope      TEXT NOT NULL CHECK (scope IN ('delegation', 'attestation', 'dpop')),
    jti        TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (scope, jti)
) WITHOUT ROWID;

CREATE INDEX idx_space_jti_replay_expires ON space_jti_replay (expires_at);
