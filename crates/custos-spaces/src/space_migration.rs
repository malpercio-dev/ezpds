// pattern: Imperative Shell

//! Space migration: the two STAR archives a space travels between hosts in, and the meta import.
//!
//! * **`atproto-space-repo`** is one account's repo in one space. Its metadata is the commit
//!   `{ver, repo, space, rev, data}`, and its pairs map `{collection}/{rkey}` to the record's
//!   DAG-CBOR, in strict bytewise key order. `getRepo` writes it ([`repo_star_writer`]) and
//!   `importRepo` reads it ([`read_repo_star`]) and lands it through the write choke point
//!   (`space_record_write::import_space_repo`).
//! * **`atproto-space-meta`** is an authority's host-side state for one space: `policy`, then the
//!   policy state (memberspace's member list, keyed as its published member records are), then
//!   `writer/{did}` → `{repoRev, data, spaceRev}`. `exportSpaceMeta` writes it
//!   ([`export_space_meta`]) and `importSpaceMeta` reads and lands it ([`read_space_meta`],
//!   [`import_space_meta`]).
//!
//! Blobs travel separately (`listBlobs` → `getBlob` → `uploadBlob`). Notification registrations,
//! credential revocations and tombstones stay behind on the old host.
//!
//! Import semantics follow the reference. `importRepo` replaces the account's records and oplog:
//! the repo takes a fresh `rev` after whatever this host held for it, with an empty oplog, and no
//! write notification fires. The first write after activation tells the authority, and a syncer
//! holding a `since` from the old host heals with `getRepo`. `importSpaceMeta` creates the space,
//! or replaces the configuration of one this host already answers for, and replaces its member
//! list and writer set. It publishes nothing, because the published policy and member records
//! arrive with the authority's own repo. The writer export leaves no writer out, since this host
//! keeps no removed writers.
//!
//! Deliberate divergences from the reference:
//!
//! * **Both imports require a deactivated account**, as `com.atproto.repo.importRepo` does here.
//!   The reference requires only full access. Every migration lands on a destination account
//!   that `createAccount` left deactivated, so an import is never mistaken for a live write.
//! * **Both imports refuse agent-derived tokens** (`require_not_agent`). The reference has no
//!   concept of agents. An import replaces a whole repo or a whole space, which is an account
//!   operation, never something an agent does on the owner's behalf.
//! * **Both imports skip the KEM-published check** every other space write takes (`kem_gate`).
//!   Until the identity leg of the migration, the DID document still names the old host's key.
//!   The deactivated precondition keeps this from being a way around the gate.
//! * **Exports carry no takedown check of their own.** The reference admits a taken-down
//!   account to `getRepo` and `exportSpaceMeta` so it can still leave. Custos has no such exit
//!   lane yet, and the account-credential seam (`auth::space::require_serviceable_caller`) refuses
//!   every moderation state. Each import checks the account's lifecycle itself, in its own
//!   transaction, so lifting the seam's refusal for exports later changes nothing for imports.
//! * **A per-space operator takedown (ADR-0035) blocks the authority's export too.** An export is
//!   serving, and the seam's `require_space_servable` answers `SpaceNotFound` for it. Clearing the
//!   takedown restores the export.

use std::collections::BTreeMap;

use common::{ApiError, Did, ErrorCode};
use custos_core::space_uri::SpaceRef;
use custos_core::CoreState;
use ipld_core::ipld::Ipld;
use repo_engine::{SpaceStarReader, SpaceStarWriter, StarPair, StarProfile, StarProfileError};

use crate::db::space_meta::MetaWriterRow;
use crate::policy::{Access, SpacePolicy, MEMBER_COLLECTION};
use crate::views::SpaceCommit;

/// The largest archive either import buffers: the ceiling `com.atproto.repo.importRepo` sets.
pub const MAX_IMPORT_BYTES: usize = 100 * 1024 * 1024;

const SPACE_META_VERSION: i128 = 1;
const POLICY_KEY: &str = "policy";
const WRITER_PREFIX: &str = "writer/";

/// Buffer an import body up to [`MAX_IMPORT_BYTES`], refusing a larger one by its declared
/// length before reading any of it.
pub async fn read_import_body(
    request: axum::http::Request<axum::body::Body>,
) -> Result<axum::body::Bytes, ApiError> {
    let too_large = || {
        ApiError::new(
            ErrorCode::PayloadTooLarge,
            format!("import exceeds maximum size of {MAX_IMPORT_BYTES} bytes"),
        )
    };
    if request
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|len| len > MAX_IMPORT_BYTES)
    {
        return Err(too_large());
    }
    axum::body::to_bytes(request.into_body(), MAX_IMPORT_BYTES)
        .await
        .map_err(|_| too_large())
}

// ── atproto-space-repo ──────────────────────────────────────────────────────

/// A writer for `commit`'s repo archive, and the archive's header bytes.
pub fn repo_star_writer(commit: &SpaceCommit) -> Result<(SpaceStarWriter, Vec<u8>), ApiError> {
    let meta = Ipld::Map(BTreeMap::from([
        (
            "$type".to_string(),
            Ipld::String(repo_engine::SPACE_REPO_STAR_TYPE.to_string()),
        ),
        (
            "ver".to_string(),
            Ipld::Integer(i128::from(crypto::SPACE_COMMIT_VERSION)),
        ),
        ("repo".to_string(), Ipld::String(commit.repo.to_string())),
        ("space".to_string(), Ipld::String(commit.space.clone())),
        ("rev".to_string(), Ipld::String(commit.rev.clone())),
        ("data".to_string(), Ipld::Bytes(commit.data.to_vec())),
    ]));
    SpaceStarWriter::new(StarProfile::SpaceRepo, &meta)
        .map_err(|e| ApiError::internal(e, "failed to write space repo archive"))
}

/// One record out of a repo archive, re-encoded and checked against its own CID.
pub struct ArchivedRecord {
    pub collection: String,
    pub rkey: String,
    pub cid: String,
    pub bytes: Vec<u8>,
}

/// A repo archive that verified against its own commit.
pub struct RepoArchive {
    pub repo: Did,
    pub space: SpaceRef,
    pub records: Vec<ArchivedRecord>,
    /// The records' set hash, which equals the commit's `data`.
    pub lthash: crypto::LtHash,
}

/// Read and verify a repo archive: the commit's shape, then each record's path and canonical
/// encoding, then the records' set hash against the commit's `data`. Every failure is
/// `InvalidRepoFile`.
///
/// A record must re-encode to its own bytes after the trip through JSON the store makes, so a
/// record that is not canonical DRISL, or that the store could not round-trip, would no longer
/// match its CID or the commit and is refused.
pub fn read_repo_star(bytes: &[u8]) -> Result<RepoArchive, ApiError> {
    let invalid = |message: String| ApiError::new(ErrorCode::InvalidRepoFile, message);
    let star_error = |e: StarProfileError| invalid(format!("invalid STAR: {e}"));

    let reader = SpaceStarReader::new(StarProfile::SpaceRepo, bytes).map_err(star_error)?;
    let meta = reader.meta();
    if meta.get("ver") != Some(&Ipld::Integer(i128::from(crypto::SPACE_COMMIT_VERSION))) {
        return Err(invalid("unsupported commit version".to_string()));
    }
    let repo = meta_string(meta, "repo")
        .and_then(|repo| Did::parse(repo).ok())
        .ok_or_else(|| invalid("commit repo is not a DID".to_string()))?;
    let space = meta_string(meta, "space")
        .and_then(custos_core::space_uri::parse_space_ref)
        .ok_or_else(|| invalid("commit space is not a space-ref".to_string()))?;
    if !meta_string(meta, "rev").is_some_and(custos_core::lexicon::is_valid_tid) {
        return Err(invalid("commit rev is not a TID".to_string()));
    }
    let Some(Ipld::Bytes(data)) = meta.get("data") else {
        return Err(invalid("commit data is not bytes".to_string()));
    };
    let data = data.clone();

    let mut lthash = crypto::LtHash::new();
    let mut records = Vec::new();
    for pair in reader {
        let StarPair { key, value } = pair.map_err(star_error)?;
        let path = String::from_utf8(key).map_err(|_| invalid("record key is not UTF-8".into()))?;
        let (collection, rkey) = path
            .split_once('/')
            .ok_or_else(|| invalid(format!("record key is not collection/rkey: {path}")))?;
        repo_engine::validate_record_path(collection, rkey)
            .map_err(|e| invalid(format!("invalid record path {path}: {e}")))?;
        let cid =
            reencoded_cid(&value).map_err(|message| invalid(format!("{message} at {path}")))?;
        lthash.add(&crypto::format_set_hash_element(collection, rkey, &cid));
        records.push(ArchivedRecord {
            collection: collection.to_string(),
            rkey: rkey.to_string(),
            cid,
            bytes: value,
        });
    }
    if lthash.digest().as_slice() != data.as_slice() {
        return Err(invalid("records do not match the commit data".to_string()));
    }
    Ok(RepoArchive {
        repo,
        space,
        records,
        lthash,
    })
}

/// The CID of a record's bytes, once they are shown to be a record the store would write
/// byte-for-byte the same: a map, through the record-format gate every write takes, re-encoding
/// to exactly these bytes.
fn reencoded_cid(bytes: &[u8]) -> Result<String, String> {
    let ipld = repo_engine::decode_record_block(bytes).map_err(|e| e.to_string())?;
    if !matches!(ipld, Ipld::Map(_)) {
        return Err("record is not a map".to_string());
    }
    let json = repo_engine::record_value_to_json(&ipld).map_err(|e| e.to_string())?;
    custos_core::auth::validation::validate_record_formats(&json)?;
    let ipld = repo_engine::json_to_record_value(&json).map_err(|e| e.to_string())?;
    let (cid, reencoded) = repo_engine::encode_record_block(&ipld).map_err(|e| e.to_string())?;
    if reencoded != bytes {
        return Err("record is not canonical DRISL".to_string());
    }
    Ok(cid.to_string())
}

fn meta_string<'a>(meta: &'a BTreeMap<String, Ipld>, key: &str) -> Option<&'a str> {
    match meta.get(key) {
        Some(Ipld::String(value)) => Some(value),
        _ => None,
    }
}

// ── atproto-space-meta ──────────────────────────────────────────────────────

/// A space meta archive, read and checked against the policy it carries.
pub struct SpaceMetaArchive {
    pub space: SpaceRef,
    pub policy: SpacePolicy,
    pub members: Vec<(Did, Access)>,
    pub writers: Vec<MetaWriterRow>,
}

/// Export the space this host is the authority for at `space` as a meta archive. The caller has
/// already authenticated the authority.
pub async fn export_space_meta(state: &CoreState, space: &SpaceRef) -> Result<Vec<u8>, ApiError> {
    let internal = |e: sqlx::Error| ApiError::internal(e, "failed to export space meta");
    // One read transaction, so the policy, members and writers describe the same moment.
    let mut tx = state.db.begin().await.map_err(internal)?;
    let (_, policy) = crate::views::load_active_space(&mut *tx, space).await?;
    let members = match policy {
        SpacePolicy::Member(_) => crate::db::spaces::all_members(&mut *tx, &space.uri)
            .await
            .map_err(internal)?,
        _ => Vec::new(),
    };
    let writers = crate::db::space_meta::all_writers(&mut *tx, &space.uri)
        .await
        .map_err(internal)?;
    drop(tx);

    let mut pairs = vec![pair(
        POLICY_KEY.to_string(),
        &json_to_ipld(&policy.to_json())?,
    )?];
    let mut state_pairs = members
        .into_iter()
        .map(|member| {
            let access = Access {
                read: member.can_read,
                write: member.can_write,
            };
            let key = format!(
                "{MEMBER_COLLECTION}/{}",
                crate::policy::did_record_key(&member.member_did)
            );
            pair(key, &json_to_ipld(&crate::policy::member_record(access))?)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut writer_pairs = writers
        .into_iter()
        .map(|writer| {
            let value = Ipld::Map(BTreeMap::from([
                ("repoRev".to_string(), Ipld::String(writer.rev)),
                ("data".to_string(), Ipld::Bytes(writer.hash)),
                ("spaceRev".to_string(), Ipld::String(writer.space_rev)),
            ]));
            pair(format!("{WRITER_PREFIX}{}", writer.repo_did), &value)
        })
        .collect::<Result<Vec<_>, _>>()?;
    // Each section is in strict bytewise key order; a DID record key need not sort as its DID.
    state_pairs.sort_by(|a, b| a.key.cmp(&b.key));
    writer_pairs.sort_by(|a, b| a.key.cmp(&b.key));
    pairs.extend(state_pairs);
    pairs.extend(writer_pairs);

    let meta = Ipld::Map(BTreeMap::from([
        (
            "$type".to_string(),
            Ipld::String(repo_engine::SPACE_META_STAR_TYPE.to_string()),
        ),
        ("ver".to_string(), Ipld::Integer(SPACE_META_VERSION)),
        ("space".to_string(), Ipld::String(space.uri.clone())),
    ]));
    repo_engine::write_space_star(StarProfile::SpaceMeta, &meta, &pairs)
        .map_err(|e| ApiError::internal(e, "failed to write space meta archive"))
}

fn pair(key: String, value: &Ipld) -> Result<StarPair, ApiError> {
    let (_, value) = repo_engine::encode_record_block(value)
        .map_err(|e| ApiError::internal(e, "failed to encode space meta entry"))?;
    Ok(StarPair {
        key: key.into_bytes(),
        value,
    })
}

fn json_to_ipld(value: &serde_json::Value) -> Result<Ipld, ApiError> {
    repo_engine::json_to_record_value(value)
        .map_err(|e| ApiError::internal(e, "failed to encode space meta entry"))
}

/// Read and check a meta archive. Malformed archives, a missing or invalid policy, and policy
/// state the policy does not define are `InvalidSpaceMeta`; a policy this host does not implement
/// is `UnsupportedPolicy`. Policy state is refused rather than dropped, since dropping it would
/// quietly change who has access to the space.
pub fn read_space_meta(bytes: &[u8]) -> Result<SpaceMetaArchive, ApiError> {
    let invalid = |message: String| ApiError::new(ErrorCode::InvalidSpaceMeta, message);
    let star_error = |e: StarProfileError| invalid(format!("invalid STAR: {e}"));

    let reader = SpaceStarReader::new(StarProfile::SpaceMeta, bytes).map_err(star_error)?;
    let meta = reader.meta();
    if meta.get("ver") != Some(&Ipld::Integer(SPACE_META_VERSION)) {
        return Err(invalid("unsupported space meta version".to_string()));
    }
    let space = meta_string(meta, "space")
        .and_then(custos_core::space_uri::parse_space_ref)
        .ok_or_else(|| invalid("space meta space is not a space-ref".to_string()))?;

    let mut policy: Option<SpacePolicy> = None;
    let mut members = Vec::new();
    let mut writers = Vec::new();
    for pair in reader {
        let StarPair { key, value } = pair.map_err(star_error)?;
        let key = String::from_utf8(key).map_err(|_| invalid("key is not UTF-8".into()))?;
        let value = decode_map(&value).map_err(|message| invalid(format!("{message} at {key}")))?;
        if let Some(did) = key.strip_prefix(WRITER_PREFIX) {
            let writer = parse_writer(did, &value)
                .ok_or_else(|| invalid(format!("invalid writer at {key}")))?;
            writers.push(writer);
            continue;
        }
        let value = repo_engine::record_value_to_json(&value)
            .map_err(|e| invalid(format!("{e} at {key}")))?;
        if key == POLICY_KEY {
            policy = Some(parse_archived_policy(&value)?);
        } else {
            // Sections are ordered, so a policy that exists has been read by now.
            let Some(SpacePolicy::Member(_)) = &policy else {
                return Err(invalid(format!("Unrecognized policy state: {key}")));
            };
            let did = key
                .strip_prefix(MEMBER_COLLECTION)
                .and_then(|rest| rest.strip_prefix('/'))
                .and_then(|rkey| Did::parse(crate::policy::record_key_did(rkey)).ok())
                .ok_or_else(|| invalid(format!("Unrecognized policy state: {key}")))?;
            let access =
                parse_member(&value).ok_or_else(|| invalid(format!("Invalid member at {key}")))?;
            members.push((did, access));
        }
    }
    let policy = policy.ok_or_else(|| invalid("missing policy".to_string()))?;
    Ok(SpaceMetaArchive {
        space,
        policy,
        members,
        writers,
    })
}

/// Decode an archive value strictly: a DAG-CBOR map that re-encodes to the same bytes.
fn decode_map(bytes: &[u8]) -> Result<Ipld, String> {
    let ipld = repo_engine::decode_record_block(bytes).map_err(|_| "invalid cbor".to_string())?;
    if !matches!(ipld, Ipld::Map(_)) {
        return Err("value is not a map".to_string());
    }
    let (_, reencoded) = repo_engine::encode_record_block(&ipld).map_err(|e| e.to_string())?;
    if reencoded != bytes {
        return Err("value is not canonical DRISL".to_string());
    }
    Ok(ipld)
}

/// The archived policy, validated against its own lexicon (nothing else has checked it), then
/// normalized as `createSpace`'s is.
fn parse_archived_policy(value: &serde_json::Value) -> Result<SpacePolicy, ApiError> {
    let invalid = |message: String| ApiError::new(ErrorCode::InvalidSpaceMeta, message);
    let policy_type = value
        .get("$type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid("Invalid policy: missing $type".to_string()))?;
    if [
        crate::policy::PERSONALSPACE,
        crate::policy::MEMBERSPACE,
        crate::policy::MANAGEDSPACE,
    ]
    .contains(&policy_type)
    {
        custos_core::lexicon::registry()
            .validate_def(&format!("lex:{policy_type}"), value)
            .map_err(|e| match e {
                custos_core::lexicon::ValidationError::Invalid(message) => {
                    invalid(format!("Invalid policy: {message}"))
                }
                lexicon => custos_core::lexicon::record_validation_error(lexicon),
            })?;
    }
    SpacePolicy::from_lex(value)
}

fn parse_member(value: &serde_json::Value) -> Option<Access> {
    if value
        .get("$type")
        .is_some_and(|t| t.as_str() != Some(MEMBER_COLLECTION))
    {
        return None;
    }
    Some(Access {
        read: value.get("read")?.as_bool()?,
        write: value.get("write")?.as_bool()?,
    })
}

/// `{repoRev, data, spaceRev}` under `writer/{did}`. `data` is a set-hash digest, so 32 bytes.
fn parse_writer(did: &str, value: &Ipld) -> Option<MetaWriterRow> {
    let Ipld::Map(map) = value else {
        return None;
    };
    let tid = |name: &str| match map.get(name) {
        Some(Ipld::String(v)) if custos_core::lexicon::is_valid_tid(v) => Some(v.clone()),
        _ => None,
    };
    let hash = match map.get("data") {
        Some(Ipld::Bytes(hash)) if hash.len() == 32 => hash.clone(),
        _ => return None,
    };
    Some(MetaWriterRow {
        repo_did: Did::parse(did).ok()?.to_string(),
        rev: tid("repoRev")?,
        hash,
        space_rev: tid("spaceRev")?,
    })
}

/// Land a meta archive for `caller`, who must be the archive space's authority on a deactivated
/// account: create the space (or replace the policy of the one this host already answers for),
/// then replace its member list and writer set, in one transaction. Publishes nothing.
pub async fn import_space_meta(
    state: &CoreState,
    caller: &Did,
    archive: &SpaceMetaArchive,
) -> Result<(), ApiError> {
    let internal = |e: sqlx::Error| ApiError::internal(e, "failed to import space meta");
    let space = &archive.space;
    let policy = archive.policy.to_json().to_string();

    let mut tx = state.db.begin().await.map_err(internal)?;
    // Re-read inside the transaction, against a concurrent `activateAccount`.
    require_deactivated(&mut *tx, caller).await?;
    let new_space = crate::db::spaces::NewSpace {
        uri: &space.uri,
        authority_did: &space.authority,
        space_type: &space.space_type,
        skey: &space.skey,
    };
    if !crate::db::spaces::create_space(&mut *tx, &new_space, &policy)
        .await
        .map_err(internal)?
    {
        // Either this host already answers for the space, or the operator has taken it down. A
        // takedown is a refusal an import must not undo.
        let row = crate::db::spaces::get_space(&mut *tx, &space.uri)
            .await
            .map_err(internal)?;
        if row.is_none_or(|row| row.takendown_at.is_some()) {
            return Err(ApiError::new(ErrorCode::SpaceNotFound, "space not found"));
        }
        crate::db::spaces::set_space_policy(&mut *tx, &space.uri, &policy)
            .await
            .map_err(internal)?;
    }
    crate::db::spaces::delete_members(&mut *tx, &space.uri)
        .await
        .map_err(internal)?;
    for (did, access) in &archive.members {
        crate::db::spaces::put_member(&mut *tx, &space.uri, did, access.read, access.write)
            .await
            .map_err(internal)?;
    }
    crate::db::space_meta::replace_writers(&mut tx, &space.uri, &archive.writers)
        .await
        .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    Ok(())
}

/// The import precondition: `did` is a deactivated account. A moderation state is refused as it
/// is on every space write; an active account must go through the ordinary write routes.
pub async fn require_deactivated<'e, E>(executor: E, did: &Did) -> Result<(), ApiError>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    use custos_db::accounts::AccountLifecycle;
    match custos_db::accounts::account_lifecycle(executor, did).await? {
        Some(AccountLifecycle::Deactivated) => Ok(()),
        Some(AccountLifecycle::Active) => Err(ApiError::new(
            ErrorCode::Forbidden,
            "account must be deactivated to import a space",
        )),
        Some(AccountLifecycle::TakenDown | AccountLifecycle::Suspended) => Err(ApiError::new(
            ErrorCode::AccountTakedown,
            "account has been taken down",
        )),
        None => Err(ApiError::new(ErrorCode::NotFound, "account not found")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal<T>(result: Result<T, ApiError>) -> ApiError {
        match result {
            Err(e) => e,
            Ok(_) => panic!("expected the archive to be refused"),
        }
    }

    fn repo_archive(pairs: &[(&str, Vec<u8>)], data: [u8; 32]) -> Vec<u8> {
        let commit = SpaceCommit {
            repo: Did::parse("did:plc:migrationtestaaaaaaaaaa").unwrap(),
            space: "at://did:plc:migrationtestaaaaaaaaaa/space/org.example.bucket/main".to_string(),
            rev: "3lztsjenmq22a".to_string(),
            data,
        };
        let (mut writer, mut out) = repo_star_writer(&commit).unwrap();
        for (key, value) in pairs {
            out.extend(writer.pair(key.as_bytes(), value).unwrap());
        }
        out.push(writer.end());
        out
    }

    fn record(text: &str) -> Vec<u8> {
        let ipld = repo_engine::json_to_record_value(&serde_json::json!({ "text": text })).unwrap();
        repo_engine::encode_record_block(&ipld).unwrap().1
    }

    fn digest(pairs: &[(&str, Vec<u8>)]) -> [u8; 32] {
        let mut lthash = crypto::LtHash::new();
        for (path, bytes) in pairs {
            let (collection, rkey) = path.split_once('/').unwrap();
            let cid = repo_engine::dag_cbor_block_cid(bytes).unwrap().to_string();
            lthash.add(&crypto::format_set_hash_element(collection, rkey, &cid));
        }
        lthash.digest()
    }

    #[test]
    fn a_repo_archive_round_trips_and_verifies_against_its_commit() {
        let pairs = [
            ("org.example.note/a", record("one")),
            ("org.example.note/b", record("two")),
        ];
        let archive = read_repo_star(&repo_archive(&pairs, digest(&pairs))).unwrap();
        assert_eq!(archive.records.len(), 2);
        assert_eq!(archive.lthash.digest(), digest(&pairs));
    }

    #[test]
    fn a_repo_archive_whose_records_miss_the_commit_is_refused() {
        let pairs = [("org.example.note/a", record("one"))];
        let err = refusal(read_repo_star(&repo_archive(&pairs, [0; 32])));
        assert_eq!(*err.code(), ErrorCode::InvalidRepoFile);
    }

    #[test]
    fn a_non_canonical_record_is_refused() {
        // `{"b": 1, "a": 2}` with its keys out of canonical order.
        let bytes = vec![0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02];
        let pairs = [("org.example.note/a", bytes)];
        let err = refusal(read_repo_star(&repo_archive(&pairs, digest(&pairs))));
        assert_eq!(*err.code(), ErrorCode::InvalidRepoFile);
        assert!(err.message().contains("canonical"), "{}", err.message());
    }

    fn meta_archive(pairs: &[(&str, serde_json::Value)]) -> Vec<u8> {
        let meta = Ipld::Map(BTreeMap::from([
            (
                "$type".to_string(),
                Ipld::String(repo_engine::SPACE_META_STAR_TYPE.to_string()),
            ),
            ("ver".to_string(), Ipld::Integer(1)),
            (
                "space".to_string(),
                Ipld::String(
                    "at://did:plc:migrationtestaaaaaaaaaa/space/org.example.bucket/main"
                        .to_string(),
                ),
            ),
        ]));
        let pairs: Vec<StarPair> = pairs
            .iter()
            .map(|(key, value)| pair(key.to_string(), &json_to_ipld(value).unwrap()).unwrap())
            .collect();
        repo_engine::write_space_star(StarProfile::SpaceMeta, &meta, &pairs).unwrap()
    }

    #[test]
    fn policy_state_a_policy_does_not_define_is_refused() {
        let member =
            serde_json::json!({ "$type": MEMBER_COLLECTION, "read": true, "write": false });
        let personal = serde_json::json!({ "$type": crate::policy::PERSONALSPACE });
        let memberspace = serde_json::json!({ "$type": crate::policy::MEMBERSPACE });
        let key = "com.atproto.memberspace.member/did:plc:bobaaaaaaaaaaaaaaaaaaaaa";

        let archive = read_space_meta(&meta_archive(&[
            ("policy", memberspace.clone()),
            (key, member.clone()),
        ]))
        .unwrap();
        assert_eq!(archive.members.len(), 1);

        for pairs in [
            vec![("policy", personal), (key, member.clone())],
            vec![
                ("policy", memberspace.clone()),
                ("org.example.other/x", member),
            ],
            vec![
                ("policy", memberspace.clone()),
                (key, serde_json::json!({ "read": 1 })),
            ],
        ] {
            let err = refusal(read_space_meta(&meta_archive(&pairs)));
            assert_eq!(*err.code(), ErrorCode::InvalidSpaceMeta, "{pairs:?}");
        }
    }

    #[test]
    fn an_archived_policy_is_validated_then_normalized() {
        let bad = serde_json::json!({ "$type": crate::policy::MEMBERSPACE, "publicRead": "yes" });
        let err = refusal(read_space_meta(&meta_archive(&[("policy", bad)])));
        assert_eq!(*err.code(), ErrorCode::InvalidSpaceMeta);

        let unknown = serde_json::json!({ "$type": "com.example.policy" });
        let err = refusal(read_space_meta(&meta_archive(&[("policy", unknown)])));
        assert_eq!(*err.code(), ErrorCode::UnsupportedPolicy);

        let err = refusal(read_space_meta(&meta_archive(&[])));
        assert_eq!(*err.code(), ErrorCode::InvalidSpaceMeta, "missing policy");
    }
}
