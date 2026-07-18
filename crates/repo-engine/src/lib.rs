// repo-engine: MST construction, CAR file storage, commit construction.
// Thin domain wrapper over atrium-repo.
// Functional Core — no HTTP, no DB schema ownership, no process-level state.

pub mod at_uri;
pub mod car_export;
pub mod car_import;
pub mod data_model;
pub mod datetime;
pub mod genesis;
pub mod lexicon;
pub mod mst;
pub mod records;
pub mod signer;

// Re-export the blockstore traits so PDS can implement them without depending on atrium-repo
// directly.
pub use atrium_repo::blockstore::{AsyncBlockStoreRead, AsyncBlockStoreWrite};

// Re-export the primary types callers need.
pub use at_uri::{AtUri, AtUriError};
pub use atrium_repo::mst::Tree;
pub use atrium_repo::repo::{CommitBuilder, RepoBuilder, Repository};
pub use atrium_repo::Cid;
pub use car_export::{
    build_blocks_car, build_car_from_cids, car_v1_block_frame, car_v1_header, collect_commit_diff,
    collect_commit_diff_cids, collect_reachable_cids, export_commit_blocks_car,
    export_record_proof_car, export_repo_car, CarExportError, CommitDiff,
};
pub use car_import::{import_repo_car, CarImportError, ImportedRepo};
pub use data_model::{validate as validate_data_model, DataModelError};
pub use datetime::{
    is_valid as is_valid_datetime, validate as validate_datetime, AtprotoDatetimeError,
};
pub use genesis::{build_genesis_repo, create_genesis_repo, CapturingBlockStore, GenesisError};
pub use lexicon::{validate_document as validate_lexicon_document, LexiconSchemaError};
pub use records::{
    apply_writes, count_records, delete_record, generate_tid, get_record, get_record_cid,
    get_record_json, json_to_record_value, list_collections, list_records_json, put_record,
    put_record_json, record_blob_cids, record_value_to_json, validate_collection,
    validate_record_path, ListRecordsPage, ListedRecord, RecordError, WriteOp, WriteOutcome,
};
pub use signer::{CommitSigner, CommitSignerError};

/// Shared test helpers for the repo-engine crate's unit tests.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::signer::CommitSigner;

    /// Construct a `CommitSigner` from a fresh random P-256 key.
    pub(crate) fn test_signer() -> CommitSigner {
        use p256::ecdsa::SigningKey;
        let key = SigningKey::random(&mut rand_core::OsRng);
        let bytes: [u8; 32] = key.to_bytes().into();
        CommitSigner::from_bytes(&bytes).unwrap()
    }
}
