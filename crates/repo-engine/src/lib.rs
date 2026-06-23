// repo-engine: MST construction, CAR file storage, commit construction.
// Thin domain wrapper over atrium-repo.
// Functional Core — no HTTP, no DB schema ownership, no process-level state.

pub mod car_export;
pub mod genesis;
pub mod mst;
pub mod records;
pub mod signer;

// Re-export the blockstore traits so relay can implement them without depending on atrium-repo
// directly.
pub use atrium_repo::blockstore::{AsyncBlockStoreRead, AsyncBlockStoreWrite};

// Re-export the primary types callers need.
pub use atrium_repo::mst::Tree;
pub use atrium_repo::repo::{CommitBuilder, RepoBuilder, Repository};
pub use atrium_repo::Cid;
pub use car_export::{collect_reachable_cids, export_repo_car, CarExportError};
pub use genesis::{build_genesis_repo, create_genesis_repo, CapturingBlockStore, GenesisError};
pub use records::{
    delete_record, get_record, get_record_json, json_to_record_value, put_record, put_record_json,
    record_value_to_json, validate_record_path, RecordError,
};
pub use signer::{CommitSigner, CommitSignerError};
