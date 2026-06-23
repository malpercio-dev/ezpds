// repo-engine: MST construction, CAR file storage, commit construction.
// Thin domain wrapper over atrium-repo.
// Functional Core — no HTTP, no DB schema ownership, no process-level state.

pub mod genesis;
pub mod mst;
pub mod signer;

// Re-export the blockstore traits so relay can implement them without depending on atrium-repo
// directly.
pub use atrium_repo::blockstore::{AsyncBlockStoreRead, AsyncBlockStoreWrite};

// Re-export the primary types callers need.
pub use atrium_repo::mst::Tree;
pub use atrium_repo::repo::{CommitBuilder, RepoBuilder, Repository};
pub use atrium_repo::Cid;
pub use genesis::{create_genesis_repo, GenesisError};
pub use signer::{CommitSigner, CommitSignerError};
