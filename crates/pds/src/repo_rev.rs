// pattern: Imperative Shell

//! Shared repo-revision reader for the sync endpoints.
//!
//! The current commit revision (`rev`) is not always stored on the `accounts` row (a
//! pre-migration account has a repo root but no stored rev); it lives in the signed commit
//! block. Reading it there means opening the repo. Several public sync endpoints
//! (`listRepos`, `getLatestCommit`, `getRepoStatus`) need this same fallback, and routes may
//! not import from one another, so the reader is homed here beside `record_write.rs`.

use crate::app::AppState;
use crate::db::blocks::SqliteBlockStore;
use repo_engine::Repository;

/// Open `did`'s repo at `head` and return its commit revision (`rev`), or `None` if the
/// repo cannot be read.
///
/// A parse/open failure (bad CID, missing block) yields `None` rather than an error: the
/// caller decides what a missing rev means for its response (skip the repo, omit the field,
/// or map to a 404).
pub(crate) async fn read_repo_rev(state: &AppState, did: &str, head: &str) -> Option<String> {
    let root_cid = match repo_engine::Cid::try_from(head) {
        Ok(cid) => cid,
        Err(e) => {
            tracing::error!(error = %e, did = %did, "invalid repo root CID in database; omitting rev");
            return None;
        }
    };

    let block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
    let repo = match Repository::open(block_store, root_cid).await {
        Ok(repo) => repo,
        Err(e) => {
            tracing::warn!(error = %e, did = %did, "failed to open repo; omitting rev");
            return None;
        }
    };

    Some(repo.commit().rev().as_str().to_string())
}
