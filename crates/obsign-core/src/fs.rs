// pattern: Imperative Shell

//! Async file I/O for the two user-held mirrors (`blob_backup`, `repo_backup`): the same
//! `spawn_blocking`-over-`std::fs` that `tokio::fs` is, without tokio's `fs` feature, which
//! tokio refuses on wasm. One module so the mirrors stay free of target branches.
//
// ponytail: path-based file I/O in the core; retire this when `BackupStore` carries bytes.

use std::io;
use std::path::{Path, PathBuf};

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(io::Error::other)?
}

fn owned(path: impl AsRef<Path>) -> PathBuf {
    path.as_ref().to_path_buf()
}

pub async fn read(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    let path = owned(path);
    blocking(move || std::fs::read(path)).await
}

pub async fn write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    let path = owned(path);
    let contents = contents.as_ref().to_vec();
    blocking(move || std::fs::write(path, contents)).await
}

pub async fn create_dir_all(path: impl AsRef<Path>) -> io::Result<()> {
    let path = owned(path);
    blocking(move || std::fs::create_dir_all(path)).await
}

#[cfg(test)]
pub async fn metadata(path: impl AsRef<Path>) -> io::Result<std::fs::Metadata> {
    let path = owned(path);
    blocking(move || std::fs::metadata(path)).await
}

#[cfg(test)]
pub async fn remove_file(path: impl AsRef<Path>) -> io::Result<()> {
    let path = owned(path);
    blocking(move || std::fs::remove_file(path)).await
}

pub async fn rename(from: impl AsRef<Path>, to: impl AsRef<Path>) -> io::Result<()> {
    let (from, to) = (owned(from), owned(to));
    blocking(move || std::fs::rename(from, to)).await
}

pub async fn try_exists(path: impl AsRef<Path>) -> io::Result<bool> {
    let path = owned(path);
    blocking(move || path.try_exists()).await
}
