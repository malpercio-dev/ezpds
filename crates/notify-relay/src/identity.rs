// pattern: Imperative Shell
//
// The relay's persistent iroh node identity. Unlike the pds — which wraps its node secret
// under the master key in the `iroh_identity` table — the relay has no master-key
// hierarchy, so the secret lives in a file the operator backs up: 64 hex characters,
// created 0600, and refused on load if the mode is any wider. The node id derived from it
// is the relay's address, printed at startup so operators can hand it to instances.

use std::path::Path;

/// Load the node secret key from `path`, creating it on first run.
///
/// Refuses a file readable by group or other: the key is the relay's identity, and a
/// permissive mode on a shared host means anyone there can impersonate the relay.
pub fn load_or_create_secret_key(path: &Path) -> anyhow::Result<[u8; 32]> {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            check_permissions(path)?;
            parse_hex_key(contents.trim()).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut secret = [0u8; 32];
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut secret);
            write_new_key(path, &secret)?;
            tracing::info!(path = %path.display(), "generated a new iroh node secret key");
            Ok(secret)
        }
        Err(e) => Err(anyhow::anyhow!(
            "failed to read node secret key {}: {e}",
            path.display()
        )),
    }
}

/// Parse 64 hex characters into a 32-byte key (Functional Core).
fn parse_hex_key(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 {
        return Err(format!(
            "node secret key must be 64 hex characters, found {}",
            text.len()
        ));
    }
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
            .map_err(|_| "node secret key must be hexadecimal".to_owned())?;
    }
    Ok(key)
}

/// Render a key as the lowercase hex the file stores.
fn to_hex(key: &[u8; 32]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

/// Write a fresh key, creating the file with 0600 from the start — never a wide-open
/// file narrowed afterwards, which would leave a readable window.
fn write_new_key(path: &Path, secret: &[u8; 32]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let contents = to_hex(secret);

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, contents.as_bytes())?;

    Ok(())
}

/// Refuse a group/other-accessible key file on unix. A no-op elsewhere (the relay is a
/// Linux container service; other platforms are developer conveniences).
fn check_permissions(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "node secret key {} has mode {mode:o}; it must not be readable by group or other \
                 (chmod 600)",
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_key_round_trips_and_is_stable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("node.key");

        let first = load_or_create_secret_key(&path).expect("create");
        let second = load_or_create_secret_key(&path).expect("reload");
        assert_eq!(
            first, second,
            "the node id must be stable across restarts — it is the relay's address"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_fresh_key_is_created_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("node.key");
        load_or_create_secret_key(&path).expect("create");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the key file must never be group/world readable"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_key_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("node.key");
        load_or_create_secret_key(&path).expect("create");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        let err = load_or_create_secret_key(&path).expect_err("0644 must be refused");
        assert!(err.to_string().contains("group or other"), "got {err}");
    }

    #[test]
    fn a_malformed_key_file_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("node.key");
        std::fs::write(&path, "not hex").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        }

        assert!(load_or_create_secret_key(&path).is_err());
    }
}
