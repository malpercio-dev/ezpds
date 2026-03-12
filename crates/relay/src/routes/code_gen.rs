use rand_core::{OsRng, RngCore};

pub const CODE_LEN: usize = 6;
pub const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Generate a single 6-character uppercase alphanumeric code.
pub fn generate_code() -> String {
    let mut buf = [0u8; CODE_LEN];
    OsRng.fill_bytes(&mut buf);
    buf.iter()
        .map(|&b| CHARSET[(b as usize) % CHARSET.len()] as char)
        .collect()
}
