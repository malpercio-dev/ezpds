// pattern: Functional Core

//! Lower-case hex encoding, shared by production digest formatting and test golden-vector
//! comparisons across this crate.

/// Render `bytes` as lower-case hex, two characters per byte.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
