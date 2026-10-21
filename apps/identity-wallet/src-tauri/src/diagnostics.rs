//! The exportable network-error log lives in `obsign_core::diagnostics` (its module doc owns
//! the redaction rules). This is only the Tauri command that renders it from Settings.

pub use obsign_core::diagnostics::*;

/// Tauri command: render the in-memory network-error breadcrumb log as plain text for the
/// user to share from Settings. Synchronous (no state, no I/O) — mirrors `list_identities`.
pub fn export_diagnostics() -> String {
    export()
}
