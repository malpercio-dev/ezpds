//! [`Clock`], the one platform trait not yet wired. The wired ones live in their own modules:
//! `keystore`, `signer`, `events`, `backup_store`, `scheduler`.
//!
//! Wiring it means routing every wall-clock read in the ceremonies and the PLC window through
//! it; that lands with the wasm build (`SystemTime::now` panics on `wasm32-unknown-unknown`),
//! where it first matters.

use std::time::SystemTime;

/// Wall time, injected so ceremonies and the 72-hour PLC window are testable.
pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}
