// pattern: Mixed (unavoidable)
//
// Client-side Shamir share generation for the DID ceremony (the ceremony inversion):
// the wallet — not the server — generates the recovery seed, derives the recovery
// rotation key from it, and splits the seed 2-of-3 into v2 share envelopes. Custos
// receives exactly one share (the Share 2 envelope, deposited with the ceremony
// request) and never sees the seed or the other shares, so no server backup can ever
// hold reconstruction material.
//
// Retry resilience lives here too: the generated set is persisted in a Keychain
// staging slot (`ceremony-staging` — transient working material, distinct from the
// durable `recovery-share-1` slot) BEFORE any network call, so a retry reuses the
// identical set (same set_id) instead of orphaning a prior attempt's escrow deposit.
// The staging record holds the three envelopes only — the seed is recomputed from
// Shares 1+2 on load, and every load re-validates each envelope's checksum and
// cross-checks set_ids, so a corrupted record regenerates instead of half-working.
//
// Teardown order is load-bearing: `clear_staging` runs only after Share 1 has
// verifiably reached its durable slot and the user has confirmed saving Share 3
// (`confirm_share_backup` in lib.rs drives that), because until then the staging
// slot is the only durable home of the seed material.

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::keychain;

/// Keychain account for the in-flight ceremony share set. Transient working
/// material — deleted by [`clear_staging`] once the ceremony is confirmed.
pub const STAGING_ACCOUNT: &str = "ceremony-staging";

/// Bumped only on a breaking staging-record format change; a mismatched version
/// reads as corrupt and regenerates.
const STAGING_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum ShareCeremonyError {
    #[error("crypto failure: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("OS RNG unavailable: {0}")]
    Rng(String),
    #[error("keychain failure: {0}")]
    Keychain(#[from] keychain::KeychainError),
}

/// The wallet-generated share set for one DID ceremony attempt (or a staged retry).
///
/// Encoded share strings are share material and ride in [`Zeroizing`] buffers, matching
/// the crypto crate's rule that share material never lands in non-zeroizing storage.
pub struct CeremonyShareSet {
    /// did:key URI of the recovery rotation key derived from the seed — goes into the
    /// genesis op's `rotationKeys` (slot \[1\]) and the ceremony request's `recoveryKey`.
    pub recovery_key_id: String,
    /// Base32 v2 envelope of Share 1 — written to the durable `recovery-share-1` slot
    /// after promotion.
    pub share1: Zeroizing<String>,
    /// Base32 v2 envelope of Share 2 — the escrow deposit sent to Custos.
    pub share2: Zeroizing<String>,
    /// Base32 v2 envelope of Share 3 — the user's manual-backup copy (QR form).
    pub share3: Zeroizing<String>,
    /// Share 3 rendered as the BIP-39-style word phrase (identical 42 bytes).
    pub share3_words: Zeroizing<String>,
}

/// The staging slot's JSON payload. The seed is deliberately absent — it is
/// `combine_envelopes(share1, share2)`, so storing it again would only widen the
/// secret surface.
#[derive(Serialize, Deserialize)]
struct StagingRecord {
    version: u32,
    /// The ceremony inputs this set was generated for. A retry with different inputs
    /// (different handle, different PDS) is a different ceremony — regenerate.
    handle: String,
    pds_url: String,
    share1: String,
    share2: String,
    share3: String,
}

/// Load the staged share set for `(handle, pds_url)` if a valid one exists, else
/// generate a fresh set and stage it — always BEFORE the caller makes any network call,
/// so a mid-ceremony failure retries with the identical set (same `set_id`).
pub fn load_or_create(handle: &str, pds_url: &str) -> Result<CeremonyShareSet, ShareCeremonyError> {
    if let Some(staged) = load_staged(handle, pds_url) {
        return Ok(staged);
    }

    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(seed.as_mut())
        .map_err(|e| ShareCeremonyError::Rng(e.to_string()))?;
    let mut set_id_bytes = [0u8; 4];
    OsRng
        .try_fill_bytes(&mut set_id_bytes)
        .map_err(|e| ShareCeremonyError::Rng(e.to_string()))?;
    let set_id = u32::from_be_bytes(set_id_bytes);

    let envelopes = crypto::split_secret_into_envelopes(&seed, set_id)?;
    let recovery = crypto::derive_recovery_keypair(&seed)?;

    let share1 = envelopes[0].encode_share();
    let share2 = envelopes[1].encode_share();
    let share3 = envelopes[2].encode_share();
    let share3_words = envelopes[2].encode_share_words();

    // Stage before returning: from here on, a retry of the same ceremony must reuse
    // this exact set. The serialized record is share material — zeroized after the
    // Keychain write.
    let record = Zeroizing::new(
        serde_json::to_string(&StagingRecord {
            version: STAGING_VERSION,
            handle: handle.to_string(),
            pds_url: pds_url.to_string(),
            share1: share1.to_string(),
            share2: share2.to_string(),
            share3: share3.to_string(),
        })
        .expect("staging record serialization cannot fail"),
    );
    keychain::store_item(STAGING_ACCOUNT, record.as_bytes())?;

    Ok(CeremonyShareSet {
        recovery_key_id: recovery.key_id.0,
        share1,
        share2,
        share3,
        share3_words,
    })
}

/// Read and validate the staging slot. Any defect — missing item, unparseable JSON,
/// version or ceremony-input mismatch, a corrupt envelope, or cross-set envelopes —
/// reads as "no staged set" (logged), so the caller regenerates fresh material.
fn load_staged(handle: &str, pds_url: &str) -> Option<CeremonyShareSet> {
    let bytes = match keychain::get_item(STAGING_ACCOUNT) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(e) if keychain::is_not_found(&e) => return None,
        Err(e) => {
            tracing::warn!(error = %e, "ceremony staging slot unreadable; regenerating share set");
            return None;
        }
    };
    let record: StagingRecord = match serde_json::from_slice(&bytes) {
        Ok(record) => record,
        Err(e) => {
            tracing::warn!(error = %e, "ceremony staging record unparseable; regenerating share set");
            return None;
        }
    };
    if record.version != STAGING_VERSION {
        tracing::warn!(
            version = record.version,
            "ceremony staging record has unsupported version; regenerating share set"
        );
        return None;
    }
    if record.handle != handle || record.pds_url != pds_url {
        tracing::info!("ceremony inputs changed since staging; regenerating share set");
        return None;
    }

    let decode = |encoded: &str, index: u8| -> Option<crypto::ShareEnvelope> {
        match crypto::ShareEnvelope::decode_share(encoded) {
            Ok(env) if env.index() == index => Some(env),
            Ok(env) => {
                tracing::warn!(
                    expected = index,
                    got = env.index(),
                    "staged share has wrong index; regenerating share set"
                );
                None
            }
            Err(e) => {
                tracing::warn!(error = %e, "staged share failed validation; regenerating share set");
                None
            }
        }
    };
    let env1 = decode(&record.share1, 1)?;
    let env2 = decode(&record.share2, 2)?;
    let env3 = decode(&record.share3, 3)?;
    if env1.set_id() != env2.set_id() || env2.set_id() != env3.set_id() {
        tracing::warn!("staged shares span set_ids; regenerating share set");
        return None;
    }

    // The seed is not stored — recompute it to re-derive the recovery key.
    let seed = match crypto::combine_envelopes(&env1, &env2) {
        Ok(seed) => seed,
        Err(e) => {
            tracing::warn!(error = %e, "staged shares failed to combine; regenerating share set");
            return None;
        }
    };
    let recovery = match crypto::derive_recovery_keypair(&seed) {
        Ok(keypair) => keypair,
        Err(e) => {
            tracing::warn!(error = %e, "recovery key derivation failed on staged seed; regenerating share set");
            return None;
        }
    };

    tracing::info!(set_id = env1.set_id(), "reusing staged ceremony share set");
    Some(CeremonyShareSet {
        recovery_key_id: recovery.key_id.0,
        share1: env1.encode_share(),
        share2: env2.encode_share(),
        share3: env3.encode_share(),
        share3_words: env3.encode_share_words(),
    })
}

/// Tear down the staging slot — the seed material's last transient home. Idempotent:
/// an absent slot is success (the teardown already happened).
pub fn clear_staging() -> Result<(), keychain::KeychainError> {
    match keychain::delete_item(STAGING_ACCOUNT) {
        Ok(()) => Ok(()),
        Err(e) if keychain::is_not_found(&e) => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HANDLE: &str = "alice.example.com";
    const PDS: &str = "https://pds.example.com";

    #[test]
    fn generates_and_stages_a_valid_set() {
        keychain::clear_for_test();
        let set = load_or_create(HANDLE, PDS).unwrap();

        // All three envelopes decode, share the same set_id, and carry their indices.
        let env1 = crypto::ShareEnvelope::decode_share(&set.share1).unwrap();
        let env2 = crypto::ShareEnvelope::decode_share(&set.share2).unwrap();
        let env3 = crypto::ShareEnvelope::decode_share(&set.share3).unwrap();
        assert_eq!(env1.index(), 1);
        assert_eq!(env2.index(), 2);
        assert_eq!(env3.index(), 3);
        assert_eq!(env1.set_id(), env2.set_id());
        assert_eq!(env2.set_id(), env3.set_id());

        // The word phrase encodes the same envelope as the base32 form.
        let from_words = crypto::ShareEnvelope::decode_share_words(&set.share3_words).unwrap();
        assert_eq!(from_words.set_id(), env3.set_id());
        assert_eq!(from_words.index(), 3);

        // Any two shares reconstruct a seed whose derived key matches the declared one.
        let seed = crypto::combine_envelopes(&env1, &env3).unwrap();
        let derived = crypto::derive_recovery_keypair(&seed).unwrap();
        assert_eq!(derived.key_id.0, set.recovery_key_id);
    }

    #[test]
    fn retry_reuses_the_staged_set() {
        keychain::clear_for_test();
        let first = load_or_create(HANDLE, PDS).unwrap();
        let second = load_or_create(HANDLE, PDS).unwrap();
        assert_eq!(*first.share1, *second.share1, "retry must reuse Share 1");
        assert_eq!(*first.share2, *second.share2, "retry must reuse Share 2");
        assert_eq!(*first.share3, *second.share3, "retry must reuse Share 3");
        assert_eq!(first.recovery_key_id, second.recovery_key_id);
        let set_id = |s: &str| crypto::ShareEnvelope::decode_share(s).unwrap().set_id();
        assert_eq!(
            set_id(&first.share2),
            set_id(&second.share2),
            "same set_id across retries — no orphaned escrow"
        );
    }

    #[test]
    fn changed_ceremony_inputs_regenerate() {
        keychain::clear_for_test();
        let first = load_or_create(HANDLE, PDS).unwrap();
        let other = load_or_create("bob.example.com", PDS).unwrap();
        assert_ne!(
            *first.share2, *other.share2,
            "a different ceremony must not reuse the old set"
        );
    }

    #[test]
    fn corrupt_staging_record_regenerates() {
        keychain::clear_for_test();
        let first = load_or_create(HANDLE, PDS).unwrap();
        keychain::store_item(STAGING_ACCOUNT, b"not json").unwrap();
        let second = load_or_create(HANDLE, PDS).unwrap();
        assert_ne!(
            *first.share2, *second.share2,
            "a corrupt staging record must regenerate, not half-work"
        );
    }

    #[test]
    fn clear_staging_is_idempotent() {
        keychain::clear_for_test();
        load_or_create(HANDLE, PDS).unwrap();
        clear_staging().unwrap();
        assert!(matches!(
            keychain::get_item(STAGING_ACCOUNT),
            Err(ref e) if keychain::is_not_found(e)
        ));
        clear_staging().unwrap();
    }
}
