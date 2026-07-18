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
// cross-checks set_ids. A present-but-unreadable record **fails closed**
// (`StagingCorrupt`) rather than regenerating: it may be the exact set a prior
// attempt already bound to a genesis op and escrowed, so overwriting it would
// permanently destroy the recovery seed. Only a genuinely absent slot — or one
// staged for different ceremony inputs, which a new ceremony explicitly abandons —
// permits fresh generation.
//
// Teardown order is load-bearing: `clear_staging` runs only after Share 1 has
// verifiably reached its durable slot and the user has confirmed saving Share 3
// (`confirm_share_backup` in lib.rs drives that), because until then the staging
// slot is the only durable home of the seed material.

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::keychain;

/// Keychain account for the in-flight *create* ceremony share set. Transient working
/// material — deleted by [`clear_staging`] once the ceremony is confirmed.
pub const STAGING_ACCOUNT: &str = "ceremony-staging";

/// Keychain account for an in-flight *re-key* share set, scoped per DID.
///
/// Re-key (moving an existing old-model account onto a client-generated recovery key)
/// runs its own ceremony against an existing identity, so it gets a slot keyed by DID
/// rather than sharing the single create-flow slot. A per-DID slot is load-bearing for
/// safety: unlike the create flow, a re-key must NEVER abandon a staged set because a
/// *different* DID's re-key started — a staged set whose rotation op has already landed
/// is the only durable home of that account's new recovery seed. Keying the account by
/// DID means one identity's re-key can never overwrite or orphan another's.
fn rekey_staging_account(did: &str) -> String {
    format!("rekey-staging:{did}")
}

/// Bumped only on a breaking staging-record format change; a mismatched version
/// reads as corrupt and fails closed (`StagingCorrupt`).
const STAGING_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum ShareCeremonyError {
    #[error("crypto failure: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("OS RNG unavailable: {0}")]
    Rng(String),
    #[error("keychain failure: {0}")]
    Keychain(#[from] keychain::KeychainError),
    /// A staging record exists but could not be read or validated. Fail closed: the
    /// record may be the exact set already bound to a genesis op (and escrowed) by a
    /// prior attempt, so it must never be silently overwritten with fresh material —
    /// that would permanently destroy the recovery seed.
    #[error("ceremony staging record is present but unreadable: {0}")]
    StagingCorrupt(String),
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
///
/// The share fields are share material held in plain `String`s while the record is
/// (de)serialized, so the record wipes them on drop (`Drop` below) — the same rule as
/// every other in-memory home of share material.
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

impl Drop for StagingRecord {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.share1.zeroize();
        self.share2.zeroize();
        self.share3.zeroize();
    }
}

/// Load the staged *create*-ceremony share set for `(handle, pds_url)` if a valid one
/// exists, else generate a fresh set and stage it — always BEFORE the caller makes any
/// network call, so a mid-ceremony failure retries with the identical set (same
/// `set_id`).
pub fn load_or_create(handle: &str, pds_url: &str) -> Result<CeremonyShareSet, ShareCeremonyError> {
    load_or_create_in_account(STAGING_ACCOUNT, handle, pds_url)
}

/// Load-or-create for a re-key ceremony: same generation/reload semantics as
/// [`load_or_create`], but staged in the per-DID re-key slot (see
/// [`rekey_staging_account`]). The `(did, pds_url)` pair is the discriminator, so a
/// resumed re-key for the same DID always reloads the identical set — a re-key never
/// abandons a staged set the way a create ceremony does on changed inputs.
pub fn load_or_create_for_rekey(
    did: &str,
    pds_url: &str,
) -> Result<CeremonyShareSet, ShareCeremonyError> {
    load_or_create_in_account(&rekey_staging_account(did), did, pds_url)
}

/// Shared implementation: load the staged set from `account` (bound to the
/// `(discriminator_a, discriminator_b)` pair), else generate a fresh set and stage it
/// there before returning.
fn load_or_create_in_account(
    account: &str,
    discriminator_a: &str,
    discriminator_b: &str,
) -> Result<CeremonyShareSet, ShareCeremonyError> {
    if let Some(staged) = load_staged(account, discriminator_a, discriminator_b)? {
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
            handle: discriminator_a.to_string(),
            pds_url: discriminator_b.to_string(),
            share1: share1.to_string(),
            share2: share2.to_string(),
            share3: share3.to_string(),
        })
        .expect("staging record serialization cannot fail"),
    );
    keychain::store_item(account, record.as_bytes())?;

    Ok(CeremonyShareSet {
        recovery_key_id: recovery.key_id.0,
        share1,
        share2,
        share3,
        share3_words,
    })
}

/// Read and validate the staging slot.
///
/// Fail-closed contract: only two outcomes permit generating fresh material —
/// `Ok(None)` for a genuinely absent slot, or for a slot staged under *different
/// ceremony inputs* (a new handle/PDS is a new ceremony; starting one is the user's
/// explicit abandonment of the old attempt, whose set can never bind to this
/// ceremony's genesis op). Every other defect — a transient read error, unparseable
/// JSON, an unsupported version, a corrupt envelope, cross-set envelopes, a failed
/// combine/derivation — is `Err(StagingCorrupt)`: the record may be the exact set a
/// prior attempt already bound to a genesis op and escrowed, so overwriting it with
/// unrelated shares would permanently destroy the recovery seed. The slot is
/// preserved for a later retry or manual inspection.
fn load_staged(
    account: &str,
    discriminator_a: &str,
    discriminator_b: &str,
) -> Result<Option<CeremonyShareSet>, ShareCeremonyError> {
    let bytes = match keychain::get_item(account) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(e) if keychain::is_not_found(&e) => return Ok(None),
        Err(e) => {
            tracing::error!(error = %e, "ceremony staging slot unreadable; failing closed");
            return Err(ShareCeremonyError::StagingCorrupt(format!(
                "keychain read failed: {e}"
            )));
        }
    };
    let record: StagingRecord = serde_json::from_slice(&bytes).map_err(|e| {
        tracing::error!(error = %e, "ceremony staging record unparseable; failing closed");
        ShareCeremonyError::StagingCorrupt(format!("unparseable staging record: {e}"))
    })?;
    if record.version != STAGING_VERSION {
        tracing::error!(
            version = record.version,
            "ceremony staging record has unsupported version; failing closed"
        );
        return Err(ShareCeremonyError::StagingCorrupt(format!(
            "unsupported staging record version {}",
            record.version
        )));
    }
    if record.handle != discriminator_a || record.pds_url != discriminator_b {
        tracing::warn!(
            "ceremony inputs changed since staging; abandoning the staged set and regenerating"
        );
        return Ok(None);
    }

    let decode = |encoded: &str, index: u8| -> Result<crypto::ShareEnvelope, ShareCeremonyError> {
        match crypto::ShareEnvelope::decode_share(encoded) {
            Ok(env) if env.index() == index => Ok(env),
            Ok(env) => {
                tracing::error!(
                    expected = index,
                    got = env.index(),
                    "staged share has wrong index; failing closed"
                );
                Err(ShareCeremonyError::StagingCorrupt(format!(
                    "staged share has index {} where {index} was expected",
                    env.index()
                )))
            }
            Err(e) => {
                tracing::error!(error = %e, "staged share failed validation; failing closed");
                Err(ShareCeremonyError::StagingCorrupt(format!(
                    "staged share failed validation: {e}"
                )))
            }
        }
    };
    let env1 = decode(&record.share1, 1)?;
    let env2 = decode(&record.share2, 2)?;
    let env3 = decode(&record.share3, 3)?;
    if env1.set_id() != env2.set_id() || env2.set_id() != env3.set_id() {
        tracing::error!("staged shares span set_ids; failing closed");
        return Err(ShareCeremonyError::StagingCorrupt(
            "staged shares span set_ids".to_string(),
        ));
    }

    // The seed is not stored — recompute it to re-derive the recovery key.
    let seed = crypto::combine_envelopes(&env1, &env2).map_err(|e| {
        tracing::error!(error = %e, "staged shares failed to combine; failing closed");
        ShareCeremonyError::StagingCorrupt(format!("staged shares failed to combine: {e}"))
    })?;
    let recovery = crypto::derive_recovery_keypair(&seed).map_err(|e| {
        tracing::error!(error = %e, "recovery key derivation failed on staged seed; failing closed");
        ShareCeremonyError::StagingCorrupt(format!("recovery key derivation failed: {e}"))
    })?;

    tracing::info!(set_id = env1.set_id(), "reusing staged ceremony share set");
    Ok(Some(CeremonyShareSet {
        recovery_key_id: recovery.key_id.0,
        share1: env1.encode_share(),
        share2: env2.encode_share(),
        share3: env3.encode_share(),
        share3_words: env3.encode_share_words(),
    }))
}

/// Tear down the *create*-ceremony staging slot — the seed material's last transient
/// home. Idempotent: an absent slot is success (the teardown already happened).
pub fn clear_staging() -> Result<(), keychain::KeychainError> {
    clear_staging_account(STAGING_ACCOUNT)
}

/// Tear down the per-DID re-key staging slot. Idempotent, like [`clear_staging`].
pub fn clear_rekey_staging(did: &str) -> Result<(), keychain::KeychainError> {
    clear_staging_account(&rekey_staging_account(did))
}

/// Whether a per-DID re-key staging slot exists — i.e. a re-key was started for this DID and has
/// not yet been confirmed/torn down. Used to resurface the "finish your upgrade" prompt when a
/// re-key was interrupted after its PLC op landed (so the identity already reads as new-model) but
/// before escrow/Share 1/confirmation completed. A transient keychain read error reads as "not in
/// progress" (fail-open for a prompt is safe — the account is never worse off un-prompted).
pub fn rekey_staging_exists(did: &str) -> bool {
    keychain::get_item(&rekey_staging_account(did)).is_ok()
}

fn clear_staging_account(account: &str) -> Result<(), keychain::KeychainError> {
    match keychain::delete_item(account) {
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
    fn corrupt_staging_record_fails_closed_and_preserves_the_slot() {
        keychain::clear_for_test();
        load_or_create(HANDLE, PDS).unwrap();
        keychain::store_item(STAGING_ACCOUNT, b"not json").unwrap();
        // A present-but-unreadable record must never be overwritten with fresh
        // material — it may be the set a prior attempt already escrowed.
        // (CeremonyShareSet has no Debug — share material must not be printable.)
        let err = load_or_create(HANDLE, PDS)
            .map(|_| ())
            .expect_err("corrupt staging must fail closed");
        assert!(matches!(err, ShareCeremonyError::StagingCorrupt(_)));
        assert_eq!(
            keychain::get_item(STAGING_ACCOUNT).unwrap(),
            b"not json".to_vec(),
            "the staging slot must be preserved for inspection/retry"
        );
    }

    #[test]
    fn tampered_staged_share_fails_closed() {
        keychain::clear_for_test();
        let first = load_or_create(HANDLE, PDS).unwrap();
        // Corrupt one envelope inside an otherwise valid record: the checksum check
        // must fail the load closed rather than regenerate. Flip share2's first
        // character to a different base32 character (deterministic corruption).
        let flipped_first = if first.share2.starts_with('A') {
            "B"
        } else {
            "A"
        };
        let mut corrupt_share2 = first.share2.to_string();
        corrupt_share2.replace_range(0..1, flipped_first);
        let bytes = keychain::get_item(STAGING_ACCOUNT).unwrap();
        let tampered = String::from_utf8(bytes)
            .unwrap()
            .replace(&*first.share2, &corrupt_share2);
        keychain::store_item(STAGING_ACCOUNT, tampered.as_bytes()).unwrap();
        assert!(matches!(
            load_or_create(HANDLE, PDS),
            Err(ShareCeremonyError::StagingCorrupt(_))
        ));
        // The envelope-validation failure path preserves the slot exactly like the
        // JSON-corruption path — the record is never overwritten with fresh material.
        assert_eq!(
            keychain::get_item(STAGING_ACCOUNT).unwrap(),
            tampered.as_bytes().to_vec(),
            "the tampered staging record must be preserved for inspection/retry"
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

    const DID_A: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    const DID_B: &str = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn rekey_staging_is_scoped_per_did() {
        keychain::clear_for_test();
        // Two identities re-keying concurrently must not share a staging slot: each
        // reloads its own set, and neither abandons the other's.
        let a = load_or_create_for_rekey(DID_A, PDS).unwrap();
        let b = load_or_create_for_rekey(DID_B, PDS).unwrap();
        assert_ne!(*a.share2, *b.share2, "distinct DIDs get distinct sets");

        let a_again = load_or_create_for_rekey(DID_A, PDS).unwrap();
        assert_eq!(
            *a.share2, *a_again.share2,
            "DID A's set survives DID B's re-key staging"
        );
        assert_eq!(a.recovery_key_id, a_again.recovery_key_id);
    }

    #[test]
    fn rekey_staging_does_not_collide_with_create_staging() {
        keychain::clear_for_test();
        let create = load_or_create(HANDLE, PDS).unwrap();
        let rekey = load_or_create_for_rekey(DID_A, PDS).unwrap();
        assert_ne!(
            *create.share2, *rekey.share2,
            "create and re-key ceremonies use independent slots"
        );
        // Clearing the re-key slot leaves the create slot intact and vice versa.
        clear_rekey_staging(DID_A).unwrap();
        assert!(keychain::get_item(STAGING_ACCOUNT).is_ok());
        assert_eq!(
            *load_or_create(HANDLE, PDS).unwrap().share2,
            *create.share2,
            "create staging is untouched by re-key teardown"
        );
    }

    #[test]
    fn clear_rekey_staging_is_idempotent() {
        keychain::clear_for_test();
        load_or_create_for_rekey(DID_A, PDS).unwrap();
        clear_rekey_staging(DID_A).unwrap();
        assert!(matches!(
            keychain::get_item(&rekey_staging_account(DID_A)),
            Err(ref e) if keychain::is_not_found(e)
        ));
        clear_rekey_staging(DID_A).unwrap();
    }
}
