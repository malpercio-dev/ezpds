// pattern: Mixed (unavoidable)

//! Shared helpers for the account's Spaces KEM key (ADR-0043): minting a wrapped key, reading
//! the key a DID document publishes, and the checks every account-creation path runs on a
//! client-built genesis op. Storage is `custos_db::kem_keys`.
//!
//! A KEM key is a P-256 keypair the host holds for each account. Its public half is published as
//! the DID document's `#atproto_kem` verification method; a syncer combines it with a throwaway
//! key of its own to agree a MAC secret with this host (`crypto::space_mac_secret`). It never
//! signs, and it never appears in `rotationKeys`.

use common::{ApiError, ApiResultExt, ErrorCode};
use custos_db::kem_keys::KemKey;
use serde_json::Value;

use crate::CoreState;

/// The `verificationMethods` id the KEM key is published under, in a PLC op and (as
/// `#atproto_kem`) in a DID document.
pub const KEM_VERIFICATION_METHOD_ID: &str = "atproto_kem";

/// The master key that wraps every stored private key, or 503 when the operator configured none.
pub fn master_key(state: &CoreState) -> Result<&[u8; 32], ApiError> {
    state
        .config
        .signing_key_master_key
        .as_ref()
        .map(|s| &*s.0)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::ServiceUnavailable,
                "signing key master key not configured",
            )
        })
}

/// Generate a fresh P-256 keypair and wrap its private half under the master key, ready to store.
/// The plaintext scalar is zeroized when this returns.
pub fn generate_wrapped_key(state: &CoreState) -> Result<KemKey, ApiError> {
    let master_key = master_key(state)?;
    let keypair = crypto::generate_p256_keypair()
        .or_internal_as("failed to generate KEM key", "key generation failed")?;
    let private_key_encrypted = crypto::encrypt_private_key(&keypair.private_key_bytes, master_key)
        .or_internal_as("failed to encrypt KEM key", "key encryption failed")?;
    Ok(KemKey {
        key_id: keypair.key_id.to_string(),
        public_key: keypair.public_key,
        private_key_encrypted,
    })
}

/// The `did:key:` a DID document publishes as `#atproto_kem`, if any.
pub fn published_kem_key(did_doc: &Value) -> Option<crypto::DidKeyUri> {
    crate::identity::resolution::verification_key(did_doc, "atproto_kem")
}

/// Whether `did_doc` publishes `key` as its `#atproto_kem` verification method.
pub fn publishes(did_doc: &Value, key: &KemKey) -> bool {
    published_kem_key(did_doc).is_some_and(|published| published.0 == key.key_id)
}

/// Check a client-built genesis op's `verificationMethods.atproto_kem` against the key this
/// server issued for the account: the op must publish exactly that key, so the host holds the
/// private half of whatever the new DID document advertises.
pub fn require_genesis_kem_key(
    verification_methods: &std::collections::BTreeMap<String, String>,
    issued: &KemKey,
) -> Result<(), ApiError> {
    match verification_methods.get(KEM_VERIFICATION_METHOD_ID) {
        Some(key) if *key == issued.key_id => Ok(()),
        Some(_) => Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "op verificationMethods.atproto_kem does not match the issued KEM key",
        )),
        None => Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "op verificationMethods.atproto_kem is required",
        )),
    }
}

/// The reserved KEM key a client-built genesis op publishes, matching the reference's
/// `createAccount`: `Ok(None)` when the op names no `atproto_kem`; the reservation filed under
/// `did` or under the named key otherwise; 400 when the op names a key this server never reserved
/// (the host would be advertising a key it cannot use).
pub async fn reserved_kem_key_for_op(
    state: &CoreState,
    did: &str,
    verification_methods: &std::collections::BTreeMap<String, String>,
) -> Result<Option<KemKey>, ApiError> {
    let Some(named) = verification_methods.get(KEM_VERIFICATION_METHOD_ID) else {
        return Ok(None);
    };
    let by_did = custos_db::kem_keys::get_reserved_kem_key_by_did(&state.db, did)
        .await
        .or_internal_as("failed to load reserved KEM key", "failed to load KEM key")?
        .filter(|key| key.key_id == *named);
    let reserved = match by_did {
        Some(key) => Some(key),
        None => custos_db::kem_keys::get_reserved_kem_key_by_id(&state.db, named)
            .await
            .or_internal_as("failed to load reserved KEM key", "failed to load KEM key")?,
    };
    reserved.map(Some).ok_or_else(|| {
        ApiError::new(
            ErrorCode::InvalidClaim,
            "op verificationMethods.atproto_kem does not match a reserved KEM key; \
             call reserveKemKey first",
        )
    })
}

/// The KEM key an inbound migration takes: the one `reserveKemKey` filed under its DID, or a
/// fresh one. Either way `getRecommendedDidCredentials` then recommends it.
pub async fn reserved_for_did_or_fresh(state: &CoreState, did: &str) -> Result<KemKey, ApiError> {
    match custos_db::kem_keys::get_reserved_kem_key_by_did(&state.db, did)
        .await
        .or_internal_as("failed to load reserved KEM key", "failed to load KEM key")?
    {
        Some(reserved) => Ok(reserved),
        None => generate_wrapped_key(state),
    }
}

/// The activation check, matching the reference's `assertValidDidDocumentForService`: an
/// account that holds a KEM key may only be activated once its DID document publishes it. A
/// did:web document that carries no `#atproto_kem` entry at all is let through, because only the
/// domain's owner can add one; a did:web that publishes a different key is refused like a did:plc.
pub fn check_activation_document(
    did: &str,
    did_doc: &Value,
    held: &KemKey,
) -> Result<(), ApiError> {
    let published = published_kem_key(did_doc);
    if did.starts_with("did:web:") && published.is_none() {
        return Ok(());
    }
    if published.is_some_and(|key| key.0 == held.key_id) {
        return Ok(());
    }
    Err(ApiError::new(
        ErrorCode::InvalidRequest,
        "DID document verification method does not match expected KEM key",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn key(id: &str) -> KemKey {
        KemKey {
            key_id: format!("did:key:{id}"),
            public_key: id.to_string(),
            private_key_encrypted: String::new(),
        }
    }

    fn doc(did: &str, kem: Option<&str>) -> Value {
        let mut methods = vec![json!({"id": "#atproto", "publicKeyMultibase": "zSigning"})];
        if let Some(kem) = kem {
            methods.push(json!({"id": format!("{did}#atproto_kem"), "publicKeyMultibase": kem}));
        }
        json!({"id": did, "verificationMethod": methods})
    }

    #[test]
    fn activation_check_follows_the_reference() {
        let held = key("zKem");
        for (did, published, ok) in [
            ("did:plc:a", Some("zKem"), true),
            ("did:plc:a", Some("zOther"), false),
            ("did:plc:a", None, false),
            ("did:web:a.example", None, true),
            ("did:web:a.example", Some("zKem"), true),
            ("did:web:a.example", Some("zOther"), false),
        ] {
            assert_eq!(
                check_activation_document(did, &doc(did, published), &held).is_ok(),
                ok,
                "{did} publishing {published:?}"
            );
        }
    }

    #[test]
    fn genesis_requires_exactly_the_issued_key() {
        let issued = key("zKem");
        let with = |k: Option<&str>| {
            let mut m = std::collections::BTreeMap::new();
            m.insert("atproto".to_string(), "did:key:zSigning".to_string());
            if let Some(k) = k {
                m.insert("atproto_kem".to_string(), format!("did:key:{k}"));
            }
            m
        };
        assert!(require_genesis_kem_key(&with(Some("zKem")), &issued).is_ok());
        assert!(require_genesis_kem_key(&with(Some("zOther")), &issued).is_err());
        assert!(require_genesis_kem_key(&with(None), &issued).is_err());
    }
}
