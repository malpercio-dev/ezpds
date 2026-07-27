// pattern: Imperative Shell
//
// The shared "which keys may sign a sovereign proof for this account" lookup, behind the three
// passwordless auth surfaces (`POST /v1/sessions/sovereign`, `POST /oauth/authorize/approve`,
// and the deletion-proof branch of `POST /xrpc/com.atproto.server.deleteAccount`).
// Signature verification is already method-agnostic (`crypto::verify_did_key_signature` over a
// `did:key:` URI, P-256 and secp256k1), so the authority lookup is the only place a DID method
// matters. It lives here rather than in either route because routes may not import one another.
//
// Both methods resolve their authority **live** from the authoritative source, never from the
// `did_documents` cache — for did:plc because `rotationKeys` is authoritative only in the latest
// non-nullified audit-log operation, and for did:web because that cache is writable by
// `POST /v1/did-web/document`.

use common::ApiError;
use serde_json::Value;

use crate::app::AppState;

use super::plc::fetch_current_plc_state;
use super::resolution::resolve_web_did_document;

/// The set of `did:key:` URIs currently authorized to sign a sovereign proof for an account,
/// plus a short description of the authority state they were read from (for the success log).
pub struct AuthoritySet {
    keys: Vec<String>,
    pub source: String,
}

impl AuthoritySet {
    pub fn authorizes(&self, signing_key: &str) -> bool {
        self.keys.iter().any(|key| key == signing_key)
    }
}

/// A failed authority lookup, split by who the caller should blame.
pub enum AuthorityError {
    /// The DID method, document, or policy denies any authority. The caller collapses this into
    /// its own opaque rejection — it must never become a distinguishable response.
    Unauthorized(&'static str),
    /// The authoritative source could not be consulted. Propagated as-is so an upstream outage
    /// still fails closed with its own status (a plc.directory 503 stays a 502, not a 401).
    Lookup(ApiError),
}

fn is_plc_did(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("did:plc:") else {
        return false;
    };
    suffix.len() == 24
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
}

/// Resolve the account's current signing authority from its DID method's authoritative source.
pub async fn authorized_signing_keys(
    state: &AppState,
    did: &str,
) -> Result<AuthoritySet, AuthorityError> {
    if is_plc_did(did) {
        plc_authority(state, did).await
    } else if did.starts_with("did:web:") {
        web_authority(state, did).await
    } else {
        Err(AuthorityError::Unauthorized("unsupported_did_method"))
    }
}

/// did:plc — every key in the DID's current `rotationKeys`. A Custos-held rotation key qualifies
/// under exactly the same PLC semantics as any other, granting Custos no power over an account it
/// already hosts: rewriting the rotation set requires an existing rotation key, and plc.directory
/// is external to this server.
async fn plc_authority(state: &AppState, did: &str) -> Result<AuthoritySet, AuthorityError> {
    let plc = fetch_current_plc_state(&state.http_client, &state.config.plc_directory_url, did)
        .await
        .map_err(AuthorityError::Lookup)?;
    Ok(AuthoritySet {
        keys: plc.rotation_keys,
        source: format!("plc:{}", plc.cid),
    })
}

/// did:web — exactly the document's `{did}#device` verification method, and nothing else.
///
/// Not "any verificationMethod": `#atproto`'s private key is Custos-held, so a broader set would
/// let this server sign its own sovereign envelope for an account it hosts. `#device` alone also
/// keeps one rule across both did:web paths — `create_did.rs` already enforces `#device`
/// specifically when promoting a new did:web.
///
/// Gated on self-hosted only. `POST /v1/did-web/document` lets an account rewrite its served
/// document under mere session auth, so for a Custos-hosted did:web a stolen session could install
/// an attacker `#device` key and bootstrap sovereign sessions — a privilege escalation with no key
/// compromise. That route already refuses unless hosting is enabled, so
/// `did_web_hosting_enabled_at IS NULL` **is** the condition "no session-authed rewrite is
/// possible", with no gap in either direction. Making `#device` immutable across such an edit
/// would let this gate be dropped later without redesigning anything.
async fn web_authority(state: &AppState, did: &str) -> Result<AuthoritySet, AuthorityError> {
    // Cheap DB gate before the outbound fetch.
    if crate::db::dids::did_web_hosting_enabled(&state.db, did)
        .await
        .map_err(AuthorityError::Lookup)?
    {
        return Err(AuthorityError::Unauthorized("did_web_hosting_enabled"));
    }

    let document = resolve_web_did_document(state, did)
        .await
        .map_err(AuthorityError::Lookup)?;
    let device_key = device_verification_key(&document, did)?;
    Ok(AuthoritySet {
        keys: vec![device_key],
        source: "did:web#device".to_string(),
    })
}

/// Extract the document's `#device` key as a `did:key:` URI, matching `create_did.rs`'s predicate
/// (`type == "Multikey"`, `controller == did`, exact `{did}#device` id). The difference in shape:
/// `create_did.rs` *verifies* a known key by comparing `publicKeyMultibase`, whereas this
/// *discovers* it, so it extracts that field instead — rendered as `did:key:{multibase}`, since the
/// verification method carries bare multibase while a PLC rotation set stores `did:key:` URIs.
///
/// More than one `#device`-shaped entry is malformed (duplicate `id` values already violate DID
/// Core) and fails closed rather than picking one by array order.
fn device_verification_key(document: &Value, did: &str) -> Result<String, AuthorityError> {
    let expected_id = format!("{did}#device");
    let methods = document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .ok_or(AuthorityError::Unauthorized("no_verification_methods"))?;
    let mut matches = methods.iter().filter(|method| {
        method.get("id").and_then(Value::as_str) == Some(&expected_id)
            && method.get("type").and_then(Value::as_str) == Some("Multikey")
            && method.get("controller").and_then(Value::as_str) == Some(did)
    });
    let Some(method) = matches.next() else {
        return Err(AuthorityError::Unauthorized(
            "no_device_verification_method",
        ));
    };
    if matches.next().is_some() {
        return Err(AuthorityError::Unauthorized(
            "duplicate_device_verification_method",
        ));
    }
    let multibase = method
        .get("publicKeyMultibase")
        .and_then(Value::as_str)
        .ok_or(AuthorityError::Unauthorized("device_key_not_multibase"))?;
    Ok(format!("did:key:{multibase}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const WEB_DID: &str = "did:web:example.com";

    fn document(methods: Value) -> Value {
        json!({ "id": WEB_DID, "verificationMethod": methods })
    }

    fn device_method(multibase: &str) -> Value {
        json!({
            "id": format!("{WEB_DID}#device"),
            "type": "Multikey",
            "controller": WEB_DID,
            "publicKeyMultibase": multibase
        })
    }

    fn key(document: &Value) -> Result<String, AuthorityError> {
        device_verification_key(document, WEB_DID)
    }

    fn reason(result: Result<String, AuthorityError>) -> &'static str {
        match result {
            Err(AuthorityError::Unauthorized(reason)) => reason,
            _ => panic!("expected an Unauthorized rejection"),
        }
    }

    #[test]
    fn device_method_is_rendered_as_a_did_key_uri() {
        let doc = document(json!([device_method("zDevice")]));
        assert_eq!(key(&doc).ok().as_deref(), Some("did:key:zDevice"));
    }

    #[test]
    fn the_custos_held_atproto_key_is_never_authority() {
        let doc = document(json!([{
            "id": format!("{WEB_DID}#atproto"),
            "type": "Multikey",
            "controller": WEB_DID,
            "publicKeyMultibase": "zRepo"
        }]));
        assert_eq!(reason(key(&doc)), "no_device_verification_method");
    }

    #[test]
    fn a_duplicate_device_entry_fails_closed_instead_of_picking_by_order() {
        let doc = document(json!([device_method("zFirst"), device_method("zSecond")]));
        assert_eq!(reason(key(&doc)), "duplicate_device_verification_method");
    }

    #[test]
    fn a_device_entry_failing_any_predicate_field_is_not_authority() {
        for method in [
            json!({"id": format!("{WEB_DID}#device"), "type": "JsonWebKey2020", "controller": WEB_DID, "publicKeyMultibase": "zDevice"}),
            json!({"id": format!("{WEB_DID}#device"), "type": "Multikey", "controller": "did:web:attacker.example", "publicKeyMultibase": "zDevice"}),
            json!({"id": "did:web:other.example#device", "type": "Multikey", "controller": WEB_DID, "publicKeyMultibase": "zDevice"}),
        ] {
            assert_eq!(
                reason(key(&document(json!([method])))),
                "no_device_verification_method"
            );
        }
    }

    #[test]
    fn a_device_entry_without_a_multibase_key_is_rejected() {
        let doc = document(json!([{
            "id": format!("{WEB_DID}#device"),
            "type": "Multikey",
            "controller": WEB_DID
        }]));
        assert_eq!(reason(key(&doc)), "device_key_not_multibase");
    }

    #[test]
    fn a_document_without_verification_methods_is_rejected() {
        assert_eq!(
            reason(device_verification_key(&json!({"id": WEB_DID}), WEB_DID)),
            "no_verification_methods"
        );
    }

    #[test]
    fn plc_did_syntax_is_enforced_exactly() {
        assert!(is_plc_did("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(!is_plc_did("did:plc:tooshort"));
        assert!(!is_plc_did("did:plc:AAAAAAAAAAAAAAAAAAAAAAAA"));
        assert!(!is_plc_did("did:plc:aaaaaaaaaaaaaaaaaaaaaaa1"));
        assert!(!is_plc_did(WEB_DID));
    }
}
