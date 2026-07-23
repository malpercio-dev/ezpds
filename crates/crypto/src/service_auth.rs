// pattern: Functional Core
//
// Offline atproto inter-service auth JWT minting. The wallet-side twin of the PDS's
// `mint_service_auth_jwt` (crates/pds/src/auth/jwt.rs): the same
// `base64url(header).base64url(payload).base64url(signature)` ES256 triple, but taking
// the crate's standard fallible external-signer callback so a wallet-held key (software
// scalar or Secure Enclave) can sign it. This is what makes sovereign disaster recovery
// possible: with a self-controlled `atproto` signing key enrolled on the DID, the wallet
// mints the `createAccount` service-auth token itself instead of asking the (dead)
// source PDS's `getServiceAuth` for one.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::error::CryptoError;
use crate::plc::ensure_low_s_callback_signature;

/// Mint an atproto inter-service auth JWT signed by an external callback.
///
/// The output is `base64url(header).base64url(payload).base64url(signature)` where
/// `signature` is the raw 64-byte r‖s P-256 ECDSA signature of the `header.payload`
/// bytes. Header is `{"typ":"JWT","alg":"ES256"}`; claims are `iss` (the account DID),
/// `aud` (the receiving service DID, no `#fragment`), `iat`, the absolute `exp`, and —
/// when `lxm` is `Some` — the lexicon method the token authorizes.
///
/// The verifier resolves the issuer's `#atproto` did:key from plc.directory and checks
/// the signature as strict ES256, so the callback must return a **low-S canonical**
/// 64-byte signature (the same contract as the PLC op builders); a non-64-byte or
/// high-S signature is rejected here rather than minting a token the network would
/// refuse.
///
/// # Errors
/// Propagates any `CryptoError` from the callback, or `CryptoError::PlcOperation` for a
/// malformed callback signature or serialization failure.
pub fn mint_service_auth_jwt<F>(
    sign: F,
    iss: &str,
    aud: &str,
    lxm: Option<&str>,
    iat: u64,
    exp: u64,
) -> Result<String, CryptoError>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, CryptoError>,
{
    let header = serde_json::json!({ "typ": "JWT", "alg": "ES256" });
    let mut payload = serde_json::json!({
        "iss": iss,
        "aud": aud,
        "iat": iat,
        "exp": exp,
    });
    if let Some(lxm) = lxm {
        payload["lxm"] = serde_json::Value::String(lxm.to_string());
    }

    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header)
            .map_err(|e| CryptoError::PlcOperation(format!("json serialize JWT header: {e}")))?,
    );
    let payload_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&payload)
            .map_err(|e| CryptoError::PlcOperation(format!("json serialize JWT payload: {e}")))?,
    );
    let signing_input = format!("{header_b64}.{payload_b64}");

    let sig_bytes = sign(signing_input.as_bytes())?;
    if sig_bytes.len() != 64 {
        return Err(CryptoError::PlcOperation(format!(
            "signing callback returned {} bytes, expected 64",
            sig_bytes.len()
        )));
    }
    ensure_low_s_callback_signature(&sig_bytes)?;

    let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_bytes);
    Ok(format!("{signing_input}.{sig_b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_p256_keypair;
    use crate::plc::verify_p256_signature;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};

    fn sign_with(scalar: &[u8; 32]) -> impl FnOnce(&[u8]) -> Result<Vec<u8>, CryptoError> + '_ {
        move |data: &[u8]| {
            let sk = SigningKey::from_bytes(scalar.as_slice().into())
                .map_err(|e| CryptoError::PlcOperation(e.to_string()))?;
            let sig: Signature = sk.sign(data);
            let sig = sig.normalize_s().unwrap_or(sig);
            Ok(sig.to_bytes().to_vec())
        }
    }

    fn decode_json(b64: &str) -> serde_json::Value {
        let bytes = URL_SAFE_NO_PAD
            .decode(b64)
            .expect("valid base64url segment");
        serde_json::from_slice(&bytes).expect("segment is JSON")
    }

    #[test]
    fn mints_the_expected_claims_and_header() {
        let kp = generate_p256_keypair().unwrap();
        let jwt = mint_service_auth_jwt(
            sign_with(&kp.private_key_bytes),
            "did:plc:alice123",
            "did:web:dest.example.com",
            Some("com.atproto.server.createAccount"),
            1_700_000_000,
            1_700_003_600,
        )
        .unwrap();

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header = decode_json(parts[0]);
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["alg"], "ES256");

        let payload = decode_json(parts[1]);
        assert_eq!(payload["iss"], "did:plc:alice123");
        assert_eq!(payload["aud"], "did:web:dest.example.com");
        assert_eq!(payload["lxm"], "com.atproto.server.createAccount");
        assert_eq!(payload["iat"], 1_700_000_000u64);
        assert_eq!(payload["exp"], 1_700_003_600u64);
    }

    #[test]
    fn omits_lxm_when_not_requested() {
        let kp = generate_p256_keypair().unwrap();
        let jwt = mint_service_auth_jwt(
            sign_with(&kp.private_key_bytes),
            "did:plc:alice123",
            "did:web:dest.example.com",
            None,
            10,
            70,
        )
        .unwrap();
        let payload = decode_json(jwt.split('.').nth(1).unwrap());
        assert!(payload.get("lxm").is_none());
    }

    #[test]
    fn signature_verifies_against_the_signing_did_key() {
        let kp = generate_p256_keypair().unwrap();
        let jwt = mint_service_auth_jwt(
            sign_with(&kp.private_key_bytes),
            "did:plc:alice123",
            "did:web:dest.example.com",
            Some("com.atproto.server.createAccount"),
            1_700_000_000,
            1_700_003_600,
        )
        .unwrap();

        let (signing_input, sig_b64) = jwt.rsplit_once('.').unwrap();
        let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).unwrap();
        let sig: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
        verify_p256_signature(&kp.key_id, signing_input.as_bytes(), &sig)
            .expect("JWT signature verifies as ES256 against the signer's did:key");
    }

    #[test]
    fn rejects_a_wrong_length_callback_signature() {
        let result = mint_service_auth_jwt(
            |_data: &[u8]| Ok(vec![0u8; 63]),
            "did:plc:alice123",
            "did:web:dest.example.com",
            None,
            10,
            70,
        );
        assert!(matches!(result, Err(CryptoError::PlcOperation(_))));
    }

    #[test]
    fn propagates_a_callback_error() {
        let result = mint_service_auth_jwt(
            |_data: &[u8]| Err(CryptoError::PlcOperation("signer unavailable".into())),
            "did:plc:alice123",
            "did:web:dest.example.com",
            None,
            10,
            70,
        );
        assert!(matches!(result, Err(CryptoError::PlcOperation(_))));
    }
}
