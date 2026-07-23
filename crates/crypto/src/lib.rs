// crypto: signing, Shamir secret sharing, DID operations.

pub mod error;
pub mod keys;
mod mnemonic;
pub mod oauth_consent;
pub mod plc;
pub mod service_auth;
pub mod shamir;
pub mod sovereign_session;

pub use error::CryptoError;
pub use keys::{
    decrypt_private_key, decrypt_secret_bytes, derive_recovery_keypair, encrypt_private_key,
    encrypt_secret_bytes, generate_p256_keypair, DidKeyUri, P256Keypair,
};
pub use oauth_consent::{
    encode_oauth_consent_envelope, granted_scope_hash, OAUTH_CONSENT_APPROVE_PATH,
    OAUTH_CONSENT_DECISION_APPROVE, OAUTH_CONSENT_DECISION_DENY, OAUTH_CONSENT_DOMAIN,
    OAUTH_CONSENT_METHOD,
};
pub use plc::{
    build_did_plc_genesis_op, build_did_plc_genesis_op_multi_rotation,
    build_did_plc_genesis_op_multi_rotation_with_external_signer,
    build_did_plc_genesis_op_with_external_signer, build_did_plc_rotation_op,
    build_did_plc_tombstone_op, compute_cid, did_key_curve, diff_audit_logs, parse_audit_log,
    verify_did_key_signature, verify_genesis_op, verify_p256_signature, verify_plc_operation,
    verify_plc_tombstone_op, AuditEntry, DidKeyCurve, PlcGenesisOp, PlcService, SignedPlcOperation,
    VerifiedGenesisOp, VerifiedPlcOp, VerifiedTombstoneOp,
};
pub use service_auth::mint_service_auth_jwt;
pub use shamir::{
    combine_envelopes, combine_shares, split_secret, split_secret_into_envelopes, ShamirShare,
    ShareEnvelope, SHARE_ENVELOPE_LEN, SHARE_ENVELOPE_VERSION,
};
pub use sovereign_session::{
    encode_sovereign_session_envelope, SOVEREIGN_SESSION_DOMAIN, SOVEREIGN_SESSION_METHOD,
    SOVEREIGN_SESSION_PATH,
};
