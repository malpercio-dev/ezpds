// crypto: signing, Shamir secret sharing, DID operations.

pub mod error;
pub mod keys;
pub mod plc;
pub mod shamir;

pub use error::CryptoError;
pub use keys::{
    decrypt_private_key, encrypt_private_key, generate_p256_keypair, DidKeyUri, P256Keypair,
};
pub use plc::{
    build_did_plc_genesis_op, build_did_plc_genesis_op_with_external_signer,
    build_did_plc_rotation_op, compute_cid, did_key_curve, diff_audit_logs, parse_audit_log,
    verify_did_key_signature, verify_genesis_op, verify_p256_signature, verify_plc_operation,
    AuditEntry, DidKeyCurve, PlcGenesisOp, PlcService, SignedPlcOperation, VerifiedGenesisOp,
    VerifiedPlcOp,
};
pub use shamir::{combine_shares, split_secret, ShamirShare};
