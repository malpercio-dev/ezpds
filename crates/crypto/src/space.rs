// Spaces (permissioned data) crypto primitives: the LtHash multiset hash that
// digests a permissioned repo's contents, and the deniable commit signature
// over it. Pinned to the reference golden vectors from the atproto
// `permissioned-data` branch (`packages/space/tests/`).

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::error::CryptoError;
use crate::keys::DidKeyUri;
use crate::plc::verify_did_key_signature;

const LANES: usize = 1024;
/// Size of a persisted [`LtHash`] state: 1024 little-endian u16 lanes.
pub const LTHASH_STATE_BYTES: usize = LANES * 2;

/// Commit format version carried in [`SignedSpaceCommit::ver`].
pub const SPACE_COMMIT_VERSION: u8 = 1;

const CTX_DOMAIN: &[u8; 16] = b"atproto-space-v1";

/// A homomorphic multiset hash over repo elements.
///
/// Each element expands to 1024 u16 lanes (BLAKE3 XOF, dkLen = 2048) which are
/// summed into the state mod 2^16. Addition and subtraction commute, so the
/// state depends only on the current multiset, not on insertion order — a repo
/// host updates it incrementally per record write instead of rehashing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LtHash {
    lanes: [u16; LANES],
}

impl Default for LtHash {
    fn default() -> Self {
        Self::new()
    }
}

impl LtHash {
    /// The empty multiset: all-zero state.
    pub fn new() -> Self {
        Self { lanes: [0; LANES] }
    }

    /// Resume from a persisted [`state`](Self::state).
    pub fn from_state(state: &[u8]) -> Result<Self, CryptoError> {
        if state.len() != LTHASH_STATE_BYTES {
            return Err(CryptoError::Space(format!(
                "LtHash state must be {LTHASH_STATE_BYTES} bytes, got {}",
                state.len()
            )));
        }
        let mut lanes = [0u16; LANES];
        for (lane, chunk) in lanes.iter_mut().zip(state.chunks_exact(2)) {
            *lane = u16::from_le_bytes([chunk[0], chunk[1]]);
        }
        Ok(Self { lanes })
    }

    pub fn add(&mut self, element: &str) {
        let expanded = expand(element);
        for (lane, e) in self.lanes.iter_mut().zip(expanded) {
            *lane = lane.wrapping_add(e);
        }
    }

    pub fn remove(&mut self, element: &str) {
        let expanded = expand(element);
        for (lane, e) in self.lanes.iter_mut().zip(expanded) {
            *lane = lane.wrapping_sub(e);
        }
    }

    /// The full 2048-byte state, for persistence.
    pub fn state(&self) -> [u8; LTHASH_STATE_BYTES] {
        let mut out = [0u8; LTHASH_STATE_BYTES];
        for (chunk, lane) in out.chunks_exact_mut(2).zip(self.lanes) {
            chunk.copy_from_slice(&lane.to_le_bytes());
        }
        out
    }

    /// The 32-byte commit digest: sha256 of the state.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.state()).into()
    }

    pub fn is_empty(&self) -> bool {
        self.lanes.iter().all(|&lane| lane == 0)
    }
}

// Expand an element to 1024 u16 lanes with BLAKE3 in XOF mode.
fn expand(element: &str) -> [u16; LANES] {
    let mut bytes = [0u8; LTHASH_STATE_BYTES];
    blake3::Hasher::new()
        .update(element.as_bytes())
        .finalize_xof()
        .fill(&mut bytes);
    let mut lanes = [0u16; LANES];
    for (lane, chunk) in lanes.iter_mut().zip(bytes.chunks_exact(2)) {
        *lane = u16::from_le_bytes([chunk[0], chunk[1]]);
    }
    lanes
}

/// The multiset element for one record: a bare `collection/rkey/cid` concat.
///
/// What keeps the encoding injective is *not* length prefixing — it is the
/// outer two fields being slash-free (a collection is an NSID, a cid is
/// base32), so the first slash always ends the collection and the last always
/// begins the cid. The invariant is inherited from lexicon validation of the
/// `nsid` and `record-key` formats; this function does not enforce it.
pub fn format_set_hash_element(collection: &str, rkey: &str, cid: &str) -> String {
    format!("{collection}/{rkey}/{cid}")
}

/// The identity a deniable commit binds: which repo, whose, at what revision.
#[derive(Debug, Clone, Copy)]
pub struct SpaceCommitCtx<'a> {
    /// Space URI (`at://…`).
    pub space: &'a str,
    /// Author DID.
    pub author: &'a str,
    /// Revision TID.
    pub rev: &'a str,
}

/// A deniable commit over a repo digest.
///
/// `sig` covers only the ctx (space, author, rev, `ikm`) — never `hash` — so a
/// leaked commit proves nothing about content: anyone holding `ikm` can forge
/// a matching `mac` for any hash. A fresh `ikm`/`sig`/`mac` triple is produced
/// per serving.
#[derive(Debug, Clone)]
pub struct SignedSpaceCommit {
    pub ver: u8,
    /// [`LtHash::digest`] of the repo contents.
    pub hash: [u8; 32],
    /// Fresh random PRK for the MAC key derivation.
    pub ikm: [u8; 32],
    /// Raw 64-byte low-S ECDSA signature over the encoded ctx.
    pub sig: [u8; 64],
    /// `HMAC-SHA256(HKDF-Expand(ikm, ctx, 32), hash)`.
    pub mac: [u8; 32],
    /// Copy of the ctx rev, so a commit is self-describing.
    pub rev: String,
}

/// TLS-vector ctx encoding:
/// `"atproto-space-v1" || u16be-len-prefixed(space, author, rev, ikm)`.
pub fn encode_space_commit_ctx(
    ctx: &SpaceCommitCtx<'_>,
    ikm: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let fields: [&[u8]; 4] = [
        ctx.space.as_bytes(),
        ctx.author.as_bytes(),
        ctx.rev.as_bytes(),
        ikm,
    ];
    let mut out =
        Vec::with_capacity(CTX_DOMAIN.len() + fields.iter().map(|f| 2 + f.len()).sum::<usize>());
    out.extend_from_slice(CTX_DOMAIN);
    for field in fields {
        let len = u16::try_from(field.len()).map_err(|_| {
            CryptoError::Space("commit ctx field exceeds u16 length prefix".to_string())
        })?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field);
    }
    Ok(out)
}

// RFC 5869 §2.3 expand only — `ikm` is the PRK, ctx the info.
fn commit_mac(ikm: &[u8; 32], ctx_bytes: &[u8], hash: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::from_prk(ikm).expect("32-byte PRK is a valid HKDF-SHA256 PRK");
    let mut okm = [0u8; 32];
    hk.expand(ctx_bytes, &mut okm)
        .expect("32 bytes is within HKDF-SHA256 output bounds");
    let mut mac = Hmac::<Sha256>::new_from_slice(&okm).expect("HMAC-SHA256 accepts any key length");
    mac.update(hash);
    mac.finalize().into_bytes().into()
}

/// Sign a deniable commit over `hash` with the author's P-256 signing key,
/// drawing a fresh `ikm`.
pub fn sign_space_commit(
    ctx: &SpaceCommitCtx<'_>,
    hash: [u8; 32],
    signing_private_key: &[u8; 32],
) -> Result<SignedSpaceCommit, CryptoError> {
    let sk = SigningKey::from_bytes(&(*signing_private_key).into())
        .map_err(|e| CryptoError::Space(format!("invalid signing key: {e}")))?;
    let mut ikm = [0u8; 32];
    OsRng.fill_bytes(&mut ikm);
    let ctx_bytes = encode_space_commit_ctx(ctx, &ikm)?;
    let sig: Signature = Signer::sign(&sk, &ctx_bytes);
    let sig = sig.normalize_s().unwrap_or(sig);
    Ok(SignedSpaceCommit {
        ver: SPACE_COMMIT_VERSION,
        hash,
        mac: commit_mac(&ikm, &ctx_bytes, &hash),
        ikm,
        sig: sig.to_bytes().into(),
        rev: ctx.rev.to_string(),
    })
}

/// Verify a commit's MAC (integrity) and signature (authenticity). Once this
/// passes, `hash` is trusted as the author's claim about their repo.
///
/// Accepts both signing curves (P-256 and secp256k1) via the author's
/// `did:key`, since foreign authors may sign ES256K.
pub fn verify_space_commit(
    commit: &SignedSpaceCommit,
    ctx: &SpaceCommitCtx<'_>,
    author_key: &DidKeyUri,
) -> Result<(), CryptoError> {
    if commit.ver != SPACE_COMMIT_VERSION {
        return Err(CryptoError::Space(format!(
            "unsupported commit version: {}",
            commit.ver
        )));
    }
    if commit.rev != ctx.rev {
        return Err(CryptoError::Space(
            "commit rev disagrees with ctx rev".to_string(),
        ));
    }
    let ctx_bytes = encode_space_commit_ctx(ctx, &commit.ikm)?;
    let expected = commit_mac(&commit.ikm, &ctx_bytes, &commit.hash);
    // Constant-time compare via HMAC re-verification is unnecessary here: the
    // MAC key derives from `ikm`, which the verifier already holds, so there is
    // no secret to leak through timing.
    if expected != commit.mac {
        return Err(CryptoError::Space("commit mac mismatch".to_string()));
    }
    verify_did_key_signature(author_key, &ctx_bytes, &commit.sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_p256_keypair;

    // cids of `{ text: 'hello' }` and `{ text: 'world' }`, from the reference suite.
    const CID_A: &str = "bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244";
    const CID_B: &str = "bafyreidpw4cbv6gr4ukh33z23pvvrpr3wi4gnpmi4doamlsl3sa4rgri2a";

    // ── LtHash ──────────────────────────────────────────────────────────────

    #[test]
    fn starts_as_zero_state() {
        let h = LtHash::new();
        assert_eq!(h.state(), [0u8; LTHASH_STATE_BYTES]);
        assert!(h.is_empty());
    }

    #[test]
    fn add_then_remove_returns_to_zero() {
        let mut h = LtHash::new();
        h.add("a");
        assert!(!h.is_empty());
        h.remove("a");
        assert!(h.is_empty());
    }

    #[test]
    fn order_independent() {
        let mut a = LtHash::new();
        a.add("a");
        a.add("b");
        let mut b = LtHash::new();
        b.add("b");
        b.add("a");
        assert_eq!(a, b);
        assert_eq!(a.digest(), b.digest());
    }

    #[test]
    fn order_independent_over_random_elements() {
        // Property check without a proptest dep: many random elements, two
        // insertion orders, one interleaved removal.
        let mut elements: Vec<String> = (0..64).map(|i| format!("element-{i}")).collect();
        let mut forward = LtHash::new();
        for e in &elements {
            forward.add(e);
        }
        elements.reverse();
        let mut backward = LtHash::new();
        for e in &elements {
            backward.add(e);
        }
        assert_eq!(forward, backward);
        for e in &elements {
            backward.remove(e);
        }
        assert!(backward.is_empty());
    }

    #[test]
    fn distinguishes_elements() {
        let mut a = LtHash::new();
        a.add("a");
        let mut b = LtHash::new();
        b.add("b");
        assert_ne!(a, b);
    }

    #[test]
    fn multiset_double_add_does_not_cancel() {
        let mut h = LtHash::new();
        h.add("a");
        h.add("a");
        assert!(!h.is_empty());
        h.remove("a");
        let mut single = LtHash::new();
        single.add("a");
        assert_eq!(h, single);
    }

    #[test]
    fn state_round_trips() {
        let mut a = LtHash::new();
        a.add("a");
        a.add("b");
        assert_eq!(LtHash::from_state(&a.state()).unwrap(), a);
    }

    #[test]
    fn rejects_wrong_length_state() {
        let err = LtHash::from_state(&[0u8; 32]).unwrap_err();
        assert!(err.to_string().contains("must be 2048 bytes"), "{err}");
    }

    #[test]
    fn golden_empty_digest() {
        // Reference vector: sha256 of the zero state.
        assert_eq!(
            crate::hex::to_hex(&LtHash::new().digest()),
            "e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad"
        );
    }

    #[test]
    fn golden_one_two_digest() {
        // Reference snapshot vector locking the algorithm: BLAKE3 XOF at
        // dkLen=2048, 1024 u16-LE lanes summed mod 2^16. If this changes,
        // persisted state must be recomputed.
        let mut h = LtHash::new();
        h.add("one");
        h.add("two");
        assert_eq!(
            crate::hex::to_hex(&h.digest()),
            "ae05cb6d224379d9710c290c8529945c5b0e0fde9ead30b9699057ce701c63e7"
        );
    }

    // ── Set hash element ────────────────────────────────────────────────────

    #[test]
    fn element_separates_fields() {
        assert_eq!(
            format_set_hash_element("c.a", "1", CID_A),
            format!("c.a/1/{CID_A}")
        );
    }

    #[test]
    fn element_distinguishes_paths_and_cids() {
        let mut same_cid_a = LtHash::new();
        same_cid_a.add(&format_set_hash_element("c.a", "1", CID_A));
        let mut same_cid_b = LtHash::new();
        same_cid_b.add(&format_set_hash_element("c.a", "2", CID_A));
        assert_ne!(same_cid_a, same_cid_b);

        let mut other_cid = LtHash::new();
        other_cid.add(&format_set_hash_element("c.a", "1", CID_B));
        assert_ne!(same_cid_a, other_cid);
    }

    // ── Ctx encoding ────────────────────────────────────────────────────────

    fn test_ctx() -> SpaceCommitCtx<'static> {
        SpaceCommitCtx {
            space: "at://did:example:space/space/app.bsky.group/test",
            author: "did:example:alice",
            rev: "3kbcq3p7ad400",
        }
    }

    #[test]
    fn ctx_is_length_prefixed_and_domain_separated() {
        let ctx = test_ctx();
        let encoded = encode_space_commit_ctx(&ctx, &[7u8; 32]).unwrap();
        assert_eq!(&encoded[..16], b"atproto-space-v1");
        let space_len = usize::from(encoded[16]) << 8 | usize::from(encoded[17]);
        assert_eq!(space_len, ctx.space.len());
    }

    #[test]
    fn ctx_is_unambiguous_across_field_boundaries() {
        // Without length prefixes these two would encode identically.
        let ikm = [7u8; 32];
        let a = encode_space_commit_ctx(
            &SpaceCommitCtx {
                space: "ab",
                author: "c",
                rev: "d",
            },
            &ikm,
        )
        .unwrap();
        let b = encode_space_commit_ctx(
            &SpaceCommitCtx {
                space: "a",
                author: "bc",
                rev: "d",
            },
            &ikm,
        )
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn ctx_is_deterministic() {
        let ikm = [7u8; 32];
        assert_eq!(
            encode_space_commit_ctx(&test_ctx(), &ikm).unwrap(),
            encode_space_commit_ctx(&test_ctx(), &ikm).unwrap()
        );
    }

    #[test]
    fn ctx_rejects_oversized_field() {
        let long = "x".repeat(0x10000);
        let ctx = SpaceCommitCtx {
            space: &long,
            author: "a",
            rev: "r",
        };
        assert!(encode_space_commit_ctx(&ctx, &[0u8; 32]).is_err());
    }

    // ── Sign / verify ───────────────────────────────────────────────────────

    fn test_repo_hash() -> [u8; 32] {
        let mut h = LtHash::new();
        h.add(&format_set_hash_element("app.bsky.feed.post", "1", CID_A));
        h.digest()
    }

    #[test]
    fn produces_a_well_formed_commit() {
        let kp = generate_p256_keypair().unwrap();
        let commit =
            sign_space_commit(&test_ctx(), test_repo_hash(), &kp.private_key_bytes).unwrap();
        assert_eq!(commit.ver, SPACE_COMMIT_VERSION);
        assert_eq!(commit.rev, test_ctx().rev);
        assert_eq!(commit.hash, test_repo_hash());
    }

    #[test]
    fn verifies_own_commit() {
        let kp = generate_p256_keypair().unwrap();
        let commit =
            sign_space_commit(&test_ctx(), test_repo_hash(), &kp.private_key_bytes).unwrap();
        verify_space_commit(&commit, &test_ctx(), &kp.key_id).unwrap();
    }

    #[test]
    fn fresh_ikm_per_commit_for_deniability() {
        let kp = generate_p256_keypair().unwrap();
        let a = sign_space_commit(&test_ctx(), test_repo_hash(), &kp.private_key_bytes).unwrap();
        let b = sign_space_commit(&test_ctx(), test_repo_hash(), &kp.private_key_bytes).unwrap();
        assert_ne!(a.ikm, b.ikm);
        assert_ne!(a.mac, b.mac);
        assert_ne!(a.sig, b.sig);
        assert_eq!(a.hash, b.hash);
    }

    #[test]
    fn rejects_signature_from_a_different_key() {
        let kp = generate_p256_keypair().unwrap();
        let other = generate_p256_keypair().unwrap();
        let commit =
            sign_space_commit(&test_ctx(), test_repo_hash(), &kp.private_key_bytes).unwrap();
        assert!(verify_space_commit(&commit, &test_ctx(), &other.key_id).is_err());
    }

    #[test]
    fn does_not_verify_under_a_different_ctx() {
        let kp = generate_p256_keypair().unwrap();
        let commit =
            sign_space_commit(&test_ctx(), test_repo_hash(), &kp.private_key_bytes).unwrap();
        let base = test_ctx();
        let variants = [
            SpaceCommitCtx {
                space: "at://did:example:space/space/app.bsky.group/other",
                ..base
            },
            SpaceCommitCtx {
                author: "did:example:bob",
                ..base
            },
            SpaceCommitCtx {
                rev: "3kbcq3p7ad999",
                ..base
            },
        ];
        for other_ctx in variants {
            assert!(verify_space_commit(&commit, &other_ctx, &kp.key_id).is_err());
        }
    }

    #[test]
    fn does_not_verify_a_tampered_hash() {
        let kp = generate_p256_keypair().unwrap();
        let mut commit =
            sign_space_commit(&test_ctx(), test_repo_hash(), &kp.private_key_bytes).unwrap();
        // The signature never covered the hash — the MAC is what catches this,
        // and what a leaked commit can't prove.
        commit.hash = LtHash::new().digest();
        assert!(verify_space_commit(&commit, &test_ctx(), &kp.key_id).is_err());
    }

    #[test]
    fn rejects_rev_disagreeing_with_ctx() {
        let kp = generate_p256_keypair().unwrap();
        let mut commit =
            sign_space_commit(&test_ctx(), test_repo_hash(), &kp.private_key_bytes).unwrap();
        commit.rev = "3kbcq3p7ad999".to_string();
        assert!(verify_space_commit(&commit, &test_ctx(), &kp.key_id).is_err());
    }

    #[test]
    fn rejects_unknown_commit_version() {
        let kp = generate_p256_keypair().unwrap();
        let mut commit =
            sign_space_commit(&test_ctx(), test_repo_hash(), &kp.private_key_bytes).unwrap();
        commit.ver = 2;
        assert!(verify_space_commit(&commit, &test_ctx(), &kp.key_id).is_err());
    }
}
