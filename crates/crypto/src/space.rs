// Spaces (permissioned data) crypto primitives: the LtHash multiset hash that
// digests a permissioned repo's contents. Pinned to the reference golden
// vectors from the atproto `permissioned-data` branch (`packages/space/tests/`).
// A space commit is not signed: the repo host authenticates it to a syncer with
// a MAC (`crate::http_signature`).

use sha2::{Digest, Sha256};

use crate::error::CryptoError;

const LANES: usize = 1024;
/// Size of a persisted [`LtHash`] state: 1024 little-endian u16 lanes.
pub const LTHASH_STATE_BYTES: usize = LANES * 2;

/// Commit format version: a space commit's `ver`.
pub const SPACE_COMMIT_VERSION: u8 = 1;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
