// pattern: Functional Core
//
// BIP-39-style mnemonic rendering for the human-custody recovery share (Share 3).
//
// The share envelope (see `shamir.rs`) is a fixed 42-byte blob that already carries its own
// version, set_id, index, and a 4-byte SHA-256 checksum. This module renders those raw bytes as a
// sequence of short English words so a person can write the share on paper and type it back later,
// and parses such a phrase back to the exact bytes.
//
// Encoding is deliberately one word per byte against a fixed 256-word list, rather than BIP-39's
// 11-bits-per-word packing. The envelope is not a whole number of 11-bit groups, so 11-bit packing
// would need a partial final word and padding-bit handling; a byte↔word map is unambiguous, has no
// padding edge cases, and keeps the wordlist a small, auditable asset. Integrity of the reproduced
// share is the envelope's own checksum, verified by `ShareEnvelope::from_bytes` — this module only
// concerns itself with the byte↔word bijection.

use zeroize::Zeroizing;

use crate::CryptoError;

/// A fixed list of exactly 256 distinct, lowercase English words — one per possible byte value.
///
/// Chosen to be short (3–6 letters) and easy to write/read. Byte `b` maps to `WORDLIST[b]`. The
/// list's length (256) and internal uniqueness are asserted by tests; the mapping is a permanent
/// contract (changing a word would invalidate every previously written human share), so entries
/// must never be reordered or replaced.
pub(crate) const WORDLIST: [&str; 256] = [
    "able", "acid", "aged", "army", "atom", "aunt", "axis", "baby", // 0x00
    "back", "bake", "bald", "ball", "band", "bank", "barn", "base", // 0x08
    "bath", "bead", "beam", "bean", "bear", "beat", "bell", "belt", // 0x10
    "bird", "bite", "blue", "boat", "body", "bold", "bone", "book", // 0x18
    "boot", "born", "boss", "both", "bowl", "cage", "cake", "calm", // 0x20
    "camp", "cane", "card", "care", "cart", "cash", "cave", "cell", // 0x28
    "chef", "chin", "city", "clay", "club", "coal", "coat", "code", // 0x30
    "coin", "cold", "colt", "cook", "cool", "cord", "corn", "cost", // 0x38
    "crab", "crew", "crop", "cube", "cure", "dark", "dawn", "deal", // 0x40
    "deer", "desk", "dime", "dirt", "dish", "dive", "dock", "doll", // 0x48
    "dome", "door", "dove", "drum", "duck", "dune", "dust", "duty", // 0x50
    "earn", "east", "easy", "edge", "envy", "epic", "even", "face", // 0x58
    "fact", "fade", "fair", "fall", "farm", "fast", "fate", "fawn", // 0x60
    "fear", "feed", "felt", "fern", "film", "fire", "fish", "five", // 0x68
    "flag", "flap", "flat", "flax", "fled", "flew", "flip", "flow", // 0x70
    "foam", "foil", "fold", "font", "food", "foot", "ford", "fork", // 0x78
    "form", "fort", "four", "frog", "fuel", "full", "fund", "fury", // 0x80
    "gain", "gala", "game", "gate", "gaze", "gear", "gems", "gift", // 0x88
    "girl", "give", "glad", "glow", "glue", "goal", "goat", "gold", // 0x90
    "golf", "gone", "good", "gown", "grab", "gray", "grew", "grid", // 0x98
    "grim", "grip", "grow", "gulf", "hail", "hair", "half", "hall", // 0xA0
    "hand", "hang", "harp", "hawk", "haze", "head", "heal", "heap", // 0xA8
    "heat", "herb", "herd", "hero", "hide", "hill", "hint", "hive", // 0xB0
    "hold", "hole", "holy", "home", "hood", "hoof", "hook", "hope", // 0xB8
    "horn", "host", "hour", "hunt", "hurl", "icon", "idea", "iris", // 0xC0
    "iron", "item", "jade", "jail", "jazz", "jean", "joke", "jolt", // 0xC8
    "july", "jump", "junk", "jury", "keel", "keen", "kelp", "kilt", // 0xD0
    "king", "kite", "knee", "knot", "lace", "lake", "lamb", "lamp", // 0xD8
    "land", "lane", "lark", "lava", "lawn", "lead", "leaf", "leak", // 0xE0
    "lean", "leap", "left", "lend", "lens", "lily", "lime", "line", // 0xE8
    "link", "lion", "list", "load", "loaf", "loan", "lock", "loft", // 0xF0
    "logo", "lone", "long", "look", "loop", "lord", "lose", "loud", // 0xF8
];

/// Render arbitrary bytes as a space-separated mnemonic phrase (one word per byte).
///
/// The phrase encodes secret share material, so it is returned in a [`Zeroizing`] buffer that
/// scrubs the heap allocation on drop.
pub(crate) fn bytes_to_words(bytes: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(
        bytes
            .iter()
            .map(|&b| WORDLIST[b as usize])
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// Parse a mnemonic phrase back to its bytes.
///
/// Whitespace between words is flexible and matching is case-insensitive. Returns
/// [`CryptoError::ShareFormat`] if any token is not a known word. The returned buffer is zeroized
/// on drop, since a decoded share carries secret material.
pub(crate) fn words_to_bytes(phrase: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let mut out = Zeroizing::new(Vec::new());
    for token in phrase.split_whitespace() {
        let lower = token.to_ascii_lowercase();
        let idx = WORDLIST
            .iter()
            .position(|&w| w == lower)
            .ok_or_else(|| CryptoError::ShareFormat(format!("unknown mnemonic word: {token:?}")))?;
        out.push(idx as u8);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// SHA-256 (hex) of each word followed by `\n`, in order. Regenerate only on a deliberate,
    /// coordinated wordlist change (which invalidates all prior human shares).
    const WORDLIST_GOLDEN_DIGEST: &str =
        "4749ec21e04de8b485afff6ab366e0285cc1544eb1216f1991793fbbf4f955fe";

    #[test]
    fn wordlist_has_256_entries() {
        assert_eq!(WORDLIST.len(), 256);
    }

    #[test]
    fn wordlist_entries_are_unique() {
        let mut seen: HashSet<&str> = HashSet::new();
        for (i, w) in WORDLIST.iter().enumerate() {
            assert!(seen.insert(w), "duplicate mnemonic word {w:?} at index {i}");
        }
    }

    /// Pins the exact ordered word→byte mapping. Length + uniqueness + lowercase checks alone would
    /// pass under a permutation or a single word swap, either of which silently changes the meaning
    /// of every human share ever written. A digest over the ordered list catches both.
    #[test]
    fn wordlist_matches_golden_digest() {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for w in WORDLIST {
            hasher.update(w.as_bytes());
            hasher.update(b"\n");
        }
        let hex: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hex, WORDLIST_GOLDEN_DIGEST,
            "the mnemonic word→byte mapping changed; this breaks every existing paper share"
        );
    }

    #[test]
    fn wordlist_entries_are_lowercase_ascii() {
        for (i, w) in WORDLIST.iter().enumerate() {
            assert!(!w.is_empty(), "word at {i} is empty");
            assert!(
                w.chars().all(|c| c.is_ascii_lowercase()),
                "word {w:?} at {i} must be lowercase ascii"
            );
        }
    }

    #[test]
    fn bytes_words_round_trip_all_values() {
        let all: Vec<u8> = (0..=255).collect();
        let phrase = bytes_to_words(&all);
        let decoded = words_to_bytes(&phrase).unwrap();
        assert_eq!(*decoded, all);
    }

    #[test]
    fn decode_is_case_insensitive_and_whitespace_tolerant() {
        let bytes = [0x00_u8, 0x2a, 0xff, 0x80];
        let phrase = bytes_to_words(&bytes);
        let messy = format!("  {}  ", phrase.to_uppercase().replace(' ', "\n  "));
        let decoded = words_to_bytes(&messy).unwrap();
        assert_eq!(*decoded, bytes);
    }

    #[test]
    fn unknown_word_is_rejected() {
        let result = words_to_bytes("able acid notarealword bank");
        assert!(matches!(result, Err(CryptoError::ShareFormat(_))));
    }
}
