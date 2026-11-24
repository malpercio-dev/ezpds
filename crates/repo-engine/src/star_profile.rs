// repo-engine: the two atproto STAR profiles, `atproto-space-repo` and
// `atproto-space-meta`.
//
// STAR allows any key order; these profiles do not. A space repo archive carries
// record paths in strict bytewise order. A space meta archive carries three sections
// in a fixed order (`policy`, then policy state, then `writer/{did}` entries), each
// in strict bytewise order on its own. Both cap frames at 64 KiB metadata, 4 KiB key,
// 1 MiB value. This layer checks the `$type`, the limits, and the order; what the
// metadata fields and values mean belongs to the code serving `getRepo` and the meta
// archive.

use std::io::Read;

use serde::Serialize;

use crate::star::{
    encode_meta, star_header, star_pair_frame, StarError, StarLimits, StarMeta, StarPair,
    StarReader, STAR_CONTROL_END,
};

pub const SPACE_REPO_STAR_TYPE: &str = "atproto-space-repo";
pub const SPACE_META_STAR_TYPE: &str = "atproto-space-meta";

/// The limits both profiles read and write under.
pub const SPACE_STAR_LIMITS: StarLimits = StarLimits {
    max_meta: 64 * 1024,
    max_key: 4 * 1024,
    max_value: 1024 * 1024,
};

const META_POLICY_KEY: &[u8] = b"policy";
const META_WRITER_PREFIX: &[u8] = b"writer/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StarProfile {
    SpaceRepo,
    SpaceMeta,
}

impl StarProfile {
    pub fn star_type(self) -> &'static str {
        match self {
            StarProfile::SpaceRepo => SPACE_REPO_STAR_TYPE,
            StarProfile::SpaceMeta => SPACE_META_STAR_TYPE,
        }
    }

    // The section a key falls in; keys order within a section, sections in order.
    fn section(self, key: &[u8]) -> u8 {
        match self {
            StarProfile::SpaceRepo => 0,
            StarProfile::SpaceMeta if key == META_POLICY_KEY => 0,
            StarProfile::SpaceMeta if key.starts_with(META_WRITER_PREFIX) => 2,
            StarProfile::SpaceMeta => 1,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StarProfileError {
    #[error(transparent)]
    Star(#[from] StarError),
    #[error("archive $type is {found:?}, expected {expected:?}")]
    WrongType {
        expected: &'static str,
        found: String,
    },
    #[error("duplicate or out-of-order key: {0}")]
    KeyOrder(String),
}

/// Checks a profile's key order one key at a time, for readers and writers alike.
#[derive(Debug)]
pub struct KeyOrder {
    profile: StarProfile,
    section: u8,
    prev: Option<Vec<u8>>,
}

impl KeyOrder {
    pub fn new(profile: StarProfile) -> Self {
        Self {
            profile,
            section: 0,
            prev: None,
        }
    }

    pub fn check(&mut self, key: &[u8]) -> Result<(), StarProfileError> {
        let section = self.profile.section(key);
        if section != self.section {
            if section < self.section {
                return Err(out_of_order(key));
            }
            self.section = section;
            self.prev = None;
        }
        if self.prev.as_deref().is_some_and(|prev| key <= prev) {
            return Err(out_of_order(key));
        }
        self.prev = Some(key.to_vec());
        Ok(())
    }
}

fn out_of_order(key: &[u8]) -> StarProfileError {
    StarProfileError::KeyOrder(String::from_utf8_lossy(key).into_owned())
}

fn check_len(frame: &'static str, len: usize, limit: u64) -> Result<(), StarError> {
    let length = len as u64;
    if length > limit {
        return Err(StarError::TooLong {
            frame,
            length,
            limit,
        });
    }
    Ok(())
}

/// Reads one profile's archive: the STAR reader under the profile's limits, with the
/// `$type` checked up front and each key's order checked as it arrives.
pub struct SpaceStarReader<R> {
    inner: StarReader<R>,
    order: KeyOrder,
    failed: bool,
}

impl<R: Read> SpaceStarReader<R> {
    pub fn new(profile: StarProfile, reader: R) -> Result<Self, StarProfileError> {
        let inner = StarReader::new(reader, SPACE_STAR_LIMITS)?;
        if inner.star_type() != profile.star_type() {
            return Err(StarProfileError::WrongType {
                expected: profile.star_type(),
                found: inner.star_type().to_string(),
            });
        }
        Ok(Self {
            inner,
            order: KeyOrder::new(profile),
            failed: false,
        })
    }

    pub fn meta(&self) -> &StarMeta {
        self.inner.meta()
    }
}

impl<R: Read> Iterator for SpaceStarReader<R> {
    type Item = Result<StarPair, StarProfileError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let result = match self.inner.next()? {
            Ok(pair) => self.order.check(&pair.key).map(|()| pair),
            Err(e) => Err(e.into()),
        };
        self.failed = result.is_err();
        Some(result)
    }
}

/// Writes one profile's archive frame by frame, refusing anything its reader would
/// refuse: a wrong `$type`, a frame over the limits, a key out of order.
pub struct SpaceStarWriter {
    order: KeyOrder,
}

impl SpaceStarWriter {
    /// Returns the writer and the archive's header bytes.
    pub fn new<T: Serialize>(
        profile: StarProfile,
        meta: &T,
    ) -> Result<(Self, Vec<u8>), StarProfileError> {
        let (bytes, parsed) = encode_meta(meta)?;
        let found = match parsed.get("$type") {
            Some(ipld_core::ipld::Ipld::String(t)) => t.as_str(),
            _ => "",
        };
        if found != profile.star_type() {
            return Err(StarProfileError::WrongType {
                expected: profile.star_type(),
                found: found.to_string(),
            });
        }
        check_len("metadata", bytes.len(), SPACE_STAR_LIMITS.max_meta)?;
        let writer = Self {
            order: KeyOrder::new(profile),
        };
        Ok((writer, star_header(&bytes)))
    }

    pub fn pair(&mut self, key: &[u8], value: &[u8]) -> Result<Vec<u8>, StarProfileError> {
        check_len("key", key.len(), SPACE_STAR_LIMITS.max_key)?;
        check_len("value", value.len(), SPACE_STAR_LIMITS.max_value)?;
        self.order.check(key)?;
        Ok(star_pair_frame(key, value))
    }

    /// The archive's final byte.
    pub fn end(self) -> u8 {
        STAR_CONTROL_END
    }
}

/// A whole profile archive in memory.
pub fn write_space_star<T: Serialize>(
    profile: StarProfile,
    meta: &T,
    pairs: &[StarPair],
) -> Result<Vec<u8>, StarProfileError> {
    let (mut writer, mut out) = SpaceStarWriter::new(profile, meta)?;
    for pair in pairs {
        out.extend(writer.pair(&pair.key, &pair.value)?);
    }
    out.push(writer.end());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::star::write_star;
    use ipld_core::ipld::Ipld;
    use std::collections::BTreeMap;

    fn meta(star_type: &str) -> BTreeMap<String, Ipld> {
        BTreeMap::from([
            ("$type".to_string(), Ipld::String(star_type.into())),
            ("ver".to_string(), Ipld::Integer(1)),
        ])
    }

    fn pair(key: &str, value: &[u8]) -> StarPair {
        StarPair {
            key: key.as_bytes().to_vec(),
            value: value.to_vec(),
        }
    }

    fn read(profile: StarProfile, star: &[u8]) -> Result<Vec<StarPair>, StarProfileError> {
        SpaceStarReader::new(profile, star)?.collect()
    }

    #[test]
    fn repo_profile_round_trips() {
        let pairs = vec![
            pair("app.bsky.feed.post/3k2a", b"\xa0"),
            pair("app.bsky.feed.post/3k2b", b"\xa0"),
            pair("app.bsky.graph.follow/3k2a", b"\xa1\x61a\x01"),
        ];
        let profile = StarProfile::SpaceRepo;
        let star = write_space_star(profile, &meta(SPACE_REPO_STAR_TYPE), &pairs).unwrap();
        let reader = SpaceStarReader::new(profile, &star[..]).unwrap();
        assert_eq!(reader.meta(), &meta(SPACE_REPO_STAR_TYPE));
        assert_eq!(reader.collect::<Result<Vec<_>, _>>().unwrap(), pairs);
    }

    #[test]
    fn meta_profile_round_trips_sections_in_order() {
        // Policy state sorts before `policy` bytewise; sections order it after.
        let pairs = vec![
            pair("policy", b"\xa0"),
            pair("app.example.member/a", b"\xa0"),
            pair("app.example.member/b", b"\xa0"),
            pair("writer/did:plc:aaa", b"\xa0"),
            pair("writer/did:plc:bbb", b"\xa0"),
        ];
        let profile = StarProfile::SpaceMeta;
        let star = write_space_star(profile, &meta(SPACE_META_STAR_TYPE), &pairs).unwrap();
        assert_eq!(read(profile, &star).unwrap(), pairs);
    }

    // Raw STAR (no profile checks) with the given keys, to feed the profile reader
    // archives its own writer refuses to produce.
    fn raw(star_type: &str, keys: &[&str]) -> Vec<u8> {
        let pairs: Vec<_> = keys.iter().map(|k| pair(k, b"\xa0")).collect();
        write_star(&meta(star_type), &pairs).unwrap()
    }

    #[test]
    fn repo_profile_rejects_unsorted_and_duplicate_keys() {
        let profile = StarProfile::SpaceRepo;
        for keys in [["a/2", "a/1"], ["a/1", "a/1"]] {
            assert!(matches!(
                read(profile, &raw(SPACE_REPO_STAR_TYPE, &keys)),
                Err(StarProfileError::KeyOrder(_))
            ));
            let pairs: Vec<_> = keys.iter().map(|k| pair(k, b"\xa0")).collect();
            assert!(matches!(
                write_space_star(profile, &meta(SPACE_REPO_STAR_TYPE), &pairs),
                Err(StarProfileError::KeyOrder(_))
            ));
        }
    }

    #[test]
    fn meta_profile_rejects_sections_out_of_order() {
        let profile = StarProfile::SpaceMeta;
        for keys in [
            &["app.example.member/a", "policy"][..],
            &["writer/did:plc:a", "app.example.member/a"],
            &["policy", "policy"],
            &["writer/did:plc:b", "writer/did:plc:a"],
        ] {
            assert!(
                matches!(
                    read(profile, &raw(SPACE_META_STAR_TYPE, keys)),
                    Err(StarProfileError::KeyOrder(_))
                ),
                "{keys:?}"
            );
        }
    }

    #[test]
    fn profiles_reject_the_other_type() {
        assert!(matches!(
            read(StarProfile::SpaceMeta, &raw(SPACE_REPO_STAR_TYPE, &[])),
            Err(StarProfileError::WrongType { .. })
        ));
        assert!(matches!(
            write_space_star(StarProfile::SpaceRepo, &meta(SPACE_META_STAR_TYPE), &[]),
            Err(StarProfileError::WrongType { .. })
        ));
    }

    #[test]
    fn profiles_enforce_frame_limits() {
        let key = "k".repeat(4 * 1024 + 1);
        let star = raw(SPACE_REPO_STAR_TYPE, &[&key]);
        assert!(matches!(
            read(StarProfile::SpaceRepo, &star),
            Err(StarProfileError::Star(StarError::TooLong {
                frame: "key",
                ..
            }))
        ));
        let value = vec![0u8; 1024 * 1024 + 1];
        assert!(matches!(
            write_space_star(
                StarProfile::SpaceRepo,
                &meta(SPACE_REPO_STAR_TYPE),
                &[StarPair {
                    key: b"a/1".to_vec(),
                    value
                }]
            ),
            Err(StarProfileError::Star(StarError::TooLong {
                frame: "value",
                ..
            }))
        ));
    }
}
