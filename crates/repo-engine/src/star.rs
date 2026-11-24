// repo-engine: the STAR archive format (https://dasl.ing/star.html).
//
// ```text
// [ magic | len | meta ] [ 1 | len | key | len | val ] ... [ 0 ]
// ```
//
// `meta` is a canonical DRISL map carrying a string `$type` that names the archive's
// profile. Each `len` is an unsigned varint in its shortest form. STAR itself sets no
// size limits and no key order: duplicate and unsorted keys are valid, and limits are
// the reader's choice (`StarLimits`). Profiles that need more live in `star_profile`.
//
// The reference implementation is `@atproto/star`; its interop fixtures are the
// conformance gate in `tests/star_interop.rs`.

use std::collections::BTreeMap;
use std::io::Read;

use ipld_core::ipld::Ipld;
use serde::Serialize;

/// The four bytes every STAR archive opens with.
pub const STAR_MAGIC: [u8; 4] = [0x2a, 0x6c, 0x01, 0x00];
/// The control byte before each key/value pair.
pub const STAR_CONTROL_PAIR: u8 = 0x01;
/// The control byte that ends an archive.
pub const STAR_CONTROL_END: u8 = 0x00;

// 9 bytes carry 63 bits, more than any length a reader will accept.
const MAX_VARINT_BYTES: usize = 9;

const SHA2_256: u64 = 0x12;
const RAW_CODEC: u64 = 0x55;
const DAG_CBOR_CODEC: u64 = 0x71;

/// A STAR archive's metadata: a DRISL map with a string `$type`.
pub type StarMeta = BTreeMap<String, Ipld>;

/// One key/value entry. STAR keys are bytes; profiles decide what they mean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarPair {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// Per-frame length limits, checked before a frame is read so an oversized frame is
/// never buffered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StarLimits {
    pub max_meta: u64,
    pub max_key: u64,
    pub max_value: u64,
}

impl StarLimits {
    /// No limits, as STAR itself sets. Only for trusted input.
    pub const UNLIMITED: StarLimits = StarLimits {
        max_meta: u64::MAX,
        max_key: u64::MAX,
        max_value: u64::MAX,
    };
}

#[derive(Debug, thiserror::Error)]
pub enum StarError {
    #[error("invalid magic bytes")]
    Magic,
    #[error("unexpected end of archive")]
    Truncated,
    #[error("non-canonical varint")]
    NonCanonicalVarint,
    #[error("varint too long")]
    VarintTooLong,
    #[error("{frame} length {length} exceeds limit of {limit}")]
    TooLong {
        frame: &'static str,
        length: u64,
        limit: u64,
    },
    #[error("invalid control byte: {0:#04x}")]
    Control(u8),
    #[error("unexpected bytes after end of archive")]
    Trailing,
    #[error("invalid metadata: {0}")]
    Meta(String),
    #[error("metadata must be a map with a string $type")]
    MetaType,
    #[error("metadata is not canonical DRISL")]
    NonCanonicalMeta,
    #[error("read error: {0}")]
    Io(#[from] std::io::Error),
}

/// Unsigned LEB128 in its shortest form.
pub fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Decode a varint, rejecting any encoding longer than the shortest one.
///
/// Not shared with the CAR decoders in `car_import` or `obsign-core`: CAR tolerates
/// non-minimal varints and STAR forbids them.
fn read_varint<R: Read>(reader: &mut R) -> Result<u64, StarError> {
    let mut value = 0u64;
    for i in 0..MAX_VARINT_BYTES {
        let byte = read_byte(reader)?.ok_or(StarError::Truncated)?;
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte < 0x80 {
            // A final zero group only pads the encoding.
            if byte == 0 && i > 0 {
                return Err(StarError::NonCanonicalVarint);
            }
            return Ok(value);
        }
    }
    Err(StarError::VarintTooLong)
}

/// One byte, or `None` at a clean end of input.
fn read_byte<R: Read>(reader: &mut R) -> Result<Option<u8>, StarError> {
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return Ok(None),
            Ok(_) => return Ok(Some(byte[0])),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(StarError::Io(e)),
        }
    }
}

fn read_frame<R: Read>(
    reader: &mut R,
    frame: &'static str,
    limit: u64,
) -> Result<Vec<u8>, StarError> {
    let length = read_varint(reader)?;
    if length > limit {
        return Err(StarError::TooLong {
            frame,
            length,
            limit,
        });
    }
    // `take` grows the buffer as bytes arrive, so a large claimed length on a short
    // input costs nothing.
    let mut bytes = Vec::new();
    reader.take(length).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != length {
        return Err(StarError::Truncated);
    }
    Ok(bytes)
}

fn push_frame(bytes: &[u8], out: &mut Vec<u8>) {
    encode_varint(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

/// Parse metadata bytes strictly: decode, require a map with a string `$type`,
/// require that it re-encodes to the same bytes, and reject what DRISL forbids but
/// survives a re-encode (negative zero, non-finite floats, non-DASL CIDs).
///
/// The re-encode is what makes the workspace's lenient `serde_ipld_dagcbor` decoder
/// strict: it catches unsorted and duplicate keys, non-minimal integers and lengths,
/// and narrow floats.
pub fn parse_meta(bytes: &[u8]) -> Result<StarMeta, StarError> {
    let meta: Ipld =
        serde_ipld_dagcbor::from_slice(bytes).map_err(|e| StarError::Meta(e.to_string()))?;
    let Ipld::Map(map) = meta else {
        return Err(StarError::MetaType);
    };
    if !matches!(map.get("$type"), Some(Ipld::String(_))) {
        return Err(StarError::MetaType);
    }
    let reencoded = serde_ipld_dagcbor::to_vec(&map).map_err(|e| StarError::Meta(e.to_string()))?;
    if reencoded != bytes {
        return Err(StarError::NonCanonicalMeta);
    }
    map.values().try_for_each(check_drisl)?;
    Ok(map)
}

fn check_drisl(value: &Ipld) -> Result<(), StarError> {
    match value {
        Ipld::Float(f) if !f.is_finite() || (*f == 0.0 && f.is_sign_negative()) => {
            Err(StarError::Meta(format!("float {f} is not DRISL")))
        }
        Ipld::Link(cid) => {
            let dasl = cid.version() == ipld_core::cid::Version::V1
                && matches!(cid.codec(), RAW_CODEC | DAG_CBOR_CODEC)
                && cid.hash().code() == SHA2_256
                && cid.hash().size() == 32;
            if dasl {
                Ok(())
            } else {
                Err(StarError::Meta(format!("CID {cid} is not a DASL CID")))
            }
        }
        Ipld::List(items) => items.iter().try_for_each(check_drisl),
        Ipld::Map(map) => map.values().try_for_each(check_drisl),
        _ => Ok(()),
    }
}

/// Encode `meta` as canonical DRISL and check it the way a reader will, so a writer
/// never emits an archive it would refuse to read.
pub fn encode_meta<T: Serialize>(meta: &T) -> Result<(Vec<u8>, StarMeta), StarError> {
    let bytes = serde_ipld_dagcbor::to_vec(meta).map_err(|e| StarError::Meta(e.to_string()))?;
    let parsed = parse_meta(&bytes)?;
    Ok((bytes, parsed))
}

/// The archive's opening bytes: magic, then the framed metadata.
pub fn star_header(meta_bytes: &[u8]) -> Vec<u8> {
    let mut out = STAR_MAGIC.to_vec();
    push_frame(meta_bytes, &mut out);
    out
}

/// One pair's bytes: the control byte, then the framed key and value.
pub fn star_pair_frame(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = vec![STAR_CONTROL_PAIR];
    push_frame(key, &mut out);
    push_frame(value, &mut out);
    out
}

/// A whole archive in memory.
pub fn write_star<T: Serialize>(meta: &T, pairs: &[StarPair]) -> Result<Vec<u8>, StarError> {
    let (meta_bytes, _) = encode_meta(meta)?;
    let mut out = star_header(&meta_bytes);
    for pair in pairs {
        out.extend(star_pair_frame(&pair.key, &pair.value));
    }
    out.push(STAR_CONTROL_END);
    Ok(out)
}

/// Reads a STAR archive: the header eagerly in [`StarReader::new`], the pairs lazily
/// as an iterator. The iterator ends after the terminator, having checked that nothing
/// follows it, and yields nothing more after an error.
///
/// Control bytes and varints are read a byte at a time: wrap a socket or file in a
/// `BufReader`. A byte slice needs nothing.
pub struct StarReader<R> {
    reader: R,
    meta: StarMeta,
    limits: StarLimits,
    done: bool,
}

impl<R: Read> StarReader<R> {
    pub fn new(mut reader: R, limits: StarLimits) -> Result<Self, StarError> {
        let mut magic = Vec::new();
        reader.by_ref().take(4).read_to_end(&mut magic)?;
        if magic != STAR_MAGIC {
            return Err(StarError::Magic);
        }
        let meta = parse_meta(&read_frame(&mut reader, "metadata", limits.max_meta)?)?;
        Ok(Self {
            reader,
            meta,
            limits,
            done: false,
        })
    }

    pub fn meta(&self) -> &StarMeta {
        &self.meta
    }

    /// The metadata's `$type`, naming the archive's profile.
    pub fn star_type(&self) -> &str {
        match self.meta.get("$type") {
            Some(Ipld::String(t)) => t,
            // `parse_meta` guarantees a string `$type`.
            _ => "",
        }
    }

    fn next_pair(&mut self) -> Result<Option<StarPair>, StarError> {
        match read_byte(&mut self.reader)?.ok_or(StarError::Truncated)? {
            STAR_CONTROL_END => {
                if read_byte(&mut self.reader)?.is_some() {
                    return Err(StarError::Trailing);
                }
                Ok(None)
            }
            STAR_CONTROL_PAIR => {
                let key = read_frame(&mut self.reader, "key", self.limits.max_key)?;
                let value = read_frame(&mut self.reader, "value", self.limits.max_value)?;
                Ok(Some(StarPair { key, value }))
            }
            other => Err(StarError::Control(other)),
        }
    }
}

impl<R: Read> Iterator for StarReader<R> {
    type Item = Result<StarPair, StarError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let result = self.next_pair().transpose();
        if !matches!(result, Some(Ok(_))) {
            self.done = true;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(bytes: &[u8]) -> Result<u64, StarError> {
        read_varint(&mut &bytes[..])
    }

    #[test]
    fn varint_round_trips_at_group_boundaries() {
        for value in [
            0,
            1,
            127,
            128,
            16_383,
            16_384,
            u32::MAX as u64,
            (1 << 63) - 1,
        ] {
            let mut out = Vec::new();
            encode_varint(value, &mut out);
            assert_eq!(varint(&out).unwrap(), value, "{value}");
        }
    }

    #[test]
    fn varint_rejects_padding_and_overlong() {
        assert!(matches!(
            varint(&[0x80, 0x00]),
            Err(StarError::NonCanonicalVarint)
        ));
        assert!(matches!(
            varint(&[0x81, 0x80, 0x00]),
            Err(StarError::NonCanonicalVarint)
        ));
        assert!(matches!(varint(&[0xff; 9]), Err(StarError::VarintTooLong)));
        assert!(matches!(varint(&[0x80]), Err(StarError::Truncated)));
    }

    #[test]
    fn limits_reject_each_frame_over_its_limit() {
        let star = write_star(
            &BTreeMap::from([("$type", "t")]),
            &[StarPair {
                key: vec![1, 2],
                value: vec![3, 4, 5],
            }],
        )
        .unwrap();
        let meta_len = encode_meta(&BTreeMap::from([("$type", "t")]))
            .unwrap()
            .0
            .len() as u64;
        let exact = StarLimits {
            max_meta: meta_len,
            max_key: 2,
            max_value: 3,
        };
        let read = |limits| -> Result<Vec<StarPair>, StarError> {
            StarReader::new(&star[..], limits)?.collect()
        };
        assert_eq!(read(exact).unwrap().len(), 1);
        for (frame, limits) in [
            (
                "metadata",
                StarLimits {
                    max_meta: meta_len - 1,
                    ..exact
                },
            ),
            (
                "key",
                StarLimits {
                    max_key: 1,
                    ..exact
                },
            ),
            (
                "value",
                StarLimits {
                    max_value: 2,
                    ..exact
                },
            ),
        ] {
            match read(limits) {
                Err(StarError::TooLong { frame: f, .. }) => assert_eq!(f, frame),
                other => panic!("{frame}: {other:?}"),
            }
        }
    }

    #[test]
    fn meta_rejects_negative_zero_and_non_dasl_cids() {
        let neg_zero = BTreeMap::from([
            ("$type".to_string(), Ipld::String("t".into())),
            ("f".to_string(), Ipld::Float(-0.0)),
        ]);
        assert!(matches!(encode_meta(&neg_zero), Err(StarError::Meta(_))));

        // CIDv1, dag-pb (0x70), sha2-256: valid CID, not a DASL one.
        let digest =
            ipld_core::cid::multihash::Multihash::<64>::wrap(SHA2_256, &[0u8; 32]).unwrap();
        let dag_pb = ipld_core::cid::Cid::new_v1(0x70, digest);
        let dasl = ipld_core::cid::Cid::new_v1(DAG_CBOR_CODEC, digest);
        let with_link = |cid| {
            BTreeMap::from([
                ("$type".to_string(), Ipld::String("t".into())),
                ("l".to_string(), Ipld::List(vec![Ipld::Link(cid)])),
            ])
        };
        assert!(matches!(
            encode_meta(&with_link(dag_pb)),
            Err(StarError::Meta(_))
        ));
        assert!(encode_meta(&with_link(dasl)).is_ok());
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Hands out one byte per read, the way the reference tests feed a byte-by-byte
    // stream, so no frame boundary relies on a read returning everything at once.
    struct OneByte<'a>(&'a [u8]);
    impl Read for OneByte<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match (self.0.split_first(), buf.first_mut()) {
                (Some((b, rest)), Some(slot)) => {
                    *slot = *b;
                    self.0 = rest;
                    Ok(1)
                }
                _ => Ok(0),
            }
        }
    }

    fn read_all<R: Read>(r: R) -> Result<(StarMeta, Vec<StarPair>), StarError> {
        let reader = StarReader::new(r, StarLimits::UNLIMITED)?;
        let meta = reader.meta().clone();
        Ok((meta, reader.collect::<Result<_, _>>()?))
    }

    #[test]
    fn interop_valid_fixtures() {
        let raw = include_str!("../tests/fixtures/interop/star-valid.json");
        let cases: Vec<serde_json::Value> = serde_json::from_str(raw).unwrap();
        assert_eq!(cases.len(), 19);
        for case in cases {
            let comment = case["comment"].as_str().unwrap();
            let star = hex(case["star_hex"].as_str().unwrap());
            let decoded = &case["decoded"];
            let pairs: Vec<StarPair> = decoded["pairs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| StarPair {
                    key: hex(p["key_hex"].as_str().unwrap()),
                    value: hex(p["value_hex"].as_str().unwrap()),
                })
                .collect();
            let expected_meta = encode_meta(&decoded["meta"]).unwrap().1;

            for (meta, got) in [
                read_all(&star[..]).unwrap_or_else(|e| panic!("{comment}: {e}")),
                read_all(OneByte(&star)).unwrap_or_else(|e| panic!("{comment}: {e}")),
            ] {
                assert_eq!(meta, expected_meta, "{comment}");
                assert_eq!(got, pairs, "{comment}");
            }
            assert_eq!(
                write_star(&decoded["meta"], &pairs).unwrap(),
                star,
                "{comment}"
            );
        }
    }

    #[test]
    fn interop_invalid_fixtures() {
        let raw = include_str!("../tests/fixtures/interop/star-invalid.json");
        let cases: Vec<serde_json::Value> = serde_json::from_str(raw).unwrap();
        assert_eq!(cases.len(), 37);
        for case in cases {
            let comment = case["comment"].as_str().unwrap();
            let star = hex(case["star_hex"].as_str().unwrap());
            assert!(read_all(&star[..]).is_err(), "accepted: {comment}");
            assert!(
                read_all(OneByte(&star)).is_err(),
                "accepted byte-wise: {comment}"
            );
        }
    }

    #[test]
    fn writer_refuses_meta_without_string_type() {
        assert!(matches!(
            write_star(&BTreeMap::from([("$type", 1)]), &[]),
            Err(StarError::MetaType)
        ));
    }
}
