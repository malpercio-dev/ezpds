# STAR and DRISL support in Rust

Researched 2026-11-09 for MM-662. Question: is there a usable Rust crate for the STAR archive
format or for DRISL and DASL CIDs, or should Custos hand-roll the codec against the spec?

## Answer

Hand-roll STAR. No published Rust crate implements the STAR format that dasl.ing specifies today
and that the reference PDS reads and writes. The format is small: the reference codec is 250
lines of TypeScript, and a Rust reader and writer is about 250 to 300 lines plus tests.

Keep the existing DAG-CBOR stack for DRISL (`serde_ipld_dagcbor` + `ipld-core` + `cid`). Its
encoder already emits DRISL-valid bytes for everything Custos encodes, with one float edge case
that atproto records cannot reach. Its decoder at the pinned 0.6.4 is not strict, so STAR
metadata needs the same decode, re-encode, compare check the reference uses, plus a small
DASL-CID check. Upgrading to `serde_ipld_dagcbor` 0.7.0 would make the decoder strict by itself;
that is a separate change.

## What STAR is

Source: <https://dasl.ing/star.html> (last updated 2026-11-03, maturity "Hot New Stuff", editor
Fig Schleihauf of microcosm.blue).

```
[ magic | len | meta ] [ 1 | len | key | len | val ] *  [ 0 ]
```

- Magic is four bytes, `0x2A 0x6C 0x01 0x00`.
- Every `len` is an unsigned varint: at most 9 bytes, minimally encoded. The spec warns that
  common LEB128 parsers are not compliant.
- `meta` is a DRISL-encoded map whose size is exactly its length prefix. `$type` is the only
  required key and must be a text string. The metadata must meet DRISL's deterministic encoding
  rules, and the spec warns that generic CBOR parsers may not enforce them.
- After the header and after each pair comes a control byte: `0x01` means a pair follows, `0x00`
  ends the archive. Nothing may follow the `0x00`.
- A pair is a length-prefixed key and a length-prefixed value, both opaque bytes. Empty and
  duplicate keys are allowed by the format.
- Pair order is significant, but the format imposes no ordering. Any parser error is fatal for
  the whole archive.
- No format-level size limits; parsers may impose their own.
- Media type `application/vnd.dasl.star`, extension `.star`.
- The "Application profiles" section of the spec is still `TODO`, and the spec says to expect
  breaking changes.

Two things the ticket asked about are therefore not properties of the STAR format:

- **Strict bytewise key ordering** is a profile rule. The reference enforces it in the profile
  layer, not in the STAR codec (see "How the reference does it").
- **Canonical metadata** is a format rule: the metadata must be canonical DRISL.

Interop vectors exist as JSON with hex-encoded archives:
`valid-star-fixtures.json` and `invalid-star-fixtures.json` on the `interop` branch of
<https://tangled.org/microcosm.blue/star/tree/interop/interop>. The reference PDS vendors them
under `packages/star/tests/interop/`.

## Candidate crates

Searched crates.io for `star`, `star-`, `star atproto`, `dasl`, `drisl`, `cborc`, and
`serde_ipld_dagcbor`, and read the Rust section of the implementations list on
<https://dasl.ing/>. Licenses, dates, and dependencies come from the crates.io API; behavior
claims come from each crate's published source.

| Crate | Latest release | License | Implements STAR? | DRISL / CID | Dependency weight | Verdict |
|---|---|---|---|---|---|---|
| `star-lite` 0.3.0-alpha.1 (microcosm.blue) | 2026-08-28, alpha; readme says "NOT FULLY REVIEWED YET" | MIT OR Apache-2.0 (allowed) | No. It implements STAR-lite v0/v1: a 3-byte magic (`2A 6C 00` or `2A 6C 01`), a kind byte, and a commitment. That is not wire-compatible with the current 4-byte magic and DRISL `$type` header. The spec calls STAR-lite "an earlier version ... to be superseded by STAR" | Uses `serde_ipld_dagcbor` ^0.6 via `star-repo` | `star-repo`, `tempfile` (normal dependency), `thiserror` ^1, `serde_bytes`. No HTTP | Wrong format |
| `star-repo` 0.3.0-alpha.1 | 2026-08-28, alpha | MIT OR Apache-2.0 | No. CARv1, MST, LtHash, strict varint helpers for `star-lite` | `ipld-core` ^0.4, `serde_ipld_dagcbor` ^0.6 (match the workspace) | `sha2` ^0.11 (workspace is 0.10; both are already in `Cargo.lock`), `thiserror` ^1, `blake3`, `unsigned-varint`. No HTTP | Not a STAR codec |
| `dasl` 0.2.0 (n0-computer; listed on dasl.ing) | 2025-09-18, 14 months old | MIT OR Apache-2.0 | No. CID and DRISL only | CID type restricted to DASL (raw or dag-cbor, SHA-256 or BLAKE3). DRISL decoder is **not** strict: the DASL compliance matrix shows `n0_dasl` 0.2.0 accepting unsorted map keys, non-minimal integers and lengths, negative zero, and -Infinity | `cbor4ii` ^1.0 (workspace resolves 0.2.14, so a second major of `cbor4ii`; not a guarded ban), `sha2` ^0.10, `thiserror` ^2, `blake3`, `data-encoding`. No HTTP | Weaker than what Custos has |
| `atproto-dasl` 0.14.5 (ngerakines) | 2026-04-02 | MIT (allowed) | No. CID, DRISL, CAR, MASL, RASL, BDASL | `DaslCid` rejects codecs other than raw and dag-cbor and hashes other than SHA-256. Decoder has a strict mode, on by default, documented to reject non-minimal integers and non-canonical key order. Not in the compliance matrix | Non-optional `tokio` (with `rt-multi-thread`, `fs`), `futures`, `tracing`, `url`, `tempfile`, `cid` ^0.11, `multihash` ^0.19, `sha2` ^0.11, `blake3`. `reqwest` ^0.12 and `axum` are optional and off by default; turning `reqwest` on would trip the `reqwest <0.13` ban in `deny.toml` | Heavy for a codec; a second DAG-CBOR implementation beside the one atrium-repo forces |
| `covalence-lib-dasl` 0.1.0-dev.7 (hiloopai) | 2026-10-28, `-dev` prerelease, first published 2026-10-14 | CC0-1.0 OR MIT OR Apache-2.0 (allowed) | No | DRISL codec and CID crates | Declares `rust-version = "1.98"`; the workspace pins 1.96.0. Exact-version pins on four sibling `covalence-lib-*` crates | Does not build on the pinned toolchain |
| `serde_ipld_dagcbor` 0.6.4 (in the workspace today) | 0.6.4 resolved; 0.7.0 released 2026-08-03 | MIT/Apache-2.0 | No | See next section | Already a dependency | Keep |
| `ipld-core` 0.4.3 / `cid` 0.11.3 (in the workspace today; `ipld-core` is listed on dasl.ing) | `ipld-core` 0.4.3 on 2026-02-16 | MIT OR Apache-2.0 | No | Generic IPFS CIDs, not restricted to the DASL subset | Already dependencies | Keep |

The third Rust entry on dasl.ing, `rust_cid_npm`, is a CID library and CLI hosted on Debian
Salsa. It was not evaluated further: it has no STAR or DRISL codec.

Other implementations of the current STAR format, none in Rust: `@atproto/star` (TypeScript,
the reference, below) and `cobalt/star` (Go, linked from the spec).

Streaming and ordering, for the crates above: none applies, since none reads or writes the
current STAR format. For the record, `star-lite` does have a streaming `Reader`/`Writer` over
`std::io` and enforces strict bytewise key order and minimal varints for its own format.

## DRISL against the DAG-CBOR the workspace encodes

### What the workspace uses

From the root `Cargo.toml` and `Cargo.lock`:

- `serde_ipld_dagcbor` 0.6.4 (on `cbor4ii` 0.2.14), used by `repo-engine`, `custos-spaces`,
  `custos-core`, `custos-blobs`, `custos-firehose`, `obsign-core`, and `pds`. The vendored
  `atrium-repo` patch also depends on `serde_ipld_dagcbor` 0.6.
- `ipld-core` 0.4.3 with the `serde` feature, which is what makes a CID serialize as tag 42.
- `cid` 0.11.3 and `multihash` 0.19.5.
- `ciborium` 0.2 in `crates/crypto` only, for did:plc operations. It is a generic CBOR encoder;
  `crypto/src/plc.rs` orders keys by hand. It is not a DRISL encoder and should not be used for
  STAR metadata.

`custos-spaces` already builds its `getRepo` index and commit block with
`serde_ipld_dagcbor::to_vec`.

### What DRISL requires

Source: <https://dasl.ing/drisl.html> (Stable) and <https://dasl.ing/cid.html> (Stable). DRISL
is a subset of CBOR Core with these additions: tag 42 must be supported and every other tag
rejected; map keys must be strings; floats are always 64-bit, never 16- or 32-bit; infinity,
negative infinity, NaN, and negative zero must not be encoded; no indefinite lengths; no simple
values other than true, false, and null. A DASL CID is CIDv1, codec raw (0x55) or dag-cbor
(0x71), SHA-256 (0x12), 32-byte digest.

### Comparison

| Rule | DRISL | `serde_ipld_dagcbor` 0.6.4 encoder | `serde_ipld_dagcbor` 0.6.4 decoder |
|---|---|---|---|
| Map key order | CBOR Core deterministic order: bytewise over the encoded key | Sorts the encoded entries bytewise (`ser.rs`, the map collector's `sort_unstable`). For text-string keys this is the same order as DAG-CBOR's length-first rule, because the length is in the key's head. Valid | Not checked. Unsorted and duplicate keys are accepted |
| Map key type | Strings only | Rejects non-string keys | Decoding to `Ipld` rejects them |
| Integers and lengths | Shortest form | Shortest form. Valid | Not checked. Non-minimal forms are accepted |
| Floats | 64-bit only | Always 64-bit; `f32` is widened. Valid | Accepts 32-bit floats on the `deserialize_any` path |
| NaN, ±Infinity | Forbidden | Rejected with an error. Valid | Decoding to `Ipld` rejects non-finite floats |
| Negative zero | Forbidden | **Emitted as `fb 80 00 ...`.** Not DRISL-valid | Accepted |
| Tags | 42 only | Emits 42 only, with the `0x00` prefix | Rejects other tags |
| Indefinite lengths | Forbidden | Never emitted | Rejected |
| Simple values | true, false, null | Only those | `undefined` and others rejected |
| CIDs under tag 42 | v1, raw or dag-cbor, SHA-256, 32 bytes | Encodes whatever `Cid` it is given | Accepts any CID the `cid` crate parses: CIDv0, dag-pb, SHA-1, short or long digests |

So the encoder emits DRISL-valid bytes except for negative zero, and the atproto data model has
no floats: `repo-engine` rejects them in records (`records.rs`, `data_model.rs`). CIDs Custos
mints are CIDv1 dag-cbor or raw with SHA-256, which are DASL CIDs. For the metadata maps STAR
profiles use (strings, integers, byte strings), `serde_ipld_dagcbor::to_vec` output is DRISL.

The decoder is the gap. To reject non-canonical STAR metadata on 0.6.4, do what the reference
does: decode, re-encode, and require the bytes to match. That catches unsorted or duplicate
keys, non-minimal heads, and 32-bit floats. It does not catch negative zero or a non-DASL CID
under tag 42; a walk over the decoded `Ipld` (about 20 lines) covers both.

`serde_ipld_dagcbor` 0.7.0 closes most of this. Its changelog says deserialization "is now as
strict as possible", and `-0.0` is serialized as `0.0`. Its source checks minimal heads
(`check_minimal`), key order and duplicates (`UnorderedKey`), and negative zero. The DASL
compliance matrix (run 2026-11-09 against 0.7.0) confirms it rejects unsorted keys, non-minimal
integers and lengths, negative zero, and infinities, and still accepts non-DASL CIDs. The
upgrade moves `cbor4ii` from 0.2 to 1.2 and changes the decode error enum, and the vendored
`atrium-repo` patch asks for 0.6, so it needs its own change and is not required for STAR.

## How the reference does it

Source: `bluesky-social/atproto` at commit `a620ad3d68d94ad2db653c1cd9ecff7b12c9b88e`
(2026-11-06).

At this commit `packages/space/src/star.ts` does not exist. The STAR codec is its own package,
`packages/star` (`@atproto/star` 0.0.1), and `packages/space` imports it.

| File | Lines | Role |
|---|---|---|
| `packages/star/src/star.ts` | 202 | `writeStar`, `readStar`, varint, metadata check |
| `packages/star/src/bytes-reader.ts` | 42 | Reads exact byte counts from a chunk stream |
| `packages/star/src/error.ts` | 6 | `StarParseError` |
| `packages/space/src/space-meta-archive.ts` | 176 | `atproto-space-meta` profile |
| `packages/space/src/sync/provider.ts` | 56 | `atproto-space-repo` profile, write side |
| `packages/space/src/sync/consumer.ts` | 196 | `atproto-space-repo` profile, read and verify side |

The codec (`star.ts`):

- **Write** is an async generator: magic, framed `encode(meta)`, then for each pair `0x01`,
  framed key, framed value, and finally `0x00`. Pairs come from an iterable, so the writer
  streams. It does not sort or check keys.
- **Read** reads the magic and metadata eagerly and yields pairs lazily. Each length is checked
  against a caller-supplied limit (`maxMetaLength`, `maxKeyLength`, `maxValueLength`) before the
  frame is buffered. An unknown control byte, a short read, or any byte after the final `0x00`
  is an error.
- **Varint** decode stops at 9 bytes and rejects a final zero byte after the first byte.
- **Metadata** must decode to a map with a string `$type`, and must re-encode to the same bytes:
  "The decoder accepts some non-canonical forms (such as unsorted map keys), so check that the
  metadata re-encodes to the same bytes."
- The interop test reads every fixture whole and one byte at a time, and checks that writing the
  decoded form reproduces the fixture bytes.

The profiles:

- `atproto-space-repo` (`sync/provider.ts`, `sync/consumer.ts`): metadata is the repo commit
  plus `$type`. Each pair is a `{collection}/{rkey}` key and the record's DRISL bytes. The
  writer throws if a key is not strictly greater, bytewise, than the previous one; the reader
  rejects the same. Limits: metadata 64 KiB, key 4 KiB, value 1 MiB.
- `atproto-space-meta` (`space-meta-archive.ts`): metadata is `{$type, ver: 1, space}`. Three
  sections in fixed order (`policy`, policy state, `writer/{did}`), each in strict bytewise key
  order; the writer sorts, the reader rejects duplicates, out-of-order keys, and out-of-order
  sections. Values are DRISL maps. Read whole, with the same limits.

## Size estimate for a hand-rolled Rust codec

Based on the reference's line counts and on the existing CAR framing code in
`crates/repo-engine` (`car_export.rs`, `car_import.rs`), which is the same shape of work.

| Piece | Reference lines | Rust estimate |
|---|---|---|
| Strict varint encode and decode | about 30 in `star.ts` | 40 |
| Writer: header, pair frame, end byte, as byte-returning functions like `car_v1_header` / `car_v1_block_frame` | about 25 | 40 |
| Streaming reader with limits, control bytes, trailing-byte check | about 85 plus 42 for `bytes-reader.ts` | 120 to 150 |
| Metadata check: decode, `$type`, re-encode compare, negative zero and DASL-CID walk | about 20 | 40 to 50 |
| Error enum | 6 | 30 |
| **Codec total** | **250** | **250 to 300** |
| Tests: interop fixtures loop (whole and byte-by-byte), limits | 63 plus 60 | 150 to 200 |

The two profiles are separate work on top of the codec: about 150 to 250 lines of Rust each,
judging from 176 lines for space-meta and 252 for the repo profile's two halves.

As a second data point, the `star-lite` crate's reader, writer, and varint modules are 310, 165,
and 103 lines for a format with more header variants.

The existing varint decoders in the workspace (`repo-engine/src/car_import.rs`,
`obsign-core/src/repo_backup.rs`) accept non-minimal and 10-byte encodings, which CAR tolerates
and STAR forbids. The STAR reader needs its own strict decoder or a strict flag on a shared one.

## Recommendation

Hand-roll the STAR reader and writer in the workspace, and keep `serde_ipld_dagcbor` for DRISL.

- No crate implements the format. The only Rust crate with "STAR" in its name implements the
  superseded STAR-lite wire format and is an unreviewed alpha.
- The codec is about 300 lines with no new dependencies. Every DASL crate surveyed would add a
  second CBOR implementation next to the one `atrium-repo` already requires, for no STAR support.
- The spec is still "Hot New Stuff" with a `TODO` profiles section. Owning 300 lines makes a
  breaking spec change a small local edit instead of a wait on an upstream alpha.
- The interop fixtures give a ready conformance test, and the reference's own test shape (read
  whole, read byte-by-byte, write and compare) ports directly.

Port the canonical-metadata check as decode, re-encode, compare, and add the negative-zero and
DASL-CID walk. Consider the `serde_ipld_dagcbor` 0.7.0 upgrade separately; it would make every
DAG-CBOR decode in the workspace strict, which is a behavior change for CAR import and firehose
consumers and deserves its own review.

## Not verified

- No code was compiled or run. Encoder and decoder behavior for `serde_ipld_dagcbor` 0.6.4 comes
  from reading its source; the compliance matrix covers 0.7.0, not 0.6.4.
- `atproto-dasl`'s strict decoding is taken from its documentation and config source, not
  tested, and it is absent from the compliance matrix.
- The matrix rows were extracted from the page's HTML with a script that matched 56 rows; rows
  it failed to parse were not reviewed.
- The reference was read over HTTPS at the pinned commit (the files listed above), not from a
  clone. The interop fixture JSON files themselves were not downloaded or read.
- The `interop` branch of `microcosm.blue/star` lists only `star-lite` and `star-repo` under
  `reference-impl/rust`, last changed 2026-08-28. Their source on that branch was not read, so
  an unpublished update to the current magic there is possible but unconfirmed. The published
  crates were read and implement STAR-lite.
- `cobalt/star` (Go) and `rust_cid_npm` were not read.
- The STAR spec's application-profiles section is `TODO`; the profile rules above come from the
  reference implementation, not from a spec.

## Sources

- STAR spec: <https://dasl.ing/star.html>
- DRISL spec: <https://dasl.ing/drisl.html>
- DASL CID spec: <https://dasl.ing/cid.html>
- DASL implementations list: <https://dasl.ing/>
- DASL compliance matrix: <https://hyphacoop.github.io/dasl-testing/> (run dated 2026-11-09)
- STAR repository and interop vectors: <https://tangled.org/microcosm.blue/star>
- Reference implementation:
  <https://github.com/bluesky-social/atproto/tree/a620ad3d68d94ad2db653c1cd9ecff7b12c9b88e/packages/star>
  and `packages/space` at the same commit
- crates.io API and published sources for `star-lite` 0.3.0-alpha.1, `star-repo` 0.3.0-alpha.1,
  `dasl` 0.2.0, `atproto-dasl` 0.14.5, `covalence-lib-dasl` 0.1.0-dev.7, `serde_ipld_dagcbor`
  0.6.4 and 0.7.0
- This repository: root `Cargo.toml`, `Cargo.lock`, `deny.toml`, `crates/repo-engine`,
  `crates/custos-spaces`, `crates/crypto`
