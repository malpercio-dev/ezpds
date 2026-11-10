# MM-661: Golden vectors and archive limits at the pin

Researched 2026-11-09. Research only; no product code changed.

## Sources

Everything below was read from source at two pinned commits. Nothing from either repository was installed or run.

- **Code:** `bluesky-social/atproto`, branch `permissioned-data`, commit `a620ad3d68d94ad2db653c1cd9ecff7b12c9b88e` (2026-11-06). Paths are relative to that tree.
- **Proposal:** `bluesky-social/proposals`, `0016-permissioned-data/README.md`, commit `9e86df35b17f828294333a4c5b95dce22bcbf323` (2026-11-05). Cited as "proposal §heading".
- **RFC 9180 §A.3.1**, fetched from `https://www.rfc-editor.org/rfc/rfc9180.txt`, to check the KEM vector against the document it claims to come from.

One path in the ticket is wrong: STAR is not in `packages/space`. It is its own package, `packages/star/` (`src/star.ts`, `src/star.test.ts`, `tests/interop.test.ts`, `tests/interop/*.json`). `packages/space` holds the two profiles built on it (`src/sync/provider.ts`, `src/sync/consumer.ts`, `src/space-meta-archive.ts`).

## Verdict

- **Fixed-output vectors published at the pin:** one KEM shared secret (RFC 9180 §A.3.1), two LtHash digests, two MAC header strings, 19 valid and 37 invalid STAR archives.
- **No fixed-output vector exists for the commit MAC or the record MAC.** Every MAC test draws its shared secret from `randomBytes(32)` and asserts only properties (round-trip, tamper rejection, domain separation). The same is true of the commit shape, the `atproto-space-repo` archive and the `atproto-space-meta` archive: property tests over fixed inputs, no expected bytes. Custos has to mint its own MAC and archive vectors. Two are derived in [Derived MAC vectors](#derived-mac-vectors-not-published-upstream), labelled as such.
- **Code and proposal agree** on every byte layout, label, header example and limit. The differences are places where the code is looser than the proposal's MUSTs, listed in [Code versus proposal](#code-versus-proposal).
- **In `crates/crypto/src/space.rs`:** `LtHash`, `format_set_hash_element` and both golden digests survive unchanged. Everything built on `ctx`/`ikm`/`sig` is obsolete.

## KEM shared secret

Source: `packages/space/src/kem.ts`, `packages/space/tests/kem.test.ts`; proposal §"Shared secret".

### Construction

ECDH on P-256 with the secret derived as in DHKEM(P-256, HKDF-SHA256), RFC 9180 §4.1.

```
dh               = 32-byte x-coordinate of the ECDH shared point
syncer_key_bytes = 0x04 || x || y   (uncompressed, 65 bytes)
author_key_bytes = 0x04 || x || y   (uncompressed, 65 bytes)

prefix = "HPKE-v1" || "KEM" || uint16be(0x0010)        // 48504b452d76314b454d0010
input  = prefix || "eae_prk" || dh
info   = uint16be(32) || prefix || "shared_secret" || syncer_key_bytes || author_key_bytes

shared_secret = HKDF-SHA256(ikm = input, salt = "", info = info, length = 32)
```

- HKDF is the full extract-then-expand of RFC 5869 (`hkdfSha256` in `packages/crypto/src/hmac.ts` wraps noble's `hkdf`), with an empty salt.
- The syncer's key comes first in `info`, the author's second, on both sides.
- `key_share` travels as a `did:key`, which holds the compressed point. The code decompresses it before hashing (`parseDidKey` in `packages/crypto/src/did.ts` calls `decompressPubkey`). The proposal says the same in a comment.
- A key that is not a P-256 `did:key`, or does not parse, throws `SpaceMacError` (`code = 'BadSpaceMac'`). The reference PDS maps that to XRPC `InvalidRequest` / `BadSpaceMac` (`packages/pds/src/api/com/atproto/space/util.ts`).

### Vector (1 fixed output)

Test "matches the RFC 9180 test vector". The syncer's key share is the RFC's `pkEm`; the author's KEM private key is `skRm`.

| Name | Value |
|---|---|
| `pkEm` (key share, uncompressed) | `04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4` |
| `skRm` (author KEM private key) | `f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2` |
| expected `shared_secret` | `c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8` |

The test builds the header value with `formatDidKey(P256_JWT_ALG, pkEm)` and asserts `decapsulate(author, keyShare)` equals the secret. It exercises only the repo-host side.

All three values match RFC 9180 §A.3.1 character for character. The RFC also gives the author's public key, which the test derives rather than states:

`pkRm = 04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0`

and the syncer's ephemeral private key, which lets a Rust test cover the syncer side too:

`skEm = 4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb`

### Other KEM tests (4, property only)

Round-trip (`encapsulate` then `decapsulate` agree, 32 bytes); a fresh key share and secret per encapsulation; a different author key gives a different secret; a secp256k1 key or `did:key:nope` throws `SpaceMacError` on both sides.

## Commit MAC and record MAC

Source: `packages/space/src/mac.ts`, `packages/space/src/bytes.ts`, `packages/space/tests/mac.test.ts`; proposal §"Commit MAC", §"Record MAC", §"Authenticity headers".

### MAC input framing

```
commit_context = "atproto-space-repo-v1"
              || uint16be(len(space)) || space
              || uint16be(len(repo))  || repo
              || uint16be(len(rev))   || rev
commit_mac     = HMAC-SHA256(shared_secret, commit_context || data)

record_context = "atproto-space-record-v1"
              || uint16be(len(uri)) || uri
record_mac     = HMAC-SHA256(shared_secret, record_context || record_cid_bytes)
```

- The domain-separation tag is `"{type}-v{ver}"` with no length prefix and no terminator: `atproto-space-repo-v1` (21 bytes) and `atproto-space-record-v1` (23 bytes).
- The field order in the commit MAC is **space, repo, rev**. That is not the order of the commit's fields.
- Each length is the UTF-8 byte length, big-endian `uint16`. `uint16be` throws a plain `Error` (not `SpaceMacError`) above 65,535, so that is a hard cap on `space`, `repo`, `rev` and `uri`.
- `data` (32 bytes) and `record_cid_bytes` (the binary CID) are appended with no length prefix.
- `shared_secret` is the HMAC key directly. There is no further key derivation.
- The commit tag is built from the constant `COMMIT_VERSION`, not from `commit.ver`. `verifyCommit` rejects `ver !== 1` before the MAC is checked.
- Comparison is constant-time (`timingSafeEqual` in `bytes.ts`); a length mismatch returns false.

### Header grammar

Both headers are RFC 9651 Structured Field Dictionaries, serialized and parsed with the `structured-headers` npm package (`^1.0.1`).

```
Atproto-Space-Want-Mac: type="atproto-space-repo", ver=1, key_share="did:key:zDna..."
Atproto-Space-Mac:      type="atproto-space-repo", ver=1, mac=:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=:
```

| Member | Structured-field type | Value |
|---|---|---|
| `type` | String | `atproto-space-repo` or `atproto-space-record` |
| `ver` | Integer | `1` for both types today (commits share `COMMIT_VERSION`; records use `RECORD_MAC_VERSION`) |
| `key_share` (request) | String | the syncer's ephemeral P-256 public key as a `did:key` |
| `mac` (response) | Byte Sequence | the 32-byte MAC, padded base64 between colons |

The code's constants are lowercase: `atproto-space-want-mac`, `atproto-space-mac`. The serializer emits members in the order `type`, `ver`, then `key_share` or `mac`.

Parsing rules in `parseMacDictionary`, `parseWantMacHeader` and `parseMacHeader`:

1. The header value must be a single string. `undefined` or a string array (a repeated header) is rejected: "missing or malformed MAC header".
2. It must parse as a Dictionary, else "malformed MAC header".
3. Any member whose value is an Inner List is rejected: "malformed MAC header field: {key}".
4. Member parameters are dropped without inspection. Unknown members are ignored.
5. `type` must equal the type the endpoint expects, else "unsupported MAC type, expected {type}".
6. `ver` must equal that type's version, else "unsupported MAC version for {type}".
7. Request: `key_share` must be a String, else "missing or malformed key_share".
8. Response: `mac` must be a Byte Sequence, else "missing or malformed mac". The parser does not check that it is 32 bytes; a wrong length only fails at comparison.
9. Member order is not checked on parse.

Every failure is a `SpaceMacError`.

Server behaviour around the headers, from `packages/pds/src/api/com/atproto/space/util.ts`: the host always appends `Vary: atproto-space-want-mac`. It skips the MAC only when the request header is absent *and* the caller is not using a space credential. Otherwise it appends `Access-Control-Expose-Headers: atproto-space-mac` and derives the secret. An account with no KEM key throws an internal error, not a `BadSpaceMac`.

### Vectors

Fixed header strings (2):

| Call | Expected |
|---|---|
| `formatWantMacHeader('atproto-space-repo', 'did:key:zDnaExample')` | `type="atproto-space-repo", ver=1, key_share="did:key:zDnaExample"` |
| `formatMacHeader('atproto-space-repo', bytes 0x00..0x1f)` | `type="atproto-space-repo", ver=1, mac=:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=:` |

The second string is the same example the proposal prints.

Fixed rejections (6): `undefined`; `'???'`; `type="atproto-space-repo", ver=1` (matches `/key_share/`); `type="atproto-space-repo", ver=1, mac="abc"` (a String where a Byte Sequence is required, matches `/mac/`); a repo-type header parsed as record type (`/unsupported MAC type/`); and `type="atproto-space-repo", ver=2, key_share="did:key:zDnaX"` (`/unsupported MAC version/`).

Fixed MAC outputs: **none.** The 11 tests in `mac.test.ts` use these fixed inputs with a random secret:

```
SPACE  = at://did:example:space/space/app.bsky.group/test
URI    = at://did:example:alice/space/app.bsky.group/test/app.bsky.feed.post/1
commit = { ver: 1, space: SPACE, repo: "did:example:alice", rev: "3kbcq3p7ad400", data: 32 bytes of 0x01 }
CID_A  = bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244   // { text: 'hello' }
CID_B  = bafyreidpw4cbv6gr4ukh33z23pvvrpr3wi4gnpmi4doamlsl3sa4rgri2a   // { text: 'world' }
```

Properties asserted: the commit MAC is 32 bytes and verifies only under the same secret; `{repo: "did:example:alice", rev: "3kbc"}` and `{repo: "did:example:alice3", rev: "kbc"}` MAC differently (the length prefixes are what separate them); changing `data` to 32 bytes of `0x02` fails; the record MAC covers both the URI (`URI + "2"` fails) and the CID (`CID_B` fails); a record MAC never equals a commit MAC under the same secret.

### Derived MAC vectors (not published upstream)

Computed for this note with Python's `hmac` from the layout above, using the upstream test inputs and the RFC 9180 shared secret as the key. They are **not** in the reference repository and were **not** checked against the reference implementation, which this research did not run. Treat them as a second opinion for a Rust implementation, and confirm them against `@atproto/space` before calling them golden.

```
shared_secret  = c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8

commit_context = 617470726f746f2d73706163652d7265706f2d7631
                 0030 61743a2f2f6469643a6578616d706c653a73706163652f73706163652f6170702e62736b792e67726f75702f74657374
                 0011 6469643a6578616d706c653a616c696365
                 000d 336b6263713370376164343030
data           = 0101010101010101010101010101010101010101010101010101010101010101
commit_mac     = 5584dd87e3b2d7db59cabb06cc2455486d8d3b446af132761552a85ce3b193d9

record_context = 617470726f746f2d73706163652d7265636f72642d7631
                 0045 61743a2f2f6469643a6578616d706c653a616c6963652f73706163652f6170702e62736b792e67726f75702f746573742f6170702e62736b792e666565642e706f73742f31
cid_bytes(A)   = 017112206428f02304b8db8cb107c89336481f0fead728bf374ca80168d2c71938cefae7
record_mac     = be5b75a64201ea39b341d61934bb6fd8f21cf51f74d89dd0bcf8d06def32da80
```

(Spaces and line breaks in the context hex are for reading only.)

## Commit shape

Source: `packages/space/src/types.ts`, `packages/space/src/repo-commit.ts`, `packages/space/tests/repo-commit.test.ts`; proposal §"Space repos".

```
Commit = { ver: number, repo: DID, space: space ref, rev: string, data: bytes }
```

- `COMMIT_VERSION = 1`.
- `data = sha256(LtHash state)`, 32 bytes.
- There is no `sig`, `ikm`, `mac` or `hash` field. The MAC lives only in the response header.
- Schema validation (`commitSchema`, zod): `ver` is any number, `repo` must be a valid DID, `space` must be a valid space ref, `rev` is any string, `data` is bytes. Neither the length of `data` nor the TID shape of `rev` is checked.
- `verifyCommit(commit, {space, repo, sharedSecret, mac})` returns false, in this order, when `ver !== 1`, `repo` differs from the requested repo, `space` differs from the requested space, or the MAC fails.
- `RepoCommit.matches(commit)` compares the local set-hash digest to `commit.data`. It says nothing about authenticity; verify first.

Fixed inputs in `repo-commit.test.ts`: `ctx = { space: "at://did:example:space/space/app.bsky.group/test", repo: "did:example:alice", rev: "3kbcq3p7ad400" }`, `CID_A`, `CID_B`, and one record `app.bsky.feed.post/1 → CID_A`.

Fixed outputs (2, both shape only): `formatSetHashElement('n.c.a', '1', CID_A)` is `n.c.a/1/bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244`; a commit built from `ctx` has `ver === 1`, the three ctx strings, and a 32-byte `data`. No digest or MAC bytes are pinned for a commit.

Properties asserted (the rest of the file's 22 `it` blocks and two `it.each` tables): set-hash behaviour through `RepoCommit` (empty, add/remove, order independence, path and CID sensitivity, state round-trip, `fromRecords`, `applyOp` create/delete/update, `applyOps`); a MAC under another secret is rejected; a commit for a different `space` or `repo` than requested is rejected; a tampered `space`, `repo`, `rev` or `data` is rejected by the MAC alone; `ver: 2` is rejected even with a valid MAC over it; `matches()` goes false once the repo changes.

### LtHash digests (2 fixed outputs)

Source: `packages/space/src/lthash.ts`, `packages/space/tests/lthash.test.ts`; proposal §"Commit digest".

State: 2048 bytes, read as 1024 little-endian `u16` lanes. An element is expanded with BLAKE3 in XOF mode to 2048 bytes and added or subtracted lane-wise mod 2^16. Element for a record: the UTF-8 bytes of `{collection}/{rkey}/{record_cid}`. Digest: `sha256(state)`.

| Input | Digest |
|---|---|
| empty | `e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad` |
| `add("one")`, `add("two")` | `ae05cb6d224379d9710c290c8529945c5b0e0fde9ead30b9699057ce701c63e7` |

The proposal prints the empty digest too (§"Repo lifecycle") and it is the same value. A state of any length other than 2048 bytes is rejected.

## STAR archive

Source: `packages/star/src/star.ts`, `packages/star/src/bytes-reader.ts`, `packages/star/src/star.test.ts`, `packages/star/tests/interop.test.ts`, `packages/star/tests/interop/{valid,invalid}-star-fixtures.json`; proposal §"Repo serialization". The format's own specification is `https://dasl.ing/star.html`, which this research did not read.

### Framing

```
[ magic | len | meta ] [ 0x01 | len | key | len | value ] ... [ 0x00 ]
```

- **Magic:** `2A 6C 01 00`.
- **`len`:** unsigned varint, 7 bits per byte, least-significant group first, high bit set on every byte but the last. It must be in shortest form: a final byte of `0x00` after the first byte is "non-canonical varint". At most 9 bytes; a tenth is "varint too long".
- **Metadata:** one length-prefixed DRISL map with a string `$type`. It must re-encode to the same bytes, else "metadata is not canonical DRISL". The check exists because the decoder alone accepts some non-canonical forms, such as unsorted map keys.
- **Pairs:** each is a control byte `0x01`, a length-prefixed key, a length-prefixed value. Keys and values are opaque bytes and may be empty.
- **Terminator:** control byte `0x00`. Any byte after it is "unexpected bytes after end of archive". Any control byte other than `0x00` or `0x01` is "invalid control byte: {n}". Input ending early is "unexpected end of archive".
- **Ordering rule:** STAR itself has none. The base format is ordered, not sorted, and allows duplicate keys; two valid interop fixtures say so in their comments. Ordering is a profile rule (below).
- **Limits:** STAR itself has none. `readStar` takes optional `maxMetaLength`, `maxKeyLength`, `maxValueLength`, each defaulting to `Infinity`. A frame is rejected when `length > max`, before its body is read, with "length {n} exceeds limit of {max}". A length exactly at the limit is accepted (`star.test.ts`).
- All errors are `StarParseError`. The reference PDS treats one in a request body as the caller's error.

### Interop fixtures (19 valid, 37 invalid)

Copied unmodified from `microcosm.blue/star` at commit `41bdec1fd1be7f6f30a1f961a01442b2fa2ec3c1` (MIT / Apache-2.0), per `packages/star/tests/interop/README.md`. Each valid fixture is read whole and one byte at a time and must decode to the stated metadata and pairs; `writeStar` over the decoded form must reproduce `star_hex` exactly. Each invalid fixture must throw `StarParseError` under both chunkings.

The fixtures are the vectors; take the two JSON files verbatim rather than this summary. The short ones, in full:

| Valid fixture | `star_hex` |
|---|---|
| minimal: `{"$type": ""}`, no pairs | `2A6C010008A16524747970656000` |
| one empty key / empty value | `2A6C010008A16524747970656001000000` |
| two empty key / empty value pairs | `2A6C010008A16524747970656001000001000000` |
| `{"$type": "abc"}`, no pairs | `2A6C01000BA16524747970656361626300` |
| non-ASCII `$type` (`★`) | `2A6C01000BA165247479706563E2988500` |
| `$type` = `a b/"\u0000` | `2A6C01000EA1652474797065666120622F220000` |
| extra meta key `banana: "loaf"` | `2A6C010017A2652474797065636162636662616E616E61646C6F616600` |
| extra `$`-prefixed meta key `$other: 1` | `2A6C010013A26524747970656361626366246F746865720100` |
| structured meta value `arr: []`, pair `AA → BB` | `2A6C010010A26361727280652474797065636162630101AA01BB00` |
| empty key, value `00` | `2A6C01000BA1652474797065636162630100010000` |
| key `00`, empty value | `2A6C01000BA1652474797065636162630101000000` |
| pairs `AA → BB`, `CCDD → EEFF` | `2A6C01000BA1652474797065636162630101AA01BB0102CCDD02EEFF00` |
| unsorted keys `FF`, `AA` (allowed) | `2A6C01000BA1652474797065636162630101FF000101AA0000` |
| duplicate key `AA` (allowed) | `2A6C01000BA1652474797065636162630101AA01BB0101AA01CC00` |

The other five valid fixtures pin the varint boundary: a 128-byte metadata (prefix `8001`), and a key and a value at 127 bytes (prefix `7F`) and 128 bytes (prefix `8001`), each filled with `0x44`.

The 37 invalid fixtures, by what they pin:

| Group | Count | Examples (`star_hex`) |
|---|---|---|
| Magic | 5 | empty; no magic `08A16524747970656000`; magic only `2A6C0100`; truncated `2A6C01`; fourth byte `01` `2A6C010108A16524747970656000` |
| Metadata content | 9 | zero-length `2A6C01000000`; integer `2A6C0100010100`; array `2A6C0100018000`; no `$type` `2A6C010001A000`; non-string `$type` `2A6C010008A16524747970650100`; non-string map key; duplicate `$type` key; non-canonical key order `2A6C01000BA265247479706560617E6000`; trailing NUL padding inside the frame |
| Metadata length | 5 | truncated prefix `2A6C010080`; too-short prefix; body shorter than prefix; padded prefix `2A6C01008800A16524747970656000`; 10-byte prefix `2A6C010080808080808080808001A16524747970656000` |
| Control and terminator | 6 | control `02` after meta; missing terminator `2A6C010008A165247479706560`; double terminator; non-NUL byte after terminator; padded-varint zero as terminator `2A6C010008A1652474797065608000`; control `02` after a pair |
| Key framing | 6 | key with no value; truncated before, inside, and mid-prefix of a key; padded zero-length key prefix; padded non-zero key prefix `2A6C010008A165247479706560018100AA0000` |
| Value framing | 6 | key present, no value; truncated after, inside, and mid-prefix of a value; padded zero-length value prefix; padded non-zero value prefix `2A6C010008A16524747970656001008100BB00` |

## `atproto-space-repo` profile

Source: `packages/space/src/sync/provider.ts`, `packages/space/src/sync/consumer.ts`, `packages/space/src/types.ts`, `packages/space/tests/sync.test.ts`; proposal §"Repo serialization", §"Archive limits".

- **Metadata:** `{ "$type": "atproto-space-repo", ver, repo, space, rev, data }`, the commit plus its type. In canonical DRISL the map keys sort shortest first, then bytewise, so the encoded order is `rev`, `ver`, `data`, `repo`, `$type`, `space`. That order is my reading of the DRISL rule, not something a test here states.
- **Key:** UTF-8 of `{collection}/{rkey}`. `parseRecordPath` requires exactly one `/`, a valid NSID before it and a valid record key after it.
- **Value:** the record's DRISL bytes. It must decode, and decode to a map. The record's CID is computed over the bytes as received.
- **Ordering:** keys must be in strictly increasing lexicographic byte order. A key less than or equal to its predecessor is "records out of order at {path}", which is also how a duplicate is caught. The writer enforces the same rule and refuses to serialize out-of-order input. A prefix sorts before any longer key that starts with it (`compareBytes`).
- **Completeness:** each record is folded into a running set hash; after the terminator the digest must equal `commit.data`, else "records do not match the commit data". The reader streams, so records it yielded are not trustworthy until the stream ends cleanly.
- **Verification order** in `verifyRepoStar`: parse metadata against the schema; reject `ver !== 1` ("unsupported commit version"); check `repo`, `space` and the commit MAC ("commit failed verification"); then stream records.
- `readRepoStar` does everything except the MAC and the repo/space match. It is for a host importing an account's own repo, which arrives with no MAC.

Limits, `REPO_STAR_LIMITS`:

| Item | Limit |
|---|---|
| Metadata | 64 KiB (65,536 bytes) |
| Each key | 4 KiB (4,096 bytes) |
| Each value | `MAX_RECORD_SIZE` = 1 MiB (1,048,576 bytes) |

`MAX_RECORD_SIZE` is also enforced on write: the reference PDS rejects a space record whose encoding exceeds it (`packages/pds/src/repo/prepare.ts`).

Fixed inputs in `sync.test.ts`: the same `SPACE`, `did:example:alice` and `3kbcq3p7ad400`, and three records in path order, `app.bsky.feed.like/3kbcq3p7ad403 → {subject: "at://x"}`, `app.bsky.feed.post/3kbcq3p7ad401 → {text: "hello"}`, `app.bsky.feed.post/3kbcq3p7ad402 → {text: "world"}`. No archive bytes are pinned. The 33 tests assert: metadata equals `{$type, ...commit}` followed by one pair per record; round-trip; the empty repo; the writer refusing out-of-order records; and rejection of a wrong secret, another author, another space, relabelled metadata, a wrong `$type`, `ver: 2`, a missing record, an extra record, a swapped value, out-of-order records, a duplicate record, an invalid path, metadata over 64 KiB (`/exceeds limit of 65536/`), a path over 4 KiB, a value of `MAX_RECORD_SIZE + 1` rejected before its body is read, and a non-map value. The remaining tests cover oplog catch-up and `verifyRecord`.

## `atproto-space-meta` profile

Source: `packages/space/src/space-meta-archive.ts`, `packages/space/src/space-meta-archive.test.ts`, `packages/space/src/types.ts`; proposal §"Space meta archive".

- **Metadata:** exactly `{ "$type": "atproto-space-meta", "ver": 1, "space": <space ref> }`. `ver` is a literal `1`; anything else, or another `$type`, is "invalid space meta archive metadata: …".
- **Sections,** in this order: `policy`, policy state, writers.
  1. `policy`: one pair with the key `policy`. Required; absence is "missing policy".
  2. Policy state: every key that is neither `policy` nor prefixed `writer/`. Values are whatever the policy defines.
  3. Writers: keys `writer/{did}`. The suffix must be a valid DID, else "invalid DID in writer key: {key}". The value is `{ rev: TID, data: bytes, spaceRev: TID }`; a missing or malformed field is "invalid writer: …".
- **Classification is by key alone** (`sectionOf`): exact match `policy`, then prefix `writer/`, then everything else. A policy-state key can therefore never begin with `writer/`.
- **Ordering:** moving to an earlier section is "section out of order at {key}". Within a section, keys must be in strictly increasing byte order, else "duplicate or out-of-order key: {key}". The comparison resets at each section boundary. A second `policy` pair is caught by the same check.
- **Values:** every value must decode as DRISL to a map, else "invalid cbor at {key}" or "value at {key} is not a map".
- The writer sorts policy state and writers into key order itself. The archive is read whole, not streamed.
- All errors are `SpaceMetaArchiveError`, or `StarParseError` from the framing layer.

Limits, `SPACE_META_STAR_LIMITS`: metadata 64 KiB, each key 4 KiB, each value 1 MiB. The numbers are the same as the repo profile but declared separately.

Fixed inputs in `space-meta-archive.test.ts`:

```
SPACE  = at://did:example:forum/space/com.example.forum/general
POLICY = { $type: "com.example.policy", readAccess: "members" }
MEMBER = { $type: "com.example.member", read: true, write: true }
WRITER = { rev: "3kbcq3p7ad42b", data: 32 bytes of 0x01, spaceRev: "3kbcq3p7ad42c" }
```

Fixed output (1, key order only): serializing an archive whose policy state and writers are given as carol then alice yields the keys

```
policy
com.example.member/did:example:alice
com.example.member/did:example:carol
writer/did:example:alice
writer/did:example:carol
```

No archive bytes are pinned. The other 16 tests: round-trip; an archive with no policy state or writers; and rejection of a missing policy, policy state before the policy, policy state after the writers, a duplicate key, a duplicate policy, out-of-order keys within a section, `writer/bob`, a writer without `spaceRev`, the wrong `$type`, `ver: 2`, metadata over 64 KiB (`/exceeds limit of 65536/`), a key over 4 KiB (`/exceeds limit of 4096/`), a value over 1 MiB (`/exceeds limit of 1048576/`), and a non-map value.

## Every limit, in one place

| Limit | Value | Where |
|---|---|---|
| STAR metadata, both profiles | 65,536 bytes | `REPO_STAR_LIMITS`, `SPACE_META_STAR_LIMITS` |
| STAR key, both profiles | 4,096 bytes | same |
| STAR value, both profiles | 1,048,576 bytes | same |
| Space record encoding | 1,048,576 bytes | `MAX_RECORD_SIZE` |
| STAR length varint | 9 bytes, shortest form | `MAX_VARINT_BYTES` |
| MAC-context string field (`space`, `repo`, `rev`, `uri`) | 65,535 bytes | `uint16be` |
| LtHash state | exactly 2,048 bytes | `LTHASH_STATE_BYTES` |
| Commit `data`, shared secret, MAC | 32 bytes each | produced at this size; not validated on parse |
| KEM key | P-256 only; 65-byte uncompressed point in the HKDF info | `p256KeyBytes` |
| Commit version, record-MAC version, space-meta version | `1` | `COMMIT_VERSION`, `RECORD_MAC_VERSION`, `SPACE_META_VERSION` |

All size limits reject only when strictly exceeded.

## Code versus proposal

No byte layout, label, header example, digest or limit differs. The differences are these.

1. **Record values are not checked for canonical encoding.** The proposal says each value is "the record's canonical DRISL encoding" and that readers MUST reject on a parse error. The code checks canonical form only for the metadata (`parseMeta` in `star.ts` re-encodes and compares). Record values in `verifyStarRecords`, and every value in `readSpaceMetaStar`, are decoded and checked to be maps, nothing more. The `star.ts` comment says the decoder accepts some non-canonical forms. So a non-canonical record value would pass, with its CID taken over the bytes as sent. I read this from the code; I did not construct such an archive to confirm it.
2. **Unknown policies and unknown policy-state keys.** The proposal says the importing host MUST reject a policy it does not implement (`UnsupportedPolicy`) and a policy-state key it does not recognise. `readSpaceMetaStar` does neither: it returns any `policy` map and any non-`policy`, non-`writer/` key. The error name exists in `packages/pds/src/space-policy/policy.ts`, so the PDS layer may enforce it; I did not trace that path.
3. **Policy-state key shape.** The proposal says the keys are "structured like repository keys (e.g. `{NSID}/{rkey}`)". The code does not validate their shape at all.
4. **Commit `rev`.** The proposal types it as a TID. `commitSchema` accepts any string. Writer entries in the space-meta archive, by contrast, do require TIDs for `rev` and `spaceRev`.
5. **Archive limits.** The proposal calls them an operational best practice that "may be raised" and says readers "may reject". The code rejects unconditionally.
6. **Repeated header lines.** The proposal says only that a malformed header is an error. The code rejects a header that arrives as more than one line, which RFC 9651 would allow a recipient to combine.
7. **Header strictness the proposal does not spell out.** The code ignores unknown dictionary members and all parameters, and does not check the MAC's length when parsing. Whether `ver=1.0` (a Decimal) passes depends on how `structured-headers` represents it; I did not check.
8. **The ticket's file layout,** not the proposal's: STAR lives in `packages/star`, and its interop fixtures come from a third-party repository.

The proposal's requirement that a syncer use a fresh keypair per request, retry and page is a caller obligation; `encapsulate` generates one per call, and nothing in the package enforces the rest.

## What this means for `crates/crypto/src/space.rs`

The module's header comment says it is pinned to the reference vectors in `packages/space/tests/`. That is still true for the set hash and no longer true for the commit.

### Survives unchanged

| Item | Why |
|---|---|
| `LtHash` (`new`, `from_state`, `add`, `remove`, `state`, `digest`, `is_empty`) | Same construction at the pin: 1024 little-endian `u16` lanes, BLAKE3 XOF to 2048 bytes, `sha256(state)`. |
| `LTHASH_STATE_BYTES` | Still 2048. |
| `format_set_hash_element` | Still the bare `collection/rkey/cid` concatenation. |
| Test `golden_empty_digest` (`e5a00aa9…83ad`) | Identical in `lthash.test.ts` and in the proposal. |
| Test `golden_one_two_digest` (`ae05cb6d…63e7`) | Identical in `lthash.test.ts`. |
| The other LtHash and element tests (`starts_as_zero_state` through `element_distinguishes_paths_and_cids`) | Property tests of the surviving code. |
| `SPACE_COMMIT_VERSION = 1` | The value survives. Its doc comment points at `SignedSpaceCommit::ver` and needs a new home. |

### Obsolete

The pin has no signed commit. A commit is `{ver, repo, space, rev, data}` and is authenticated per request by a MAC keyed from the KEM secret.

| Item | Replaced by |
|---|---|
| `CTX_DOMAIN` (`"atproto-space-v1"`) | The tags `atproto-space-repo-v1` and `atproto-space-record-v1`. |
| `SpaceCommitCtx` (`space`, `author`, `rev`) | The commit itself; `author` is now the commit's `repo` field. |
| `SignedSpaceCommit` (`ver`, `hash`, `ikm`, `sig`, `mac`, `rev`) | `{ver, repo, space, rev, data}`. `hash` becomes `data`; `ikm`, `sig` and `mac` are gone from the stored and serialized commit. |
| `encode_space_commit_ctx` | The commit MAC context. The `u16be` length-prefix technique carries over, but the tag differs, the fields are space, repo, rev with no `ikm`, and `data` is the HMAC message rather than outside the context. |
| `commit_mac` (HKDF-Expand from `ikm`, then HMAC over `hash`) | `HMAC-SHA256(shared_secret, context || data)` with no HKDF step at this layer. HKDF moves into the KEM, as full extract-then-expand. |
| `sign_space_commit` | Nothing. There is no ECDSA signature; the host needs a KEM decapsulation and a MAC instead. |
| `verify_space_commit` | The equivalent of `verifyCommit`: version, repo, space, then a constant-time MAC check. The current comment arguing that a constant-time compare is unnecessary no longer holds, because the key is now a secret. |
| Tests `ctx_is_length_prefixed_and_domain_separated`, `ctx_is_unambiguous_across_field_boundaries`, `ctx_is_deterministic`, `ctx_rejects_oversized_field` | Equivalents over the new context. |
| Tests `produces_a_well_formed_commit`, `verifies_own_commit`, `fresh_ikm_per_commit_for_deniability`, `rejects_signature_from_a_different_key`, `does_not_verify_under_a_different_ctx`, `does_not_verify_a_tampered_hash`, `rejects_rev_disagreeing_with_ctx`, `rejects_unknown_commit_version` | Equivalents of the upstream MAC and `verifyCommit` properties. |
| The imports `p256::ecdsa`, `rand_core`, `DidKeyUri`, `verify_did_key_signature`, and the expand-only use of `hkdf` | Unused in this module once the above goes. |

The obsolete items are re-exported from `crates/crypto/src/lib.rs` and used outside the crate. Files that name `sign_space_commit`, `verify_space_commit` or `SignedSpaceCommit`: `crates/custos-core/src/auth/signing_key.rs`, `crates/custos-spaces/src/routes/space_get_repo.rs`, `crates/custos-spaces/src/views.rs`, `crates/custos-spaces/src/routes/space_routes_test.rs`, `crates/custos-spaces/src/routes/space_sync_routes_test.rs`, and `crates/crypto/AGENTS.md`.

### New, with no counterpart today

- KEM `encapsulate` / `decapsulate` giving the 32-byte shared secret, pinned by the RFC 9180 §A.3.1 vector. `crates/crypto/src/hpke.rs` already uses the `hpke` crate's `DhP256HkdfSha256` for notifications, but only through seal and open. Whether that crate exposes the bare KEM shared secret I did not check; the workspace `p256` dependency does not enable the `ecdh` feature.
- Commit MAC and record MAC.
- The two header formatters and parsers. The root `Cargo.toml` names no structured-fields crate (a grep for `sfv` and `structured` finds nothing).
- A STAR reader and writer with the two profiles and their limits. A grep of `crates/` for the STAR magic bytes and for the strings `atproto-space-repo` and `atproto-space-meta` finds nothing. `crates/custos-spaces/src/routes/space_get_repo.rs` builds a CAR v1 stream today.

## Not verified

- Nothing from the reference repository was executed. Every expected value above is as written in a test file, not observed.
- The two derived MAC vectors were computed independently and never compared with the reference implementation.
- `https://dasl.ing/star.html` was not read; STAR's rules here are the reference code's and the proposal's.
- The canonical DRISL key order given for the repo metadata is derived from the encoding rule, not from a fixture.
- Whether the reference decoder really accepts a non-canonical record value (disagreement 1) and how `structured-headers` treats `ver=1.0` (disagreement 7) were reasoned from source, not tested.
- The reference PDS's handling of unsupported policies on import (disagreement 2) was not traced.
- The interop fixtures were not compared with their stated upstream at `microcosm.blue/star`.
