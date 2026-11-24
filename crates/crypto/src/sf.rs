// pattern: Functional Core

//! RFC 9651 structured fields: the Dictionary, Inner List, and Item grammar that RFC 9421's
//! `Signature-Input`, `Signature`, and `Accept-Signature` fields — and the Spaces
//! `Atproto-Space-Commit` / `Atproto-Space-Record` headers a MAC covers — are written in.
//!
//! Parsing follows RFC 9651 §4.2; serialization follows §4.1 and is canonical, which is what
//! an `sf`-flagged covered component is signed over (RFC 9421 §2.1.1). Dictionaries and
//! parameters keep insertion order, and a repeated key overwrites the earlier value in place.
//!
//! ponytail: Decimal, Date, and Display String bare items are rejected as unparseable — no
//! Spaces or RFC 9421 field this crate reads uses them. Add them when one does.

use base64::{
    alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
    Engine,
};

use crate::error::CryptoError;

/// A bare item (RFC 9651 §3.3), minus the variants noted in the module doc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BareItem {
    Integer(i64),
    String(String),
    Token(String),
    Bytes(Vec<u8>),
    Boolean(bool),
}

/// Ordered key/value parameters; a key appears at most once.
pub type Params = Vec<(String, BareItem)>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub bare: BareItem,
    pub params: Params,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerList {
    pub items: Vec<Item>,
    pub params: Params,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Member {
    Item(Item),
    InnerList(InnerList),
}

/// Ordered dictionary members; a key appears at most once.
pub type Dictionary = Vec<(String, Member)>;

const MAX_INTEGER: i64 = 999_999_999_999_999;

impl Item {
    pub fn new(bare: BareItem) -> Self {
        Item {
            bare,
            params: Vec::new(),
        }
    }
}

/// The value of parameter `key`, if present.
pub fn param<'a>(params: &'a Params, key: &str) -> Option<&'a BareItem> {
    params.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn upsert<V>(entries: &mut Vec<(String, V)>, key: String, value: V) {
    match entries.iter_mut().find(|(k, _)| *k == key) {
        Some(slot) => slot.1 = value,
        None => entries.push((key, value)),
    }
}

fn err(what: &str) -> CryptoError {
    CryptoError::Space(format!("malformed structured field: {what}"))
}

// ── Parsing ───────────────────────────────────────────────────────────────────────────

/// Parse a Dictionary field value (RFC 9651 §4.2.2).
pub fn parse_dictionary(input: &str) -> Result<Dictionary, CryptoError> {
    let mut p = Parser::new(input);
    p.skip_sp();
    let mut dict = Dictionary::new();
    while !p.done() {
        let key = p.key()?;
        let member = if p.eat(b'=') {
            p.item_or_inner_list()?
        } else {
            Member::Item(Item {
                bare: BareItem::Boolean(true),
                params: p.params()?,
            })
        };
        upsert(&mut dict, key, member);
        p.skip_ows();
        if p.done() {
            break;
        }
        if !p.eat(b',') {
            return Err(err("expected ',' between dictionary members"));
        }
        p.skip_ows();
        if p.done() {
            return Err(err("trailing ','"));
        }
    }
    Ok(dict)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        // Trailing SP is discarded before parsing (§4.2 step 2-3).
        Parser {
            s: input.trim_end_matches(' ').as_bytes(),
            i: 0,
        }
    }

    fn done(&self) -> bool {
        self.i >= self.s.len()
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn skip_sp(&mut self) {
        while self.eat(b' ') {}
    }

    fn skip_ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.i += 1;
        }
    }

    fn item_or_inner_list(&mut self) -> Result<Member, CryptoError> {
        if self.peek() == Some(b'(') {
            self.inner_list().map(Member::InnerList)
        } else {
            self.item().map(Member::Item)
        }
    }

    fn inner_list(&mut self) -> Result<InnerList, CryptoError> {
        self.eat(b'(');
        let mut items = Vec::new();
        loop {
            self.skip_sp();
            if self.eat(b')') {
                return Ok(InnerList {
                    items,
                    params: self.params()?,
                });
            }
            if self.done() {
                return Err(err("unterminated inner list"));
            }
            items.push(self.item()?);
            if !matches!(self.peek(), Some(b' ' | b')')) {
                return Err(err("expected ' ' or ')' in inner list"));
            }
        }
    }

    fn item(&mut self) -> Result<Item, CryptoError> {
        Ok(Item {
            bare: self.bare_item()?,
            params: self.params()?,
        })
    }

    fn params(&mut self) -> Result<Params, CryptoError> {
        let mut params = Params::new();
        while self.eat(b';') {
            self.skip_sp();
            let key = self.key()?;
            let value = if self.eat(b'=') {
                self.bare_item()?
            } else {
                BareItem::Boolean(true)
            };
            upsert(&mut params, key, value);
        }
        Ok(params)
    }

    fn key(&mut self) -> Result<String, CryptoError> {
        let start = self.i;
        match self.peek() {
            Some(b'a'..=b'z' | b'*') => self.i += 1,
            _ => return Err(err("expected a key")),
        }
        while matches!(
            self.peek(),
            Some(b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b'*')
        ) {
            self.i += 1;
        }
        Ok(self.slice(start))
    }

    fn slice(&self, start: usize) -> String {
        // Every byte accepted by the grammar is ASCII, so this never replaces anything.
        String::from_utf8_lossy(&self.s[start..self.i]).into_owned()
    }

    fn bare_item(&mut self) -> Result<BareItem, CryptoError> {
        match self.peek() {
            Some(b'-' | b'0'..=b'9') => self.integer(),
            Some(b'"') => self.string(),
            Some(b'*' | b'A'..=b'Z' | b'a'..=b'z') => Ok(self.token()),
            Some(b':') => self.bytes(),
            Some(b'?') => self.boolean(),
            _ => Err(err("unsupported or missing bare item")),
        }
    }

    fn integer(&mut self) -> Result<BareItem, CryptoError> {
        let negative = self.eat(b'-');
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        let digits = self.i - start;
        if digits == 0 || digits > 15 {
            return Err(err("integer must have 1 to 15 digits"));
        }
        if self.peek() == Some(b'.') {
            return Err(err("decimals are not supported"));
        }
        let n: i64 = self.slice(start).parse().map_err(|_| err("integer"))?;
        Ok(BareItem::Integer(if negative { -n } else { n }))
    }

    fn string(&mut self) -> Result<BareItem, CryptoError> {
        self.eat(b'"');
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err(err("unterminated string")),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(BareItem::String(out));
                }
                Some(b'\\') => {
                    self.i += 1;
                    match self.peek() {
                        Some(c @ (b'"' | b'\\')) => {
                            out.push(char::from(c));
                            self.i += 1;
                        }
                        _ => return Err(err("invalid string escape")),
                    }
                }
                Some(c @ 0x20..=0x7e) => {
                    out.push(char::from(c));
                    self.i += 1;
                }
                Some(_) => return Err(err("string character out of range")),
            }
        }
    }

    fn token(&mut self) -> BareItem {
        let start = self.i;
        self.i += 1;
        while matches!(self.peek(), Some(c) if is_tchar(c) || c == b':' || c == b'/') {
            self.i += 1;
        }
        BareItem::Token(self.slice(start))
    }

    fn bytes(&mut self) -> Result<BareItem, CryptoError> {
        self.eat(b':');
        let start = self.i;
        while matches!(self.peek(), Some(c) if c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'='))
        {
            self.i += 1;
        }
        let encoded = self.slice(start);
        if !self.eat(b':') {
            return Err(err("unterminated byte sequence"));
        }
        BASE64_LENIENT
            .decode(encoded)
            .map(BareItem::Bytes)
            .map_err(|_| err("byte sequence is not base64"))
    }

    fn boolean(&mut self) -> Result<BareItem, CryptoError> {
        self.eat(b'?');
        let value = match self.peek() {
            Some(b'1') => true,
            Some(b'0') => false,
            _ => return Err(err("boolean must be ?0 or ?1")),
        };
        self.i += 1;
        Ok(BareItem::Boolean(value))
    }
}

/// §4.2.7: parsers accept a byte sequence with or without `=` padding.
const BASE64_LENIENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

fn is_tchar(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

// ── Serialization ─────────────────────────────────────────────────────────────────────

/// Serialize a Dictionary (RFC 9651 §4.1.2).
pub fn serialize_dictionary(dict: &Dictionary) -> Result<String, CryptoError> {
    let mut out = Vec::with_capacity(dict.len());
    for (key, member) in dict {
        let mut s = serialize_key(key)?;
        match member {
            Member::Item(Item {
                bare: BareItem::Boolean(true),
                params,
            }) => s.push_str(&serialize_params(params)?),
            Member::Item(item) => {
                s.push('=');
                s.push_str(&serialize_item(item)?);
            }
            Member::InnerList(list) => {
                s.push('=');
                s.push_str(&serialize_inner_list(list)?);
            }
        }
        out.push(s);
    }
    Ok(out.join(", "))
}

/// Serialize an Inner List with its parameters (RFC 9651 §4.1.1.1).
pub fn serialize_inner_list(list: &InnerList) -> Result<String, CryptoError> {
    let items = list
        .items
        .iter()
        .map(serialize_item)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(format!(
        "({}){}",
        items.join(" "),
        serialize_params(&list.params)?
    ))
}

/// Serialize an Item with its parameters (RFC 9651 §4.1.3).
pub fn serialize_item(item: &Item) -> Result<String, CryptoError> {
    Ok(format!(
        "{}{}",
        serialize_bare_item(&item.bare)?,
        serialize_params(&item.params)?
    ))
}

fn serialize_params(params: &Params) -> Result<String, CryptoError> {
    let mut out = String::new();
    for (key, value) in params {
        out.push(';');
        out.push_str(&serialize_key(key)?);
        if *value != BareItem::Boolean(true) {
            out.push('=');
            out.push_str(&serialize_bare_item(value)?);
        }
    }
    Ok(out)
}

fn serialize_key(key: &str) -> Result<String, CryptoError> {
    let mut p = Parser::new(key);
    match p.key() {
        Ok(k) if p.done() && k == key => Ok(k),
        _ => Err(err("invalid key")),
    }
}

fn serialize_bare_item(bare: &BareItem) -> Result<String, CryptoError> {
    Ok(match bare {
        BareItem::Integer(n) if n.abs() <= MAX_INTEGER => n.to_string(),
        BareItem::Integer(_) => return Err(err("integer out of range")),
        BareItem::String(s) => {
            let mut out = String::from("\"");
            for c in s.chars() {
                match c {
                    '"' | '\\' => {
                        out.push('\\');
                        out.push(c);
                    }
                    ' '..='~' => out.push(c),
                    _ => return Err(err("string character out of range")),
                }
            }
            out.push('"');
            out
        }
        BareItem::Token(t) => {
            let valid = t.bytes().enumerate().all(|(i, c)| {
                if i == 0 {
                    c == b'*' || c.is_ascii_alphabetic()
                } else {
                    is_tchar(c) || c == b':' || c == b'/'
                }
            });
            if t.is_empty() || !valid {
                return Err(err("invalid token"));
            }
            t.clone()
        }
        BareItem::Bytes(b) => format!(":{}:", base64::engine::general_purpose::STANDARD.encode(b)),
        BareItem::Boolean(b) => if *b { "?1" } else { "?0" }.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(input: &str) -> String {
        serialize_dictionary(&parse_dictionary(input).unwrap()).unwrap()
    }

    #[test]
    fn round_trips_the_reference_header_grammar() {
        // Every shape the reference's `mac.ts` / `http-signature.ts` emit, already canonical.
        for canonical in [
            r#"mac=("atproto-space-commit";sf);keyid="did:key:zDnaExample";tag="atproto-space-commit""#,
            r#"sig=("authorization" "atproto-space-audience");tag="atproto-space-credential""#,
            r#"sig1=:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:"#,
            r#"ver=1, repo="did:example:alice", space="at://did:example:space/space/app.bsky.group/test", rev="3kbcq3p7ad400", data=:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:"#,
            r#"uri="at://did:example:space/space/app.bsky.group/test/did:example:alice/app.bsky.feed.post/1", cid="bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244""#,
            r#"m=("atproto-space-commit";sf);tag="atproto-space-commit";created=1700000000;keyid="k""#,
            r#"a=?0, b, c;x=tok/en:1, d=-42, e=("a\"b\\c" ?1);p, f=()"#,
        ] {
            assert_eq!(round_trip(canonical), canonical);
        }
    }

    #[test]
    fn canonicalizes_insignificant_whitespace_and_padding() {
        assert_eq!(round_trip("  a=1,   b=2\t,c=3  "), "a=1, b=2, c=3");
        assert_eq!(round_trip("a=(  1   2 )"), "a=(1 2)");
        assert_eq!(round_trip("a=:YWJj:, b=:YQ:"), "a=:YWJj:, b=:YQ==:");
    }

    #[test]
    fn a_repeated_key_overwrites_in_place() {
        assert_eq!(round_trip("a=1, b=2, a=3"), "a=3, b=2");
        assert_eq!(round_trip("a;x=1;y;x=2"), "a;x=2;y");
    }

    #[test]
    fn parses_values_and_parameters() {
        let dict = parse_dictionary(r#"mac=("h";sf);keyid="k";tag="t""#).unwrap();
        let [(label, Member::InnerList(list))] = dict.as_slice() else {
            panic!("one inner-list member");
        };
        assert_eq!(label, "mac");
        assert_eq!(list.items[0].bare, BareItem::String("h".into()));
        assert_eq!(
            param(&list.items[0].params, "sf"),
            Some(&BareItem::Boolean(true))
        );
        assert_eq!(
            param(&list.params, "tag"),
            Some(&BareItem::String("t".into()))
        );
    }

    #[test]
    fn rejects_malformed_input() {
        for bad in [
            r#"sig=("authorization""#,
            "???",
            "a=1,",
            "a=1 b=2",
            "A=1",
            "a=\"unterminated",
            r#"a="bad\escape""#,
            "a=:not base64:",
            "a=:YWJj",
            "a=?2",
            "a=1.5",
            "a=1234567890123456",
            "a=(1 2",
            "a=(1;)",
        ] {
            assert!(parse_dictionary(bad).is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn refuses_to_serialize_what_cannot_be_parsed_back() {
        let item = |bare| vec![("a".to_string(), Member::Item(Item::new(bare)))];
        assert!(serialize_dictionary(&item(BareItem::String("é".into()))).is_err());
        assert!(serialize_dictionary(&item(BareItem::Token("1x".into()))).is_err());
        assert!(serialize_dictionary(&item(BareItem::Integer(MAX_INTEGER + 1))).is_err());
        let bad_key = vec![(
            "Bad".to_string(),
            Member::Item(Item::new(BareItem::Integer(1))),
        )];
        assert!(serialize_dictionary(&bad_key).is_err());
    }
}
