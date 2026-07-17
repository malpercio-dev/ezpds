// pattern: Functional Core
//
// Typed model of the vendored lexicon documents (`crates/pds/lexicons/`) plus a strict parser.
//
// The parser is deliberately hand-rolled over an order-preserving JSON value rather than
// serde-derived, for two reasons:
//
// 1. **Property order matters.** The reference validator (`@atproto/lexicon`) iterates an
//    object's `properties` in document order, so which violation is reported first (e.g. a
//    body missing both `identifier` and `password`) follows the lexicon's declaration order.
//    `serde_json::Map` is a BTreeMap (alphabetical) unless the crate-wide `preserve_order`
//    feature is enabled — which would silently change JSON object ordering everywhere else in
//    the workspace — so we parse into our own ordered value instead.
//
// 2. **Unknown constructs must fail loudly.** Every schema node checks its keys against an
//    allowlist and every `type` against the constructs this validator implements. If a future
//    re-vendoring introduces a constraint we don't enforce (say `minLength` or a new string
//    format), parsing fails — surfaced by the registry unit tests — instead of the constraint
//    being silently skipped and Custos drifting laxer than the reference again — the
//    input-strictness failure mode this module exists to prevent.

use std::fmt;

use serde::de::{Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;

// ── Order-preserving JSON value ──────────────────────────────────────────────

/// A JSON value whose objects preserve document key order, unlike `serde_json::Value`.
/// Only used at registry-build time to parse the vendored lexicon documents; request bodies
/// are still `serde_json::Value` (body key order is irrelevant to validation).
#[derive(Debug, Clone)]
pub enum OrderedValue {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<OrderedValue>),
    Object(Vec<(String, OrderedValue)>),
}

impl<'de> Deserialize<'de> for OrderedValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;

        impl<'de> Visitor<'de> for V {
            type Value = OrderedValue;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("any JSON value")
            }

            fn visit_bool<E>(self, v: bool) -> Result<OrderedValue, E> {
                Ok(OrderedValue::Bool(v))
            }
            fn visit_i64<E>(self, v: i64) -> Result<OrderedValue, E> {
                Ok(OrderedValue::Number(v.into()))
            }
            fn visit_u64<E>(self, v: u64) -> Result<OrderedValue, E> {
                Ok(OrderedValue::Number(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<OrderedValue, E> {
                serde_json::Number::from_f64(v)
                    .map(OrderedValue::Number)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }
            fn visit_str<E>(self, v: &str) -> Result<OrderedValue, E> {
                Ok(OrderedValue::String(v.to_owned()))
            }
            fn visit_string<E>(self, v: String) -> Result<OrderedValue, E> {
                Ok(OrderedValue::String(v))
            }
            fn visit_unit<E>(self) -> Result<OrderedValue, E> {
                Ok(OrderedValue::Null)
            }
            fn visit_none<E>(self) -> Result<OrderedValue, E> {
                Ok(OrderedValue::Null)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<OrderedValue, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(OrderedValue::Array(items))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<OrderedValue, A::Error> {
                let mut entries = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, OrderedValue>()? {
                    entries.push((key, value));
                }
                Ok(OrderedValue::Object(entries))
            }
        }

        deserializer.deserialize_any(V)
    }
}

impl OrderedValue {
    fn type_name(&self) -> &'static str {
        match self {
            OrderedValue::Null => "null",
            OrderedValue::Bool(_) => "boolean",
            OrderedValue::Number(_) => "number",
            OrderedValue::String(_) => "string",
            OrderedValue::Array(_) => "array",
            OrderedValue::Object(_) => "object",
        }
    }
}

// ── Typed lexicon model ──────────────────────────────────────────────────────

/// One parsed lexicon document: its NSID and every definition, in document order.
pub struct LexiconDoc {
    pub id: String,
    pub defs: Vec<(String, LexDef)>,
}

/// A top-level definition. Only the def types present in the vendored set are modeled; a new
/// def type (query, subscription, …) fails parsing until support is added deliberately.
pub enum LexDef {
    Procedure(LexProcedure),
    /// A `record` def (`app.bsky.feed.post`, …): the record-key discipline plus the object
    /// schema the record body must satisfy. Only ever the `main` def of a document.
    Record(LexRecord),
    /// Any other top-level def stored for cross-document `ref`/`union` resolution — an `object`
    /// (`#replyRef`), a bare `string` def (`app.bsky.graph.defs#listPurpose`), a `token`, etc.
    Schema(LexSchema),
}

pub struct LexProcedure {
    /// Absent for no-input procedures (which `NoInputBody` guards instead).
    pub input: Option<LexXrpcBody>,
}

pub struct LexXrpcBody {
    pub encoding: String,
    pub schema: Option<LexSchema>,
}

/// A `record` definition: the `key` discipline (`tid`, `literal:self`, …) the record key must
/// satisfy and the object `record` body schema, mirroring `@atproto/lexicon`'s record def.
pub struct LexRecord {
    pub key: String,
    pub record: LexSchema,
}

pub struct LexObject {
    pub required: Vec<String>,
    pub nullable: Vec<String>,
    /// Document order — the reference reports the first violating property in this order.
    pub properties: Vec<(String, LexSchema)>,
}

/// A validatable schema node. Field constraints are modeled only where the vendored documents
/// use them; anything else fails parsing (see the module comment).
pub enum LexSchema {
    Object(LexObject),
    String {
        format: Option<StringFormat>,
        /// Minimum length in UTF-8 bytes (the reference counts `utf8Len`).
        min_length: Option<u64>,
        /// Maximum length in UTF-8 bytes (the reference counts `utf8Len`, despite the error
        /// message saying "characters").
        max_length: Option<u64>,
        /// Maximum length in extended grapheme clusters (`@atproto/lexicon`'s `graphemeLen`).
        max_graphemes: Option<u64>,
        has_default: bool,
    },
    Boolean {
        /// A `const` fixes the only accepted value (view flags like `notFound: true`).
        const_value: Option<bool>,
        has_default: bool,
    },
    Integer {
        minimum: Option<i64>,
        maximum: Option<i64>,
        /// Whether the lexicon declares a `default`. The reference applies primitive defaults
        /// during validation, so an absent value with a default satisfies even a `required`
        /// property (`createInviteCodes.codeCount`); the default's value itself never matters
        /// for input validation.
        has_default: bool,
    },
    /// `unknown`: any JSON object (the reference rejects non-objects).
    Unknown,
    /// A `blob` ref. `accept`/`maxSize` are parsed but not enforced here: the reference checks
    /// them against the *uploaded blob's* metadata at ingestion, not against the record schema.
    Blob,
    /// `bytes`: lex-JSON `{ "$bytes": "<base64>" }`. No length bounds are used by the vendored
    /// record closure, so none are modeled.
    Bytes,
    /// A `token` def: a bare marker identifier. Nothing in the vendored record closure `ref`s a
    /// token (they appear only as advisory `knownValues`), so a value is never validated against
    /// one; it is modeled solely so the def parses and resolves.
    Token,
    Array {
        items: Box<LexSchema>,
        min_length: Option<u64>,
        max_length: Option<u64>,
    },
    Ref {
        /// Fully qualified by the registry after parsing: `lex:<nsid>#<def>`.
        target: String,
    },
    Union {
        /// Fully qualified by the registry after parsing (the reference does the same when a
        /// document is added, which is why its closed-union error prints `lex:`-prefixed refs).
        refs: Vec<String>,
        closed: bool,
    },
}

impl LexSchema {
    /// Whether an absent value is filled by a declared `default` — which satisfies `required`,
    /// because the reference applies primitive defaults inside validation.
    pub fn has_default(&self) -> bool {
        matches!(
            self,
            LexSchema::Integer {
                has_default: true,
                ..
            } | LexSchema::String {
                has_default: true,
                ..
            } | LexSchema::Boolean {
                has_default: true,
                ..
            }
        )
    }
}

/// The string formats the validator implements (`formats.rs`), which are exactly the formats
/// the vendored documents use. A document using any other format fails parsing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StringFormat {
    AtIdentifier,
    AtUri,
    Cid,
    Datetime,
    Did,
    Handle,
    Language,
    Nsid,
    RecordKey,
    Uri,
}

impl StringFormat {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "at-identifier" => Self::AtIdentifier,
            "at-uri" => Self::AtUri,
            "cid" => Self::Cid,
            "datetime" => Self::Datetime,
            "did" => Self::Did,
            "handle" => Self::Handle,
            "language" => Self::Language,
            "nsid" => Self::Nsid,
            "record-key" => Self::RecordKey,
            "uri" => Self::Uri,
            _ => return None,
        })
    }
}

// ── Parser ───────────────────────────────────────────────────────────────────

/// Object-entry access with an allowlist check: any key outside `allowed` is a parse error,
/// the loud-failure guard against silently skipping a constraint we don't implement.
struct Node<'a> {
    entries: &'a [(String, OrderedValue)],
    context: &'a str,
}

impl<'a> Node<'a> {
    fn from(value: &'a OrderedValue, context: &'a str) -> Result<Self, String> {
        match value {
            OrderedValue::Object(entries) => Ok(Node { entries, context }),
            other => Err(format!(
                "{context}: expected an object, got {}",
                other.type_name()
            )),
        }
    }

    fn check_keys(&self, allowed: &[&str]) -> Result<(), String> {
        for (key, _) in self.entries {
            if !allowed.contains(&key.as_str()) {
                return Err(format!(
                    "{}: unsupported key {key:?} (the validator does not implement it; \
                     extend crates/pds/src/lexicon before vendoring this document)",
                    self.context
                ));
            }
        }
        Ok(())
    }

    fn get(&self, key: &str) -> Option<&'a OrderedValue> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    fn string(&self, key: &str) -> Result<Option<&'a str>, String> {
        match self.get(key) {
            None => Ok(None),
            Some(OrderedValue::String(s)) => Ok(Some(s)),
            Some(other) => Err(format!(
                "{}: {key} must be a string, got {}",
                self.context,
                other.type_name()
            )),
        }
    }

    fn required_string(&self, key: &str) -> Result<&'a str, String> {
        self.string(key)?
            .ok_or_else(|| format!("{}: missing required key {key:?}", self.context))
    }

    fn string_array(&self, key: &str) -> Result<Vec<String>, String> {
        let Some(value) = self.get(key) else {
            return Ok(Vec::new());
        };
        let OrderedValue::Array(items) = value else {
            return Err(format!("{}: {key} must be an array", self.context));
        };
        items
            .iter()
            .map(|item| match item {
                OrderedValue::String(s) => Ok(s.clone()),
                other => Err(format!(
                    "{}: {key} entries must be strings, got {}",
                    self.context,
                    other.type_name()
                )),
            })
            .collect()
    }

    /// An optional non-negative integer constraint (`maxLength`, `maxSize`, `maxGraphemes`, …).
    fn u64_opt(&self, key: &str) -> Result<Option<u64>, String> {
        match self.get(key) {
            None => Ok(None),
            Some(OrderedValue::Number(n)) => n
                .as_u64()
                .map(Some)
                .ok_or_else(|| format!("{}: {key} must be a non-negative integer", self.context)),
            Some(_) => Err(format!("{}: {key} must be a number", self.context)),
        }
    }

    /// An optional signed integer constraint (`minimum`, `maximum`).
    fn i64_opt(&self, key: &str) -> Result<Option<i64>, String> {
        match self.get(key) {
            None => Ok(None),
            Some(OrderedValue::Number(n)) => n
                .as_i64()
                .map(Some)
                .ok_or_else(|| format!("{}: {key} must be an integer", self.context)),
            Some(_) => Err(format!("{}: {key} must be a number", self.context)),
        }
    }
}

/// Parse one vendored lexicon document from its JSON source.
pub fn parse_doc(src: &str) -> Result<LexiconDoc, String> {
    let root: OrderedValue = serde_json::from_str(src)
        .map_err(|e| format!("lexicon document is not valid JSON: {e}"))?;
    let doc = Node::from(&root, "document")?;
    doc.check_keys(&["lexicon", "id", "description", "defs"])?;
    match doc.get("lexicon") {
        Some(OrderedValue::Number(n)) if n.as_u64() == Some(1) => {}
        _ => return Err("document: `lexicon` must be the number 1".into()),
    }
    let id = doc.required_string("id")?.to_owned();

    let defs_value = doc
        .get("defs")
        .ok_or_else(|| format!("{id}: missing `defs`"))?;
    let OrderedValue::Object(def_entries) = defs_value else {
        return Err(format!("{id}: `defs` must be an object"));
    };

    let mut defs = Vec::new();
    for (name, def_value) in def_entries {
        let context = format!("{id}#{name}");
        defs.push((name.clone(), parse_def(def_value, &context)?));
    }
    Ok(LexiconDoc { id, defs })
}

fn parse_def(value: &OrderedValue, context: &str) -> Result<LexDef, String> {
    let node = Node::from(value, context)?;
    match node.required_string("type")? {
        "procedure" => {
            node.check_keys(&["type", "description", "input", "output", "errors"])?;
            let input = match node.get("input") {
                None => None,
                Some(input_value) => {
                    let input_context = format!("{context} input");
                    let input = Node::from(input_value, &input_context)?;
                    input.check_keys(&["encoding", "schema", "description"])?;
                    let encoding = input.required_string("encoding")?.to_owned();
                    let schema = match input.get("schema") {
                        None => None,
                        Some(schema_value) => Some(parse_schema(
                            schema_value,
                            &format!("{context} input schema"),
                        )?),
                    };
                    Some(LexXrpcBody { encoding, schema })
                }
            };
            Ok(LexDef::Procedure(LexProcedure { input }))
        }
        "record" => {
            node.check_keys(&["type", "description", "key", "record"])?;
            let key = node.required_string("key")?.to_owned();
            let record_value = node
                .get("record")
                .ok_or_else(|| format!("{context}: record def is missing `record`"))?;
            let record = parse_schema(record_value, &format!("{context} record"))?;
            if !matches!(record, LexSchema::Object(_)) {
                return Err(format!("{context}: a record's `record` must be an object"));
            }
            Ok(LexDef::Record(LexRecord { key, record }))
        }
        // Every other top-level def (`object`, a bare `string`, a `token`, …) is a schema stored
        // for `ref`/`union` resolution. `parse_schema` rejects any construct we don't implement.
        _ => Ok(LexDef::Schema(parse_schema(value, context)?)),
    }
}

fn parse_object(node: &Node, context: &str) -> Result<LexObject, String> {
    node.check_keys(&["type", "description", "required", "nullable", "properties"])?;
    let required = node.string_array("required")?;
    let nullable = node.string_array("nullable")?;

    let mut properties = Vec::new();
    if let Some(props_value) = node.get("properties") {
        let OrderedValue::Object(entries) = props_value else {
            return Err(format!("{context}: `properties` must be an object"));
        };
        for (name, prop_value) in entries {
            let prop_context = format!("{context}/{name}");
            properties.push((name.clone(), parse_schema(prop_value, &prop_context)?));
        }
    }
    Ok(LexObject {
        required,
        nullable,
        properties,
    })
}

fn parse_schema(value: &OrderedValue, context: &str) -> Result<LexSchema, String> {
    let node = Node::from(value, context)?;
    match node.required_string("type")? {
        "object" => Ok(LexSchema::Object(parse_object(&node, context)?)),
        "string" => {
            // `knownValues` is advisory (the reference does not enforce it), so it is accepted
            // and ignored rather than treated as an unimplemented constraint. `default` is
            // presence-only: an absent value with a default satisfies `required` (like `integer`).
            node.check_keys(&[
                "type",
                "description",
                "format",
                "minLength",
                "maxLength",
                "maxGraphemes",
                "knownValues",
                "default",
            ])?;
            let format = match node.string("format")? {
                None => None,
                Some(name) => Some(StringFormat::parse(name).ok_or_else(|| {
                    format!(
                        "{context}: unsupported string format {name:?} \
                         (extend crates/pds/src/lexicon/formats.rs before vendoring this document)"
                    )
                })?),
            };
            Ok(LexSchema::String {
                format,
                min_length: node.u64_opt("minLength")?,
                max_length: node.u64_opt("maxLength")?,
                max_graphemes: node.u64_opt("maxGraphemes")?,
                has_default: node.get("default").is_some(),
            })
        }
        "boolean" => {
            node.check_keys(&["type", "description", "const", "default"])?;
            let const_value = match node.get("const") {
                None => None,
                Some(OrderedValue::Bool(b)) => Some(*b),
                Some(_) => return Err(format!("{context}: const must be a boolean")),
            };
            Ok(LexSchema::Boolean {
                const_value,
                has_default: node.get("default").is_some(),
            })
        }
        "integer" => {
            node.check_keys(&["type", "description", "minimum", "maximum", "default"])?;
            let has_default = match node.get("default") {
                None => false,
                Some(OrderedValue::Number(n)) if n.is_i64() || n.is_u64() => true,
                Some(_) => return Err(format!("{context}: default must be an integer")),
            };
            Ok(LexSchema::Integer {
                minimum: node.i64_opt("minimum")?,
                maximum: node.i64_opt("maximum")?,
                has_default,
            })
        }
        "unknown" => {
            node.check_keys(&["type", "description"])?;
            Ok(LexSchema::Unknown)
        }
        "blob" => {
            // `accept`/`maxSize` are validated against the uploaded blob's metadata at ingestion,
            // not against the record schema, so they are accepted and ignored here.
            node.check_keys(&["type", "description", "accept", "maxSize"])?;
            Ok(LexSchema::Blob)
        }
        "bytes" => {
            node.check_keys(&["type", "description", "minLength", "maxLength"])?;
            Ok(LexSchema::Bytes)
        }
        "token" => {
            node.check_keys(&["type", "description"])?;
            Ok(LexSchema::Token)
        }
        "array" => {
            node.check_keys(&["type", "description", "items", "minLength", "maxLength"])?;
            let items = node
                .get("items")
                .ok_or_else(|| format!("{context}: array is missing `items`"))?;
            Ok(LexSchema::Array {
                items: Box::new(parse_schema(items, &format!("{context} items"))?),
                min_length: node.u64_opt("minLength")?,
                max_length: node.u64_opt("maxLength")?,
            })
        }
        "ref" => {
            node.check_keys(&["type", "description", "ref"])?;
            Ok(LexSchema::Ref {
                target: node.required_string("ref")?.to_owned(),
            })
        }
        "union" => {
            node.check_keys(&["type", "description", "refs", "closed"])?;
            let refs = node.string_array("refs")?;
            if refs.is_empty() {
                return Err(format!("{context}: union must list at least one ref"));
            }
            let closed = match node.get("closed") {
                None => false,
                Some(OrderedValue::Bool(b)) => *b,
                Some(_) => return Err(format!("{context}: closed must be a boolean")),
            };
            Ok(LexSchema::Union { refs, closed })
        }
        other => Err(format!(
            "{context}: unsupported schema type {other:?} \
             (extend crates/pds/src/lexicon before vendoring this document)"
        )),
    }
}
