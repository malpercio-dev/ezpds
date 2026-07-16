// pattern: Functional Core
//
// The lexicon registry: the vendored `com.atproto.*` lexicon documents (`crates/pds/lexicons/`,
// pinned upstream — see the README there) compiled into the binary and parsed once, plus
// `validate_input`, the single place asserting "this request body conforms to the procedure's
// declared lexicon input". The reference PDS gets this uniformity from `@atproto/xrpc-server`'s
// `validateInput` running on every route; Custos historically hand-parsed each body with a
// bespoke serde struct, so strictness drifted route by route and concealed client bugs — a
// per-route inconsistency this module removes. Handlers consume this through the `LexiconInput` axum
// extractor (`extractor.rs`), or through `validate_procedure_body` where the raw body bytes are
// also needed for signature verification.
//
// Scope: input bodies of the natively-handled JSON procedures. Query-parameter validation,
// output validation, and `validate`-flag record validation are deliberate non-goals for now —
// vendoring the documents is the prerequisite step for all of them.

mod extractor;
mod formats;
mod schema;
mod validate;

use std::collections::HashMap;
use std::sync::LazyLock;

use serde_json::Value;

use schema::{LexDef, LexSchema, LexXrpcBody};

pub use extractor::{validate_procedure_body, LexiconInput};
pub use validate::ValidationError;

/// The vendored lexicon documents. Adding a route with a JSON input body means vendoring its
/// document (plus any documents its refs reach) and listing it here; the registry tests fail on
/// unsupported constructs or dangling refs.
static LEXICON_SOURCES: &[&str] = &[
    include_str!("../../lexicons/com/atproto/admin/defs.json"),
    include_str!("../../lexicons/com/atproto/admin/updateSubjectStatus.json"),
    include_str!("../../lexicons/com/atproto/identity/refreshIdentity.json"),
    include_str!("../../lexicons/com/atproto/identity/signPlcOperation.json"),
    include_str!("../../lexicons/com/atproto/identity/submitPlcOperation.json"),
    include_str!("../../lexicons/com/atproto/identity/updateHandle.json"),
    include_str!("../../lexicons/com/atproto/repo/applyWrites.json"),
    include_str!("../../lexicons/com/atproto/repo/createRecord.json"),
    include_str!("../../lexicons/com/atproto/repo/deleteRecord.json"),
    include_str!("../../lexicons/com/atproto/repo/putRecord.json"),
    include_str!("../../lexicons/com/atproto/repo/strongRef.json"),
    include_str!("../../lexicons/com/atproto/server/confirmEmail.json"),
    include_str!("../../lexicons/com/atproto/server/createAccount.json"),
    include_str!("../../lexicons/com/atproto/server/createAppPassword.json"),
    include_str!("../../lexicons/com/atproto/server/createInviteCode.json"),
    include_str!("../../lexicons/com/atproto/server/createInviteCodes.json"),
    include_str!("../../lexicons/com/atproto/server/createSession.json"),
    include_str!("../../lexicons/com/atproto/server/deactivateAccount.json"),
    include_str!("../../lexicons/com/atproto/server/deleteAccount.json"),
    include_str!("../../lexicons/com/atproto/server/requestPasswordReset.json"),
    include_str!("../../lexicons/com/atproto/server/reserveSigningKey.json"),
    include_str!("../../lexicons/com/atproto/server/resetPassword.json"),
    include_str!("../../lexicons/com/atproto/server/revokeAppPassword.json"),
    include_str!("../../lexicons/com/atproto/server/updateEmail.json"),
];

/// A procedure's declared input body: its encoding and (for JSON inputs) its schema.
pub struct InputDef {
    encoding: String,
    schema: Option<LexSchema>,
}

impl InputDef {
    pub fn encoding(&self) -> &str {
        &self.encoding
    }
}

/// Parsed lexicons, keyed for validation: procedure inputs by NSID, referencable object
/// definitions by fully-qualified `lex:<nsid>#<def>` URI.
pub struct Registry {
    inputs: HashMap<String, InputDef>,
    defs: HashMap<String, LexSchema>,
}

static REGISTRY: LazyLock<Registry> = LazyLock::new(|| {
    // The sources are compile-time constants, so a failure here is a defect in the vendored
    // set or the parser, not a runtime condition — and `tests::registry_builds` turns it into
    // a CI failure long before any request can hit this path.
    Registry::build(LEXICON_SOURCES).expect("vendored lexicon set must build")
});

/// The process-wide registry over the vendored documents.
pub fn registry() -> &'static Registry {
    &REGISTRY
}

impl Registry {
    fn build(sources: &[&str]) -> Result<Self, String> {
        let mut inputs = HashMap::new();
        let mut defs = HashMap::new();

        for source in sources {
            let doc = schema::parse_doc(source)?;
            for (name, def) in doc.defs {
                match def {
                    LexDef::Procedure(procedure) => {
                        if name != "main" {
                            return Err(format!(
                                "{}#{name}: only main procedure definitions are supported",
                                doc.id
                            ));
                        }
                        if let Some(LexXrpcBody { encoding, schema }) = procedure.input {
                            let schema = schema.map(|mut s| {
                                qualify_refs(&mut s, &doc.id);
                                s
                            });
                            inputs.insert(doc.id.clone(), InputDef { encoding, schema });
                        }
                    }
                    LexDef::Object(object) => {
                        let mut schema = LexSchema::Object(object);
                        qualify_refs(&mut schema, &doc.id);
                        defs.insert(format!("lex:{}#{name}", doc.id), schema);
                    }
                }
            }
        }

        let registry = Registry { inputs, defs };
        registry.check_refs()?;
        Ok(registry)
    }

    /// Fail the build on a ref that doesn't resolve within the vendored set, so a dangling ref
    /// is a test failure at vendoring time instead of a 500 at request time.
    fn check_refs(&self) -> Result<(), String> {
        fn walk(registry: &Registry, schema: &LexSchema) -> Result<(), String> {
            match schema {
                LexSchema::Object(object) => {
                    for (_, property) in &object.properties {
                        walk(registry, property)?;
                    }
                    Ok(())
                }
                LexSchema::Array { items } => walk(registry, items),
                LexSchema::Ref { target } => match registry.resolve(target) {
                    Some(resolved) => walk(registry, resolved),
                    None => Err(format!("dangling lexicon ref: {target}")),
                },
                LexSchema::Union { refs, .. } => {
                    for r in refs {
                        // Union members are resolved (and walked) eagerly here even though
                        // validation resolves them lazily per `$type`.
                        match registry.resolve(r) {
                            Some(resolved) => walk(registry, resolved)?,
                            None => return Err(format!("dangling lexicon union ref: {r}")),
                        }
                    }
                    Ok(())
                }
                LexSchema::String { .. }
                | LexSchema::Boolean
                | LexSchema::Integer { .. }
                | LexSchema::Unknown => Ok(()),
            }
        }
        for input in self.inputs.values() {
            if let Some(schema) = &input.schema {
                walk(self, schema)?;
            }
        }
        Ok(())
    }

    /// The declared input of a natively-handled procedure, if its document is vendored.
    pub fn input(&self, nsid: &str) -> Option<&InputDef> {
        self.inputs.get(nsid)
    }

    /// Assert `body` conforms to `nsid`'s declared input schema, rooted at `Input` like the
    /// reference's `assertValidXrpcInput`.
    pub fn validate_input(&self, nsid: &str, body: &Value) -> Result<(), ValidationError> {
        let input = self.input(nsid).ok_or_else(|| {
            ValidationError::Lexicon(format!("no lexicon input is vendored for {nsid}"))
        })?;
        match &input.schema {
            Some(schema) => validate::validate(self, "Input", schema, body),
            None => Ok(()),
        }
    }

    fn resolve(&self, lex_uri: &str) -> Option<&LexSchema> {
        if lex_uri.contains('#') {
            self.defs.get(lex_uri)
        } else {
            self.defs.get(&format!("{lex_uri}#main"))
        }
    }
}

/// Rewrite every ref in `schema` to a fully-qualified `lex:<nsid>#<def>` URI, exactly as the
/// reference does when a document is added to its `Lexicons` registry — which is also why its
/// closed-union error messages print `lex:`-prefixed refs; keeping the same stored form keeps
/// those messages byte-identical.
fn qualify_refs(schema: &mut LexSchema, base_id: &str) {
    match schema {
        LexSchema::Object(object) => {
            for (_, property) in &mut object.properties {
                qualify_refs(property, base_id);
            }
        }
        LexSchema::Array { items } => qualify_refs(items, base_id),
        LexSchema::Ref { target } => *target = qualify(target, base_id),
        LexSchema::Union { refs, .. } => {
            for r in refs.iter_mut() {
                *r = qualify(r, base_id);
            }
        }
        LexSchema::String { .. }
        | LexSchema::Boolean
        | LexSchema::Integer { .. }
        | LexSchema::Unknown => {}
    }
}

fn qualify(reference: &str, base_id: &str) -> String {
    if let Some(fragment) = reference.strip_prefix('#') {
        format!("lex:{base_id}#{fragment}")
    } else if reference.starts_with("lex:") {
        reference.to_owned()
    } else {
        format!("lex:{reference}")
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn expect_invalid(nsid: &str, body: Value) -> String {
        match registry().validate_input(nsid, &body) {
            Err(ValidationError::Invalid(message)) => message,
            Err(ValidationError::Lexicon(message)) => {
                panic!("expected an Invalid error, got a Lexicon error: {message}")
            }
            Ok(()) => panic!("expected {nsid} to reject {body}"),
        }
    }

    fn expect_valid(nsid: &str, body: Value) {
        if let Err(e) = registry().validate_input(nsid, &body) {
            let message = match e {
                ValidationError::Invalid(m) | ValidationError::Lexicon(m) => m,
            };
            panic!("expected {nsid} to accept {body}: {message}");
        }
    }

    /// The vendored set must parse, resolve every ref, and register every construct the
    /// validator implements — the drift guard for re-vendoring (see `schema.rs`).
    #[test]
    fn registry_builds() {
        let registry = registry();
        // Every natively-handled JSON procedure this branch converts must be registered.
        for nsid in [
            "com.atproto.admin.updateSubjectStatus",
            "com.atproto.identity.refreshIdentity",
            "com.atproto.identity.signPlcOperation",
            "com.atproto.identity.submitPlcOperation",
            "com.atproto.identity.updateHandle",
            "com.atproto.repo.applyWrites",
            "com.atproto.repo.createRecord",
            "com.atproto.repo.deleteRecord",
            "com.atproto.repo.putRecord",
            "com.atproto.server.confirmEmail",
            "com.atproto.server.createAccount",
            "com.atproto.server.createAppPassword",
            "com.atproto.server.createInviteCode",
            "com.atproto.server.createInviteCodes",
            "com.atproto.server.createSession",
            "com.atproto.server.deactivateAccount",
            "com.atproto.server.deleteAccount",
            "com.atproto.server.requestPasswordReset",
            "com.atproto.server.reserveSigningKey",
            "com.atproto.server.resetPassword",
            "com.atproto.server.revokeAppPassword",
            "com.atproto.server.updateEmail",
        ] {
            let input = registry
                .input(nsid)
                .unwrap_or_else(|| panic!("{nsid} must have a vendored input"));
            assert_eq!(input.encoding(), "application/json", "{nsid} encoding");
        }
    }

    #[test]
    fn missing_required_property_reports_document_order() {
        // createSession requires identifier and password; identifier is declared first, so it
        // is the property the reference names when both are absent.
        assert_eq!(
            expect_invalid("com.atproto.server.createSession", json!({})),
            "Input must have the property \"identifier\""
        );
        assert_eq!(
            expect_invalid(
                "com.atproto.server.createSession",
                json!({"identifier": "alice.example.com"})
            ),
            "Input must have the property \"password\""
        );
    }

    #[test]
    fn non_object_input_is_rejected() {
        assert_eq!(
            expect_invalid("com.atproto.server.createSession", json!([1, 2])),
            "Input must be an object"
        );
        assert_eq!(
            expect_invalid("com.atproto.server.createSession", json!("body")),
            "Input must be an object"
        );
    }

    #[test]
    fn wrong_property_type_is_rejected_with_path() {
        assert_eq!(
            expect_invalid(
                "com.atproto.server.createSession",
                json!({"identifier": 42, "password": "hunter2"})
            ),
            "Input/identifier must be a string"
        );
        assert_eq!(
            expect_invalid(
                "com.atproto.server.createAppPassword",
                json!({"name": "cli", "privileged": "yes"})
            ),
            "Input/privileged must be a boolean"
        );
    }

    #[test]
    fn null_is_not_missing_but_is_a_type_error_unless_nullable() {
        // Explicit null on a required, non-nullable property: the reference's required check
        // only fires on absence, so this is a type error.
        assert_eq!(
            expect_invalid(
                "com.atproto.server.createSession",
                json!({"identifier": null, "password": "hunter2"})
            ),
            "Input/identifier must be a string"
        );
        // putRecord declares swapRecord nullable: null passes.
        expect_valid(
            "com.atproto.repo.putRecord",
            json!({
                "repo": "alice.example.com",
                "collection": "app.bsky.feed.post",
                "rkey": "3jui7kd54zh2y",
                "record": {"text": "hi"},
                "swapRecord": null,
            }),
        );
    }

    #[test]
    fn string_formats_are_enforced() {
        assert_eq!(
            expect_invalid(
                "com.atproto.identity.updateHandle",
                json!({"handle": "not_a_handle"})
            ),
            "Input/handle must be a valid handle"
        );
        assert_eq!(
            expect_invalid(
                "com.atproto.repo.createRecord",
                json!({"repo": "alice.example.com", "collection": "not-an-nsid", "record": {}})
            ),
            "Input/collection must be a valid nsid"
        );
        assert_eq!(
            expect_invalid(
                "com.atproto.repo.createRecord",
                json!({
                    "repo": "alice.example.com",
                    "collection": "app.bsky.feed.post",
                    "record": {},
                    "swapCommit": "not-a-cid",
                })
            ),
            "Input/swapCommit must be a cid string"
        );
        assert_eq!(
            expect_invalid(
                "com.atproto.server.deactivateAccount",
                json!({"deleteAfter": "tomorrow"})
            ),
            "Input/deleteAfter must be an valid atproto datetime (both RFC-3339 and ISO-8601)"
        );
        assert_eq!(
            expect_invalid(
                "com.atproto.server.deleteAccount",
                json!({
                    "did": "plc:not-a-did",
                    "password": "hunter2",
                    "token": "12345-67890",
                })
            ),
            "Input/did must be a valid did"
        );
    }

    #[test]
    fn unknown_typed_properties_must_be_objects() {
        assert_eq!(
            expect_invalid(
                "com.atproto.repo.createRecord",
                json!({
                    "repo": "alice.example.com",
                    "collection": "app.bsky.feed.post",
                    "record": "not-an-object",
                })
            ),
            "Input/record must be an object"
        );
        assert_eq!(
            expect_invalid(
                "com.atproto.identity.submitPlcOperation",
                json!({"operation": ["not", "an", "object"]})
            ),
            "Input/operation must be an object"
        );
    }

    #[test]
    fn extra_fields_are_ignored() {
        // Lexicon objects are open: the reference silently ignores undeclared properties.
        expect_valid(
            "com.atproto.server.createSession",
            json!({"identifier": "alice.example.com", "password": "hunter2", "extra": true}),
        );
    }

    #[test]
    fn string_max_length_counts_utf8_bytes() {
        let long_rkey = "k".repeat(513);
        assert_eq!(
            expect_invalid(
                "com.atproto.repo.createRecord",
                json!({
                    "repo": "alice.example.com",
                    "collection": "app.bsky.feed.post",
                    "rkey": long_rkey,
                    "record": {},
                })
            ),
            // 513 chars also exceeds the record-key format's own 512 limit, but the reference
            // checks maxLength before format — this asserts that ordering.
            "Input/rkey must not be longer than 512 characters"
        );
    }

    #[test]
    fn closed_union_rejects_unknown_type_with_qualified_refs() {
        assert_eq!(
            expect_invalid(
                "com.atproto.repo.applyWrites",
                json!({
                    "repo": "alice.example.com",
                    "writes": [{"$type": "com.atproto.repo.applyWrites#upsert"}],
                })
            ),
            "Input/writes/0 $type must be one of lex:com.atproto.repo.applyWrites#create, \
             lex:com.atproto.repo.applyWrites#update, lex:com.atproto.repo.applyWrites#delete"
        );
    }

    #[test]
    fn closed_union_validates_matched_member() {
        assert_eq!(
            expect_invalid(
                "com.atproto.repo.applyWrites",
                json!({
                    "repo": "alice.example.com",
                    "writes": [{"$type": "com.atproto.repo.applyWrites#create", "value": {}}],
                })
            ),
            "Input/writes/0 must have the property \"collection\""
        );
        expect_valid(
            "com.atproto.repo.applyWrites",
            json!({
                "repo": "alice.example.com",
                "writes": [{
                    "$type": "com.atproto.repo.applyWrites#create",
                    "collection": "app.bsky.feed.post",
                    "value": {"text": "hi"},
                }],
            }),
        );
    }

    #[test]
    fn union_requires_discriminated_object() {
        assert_eq!(
            expect_invalid(
                "com.atproto.repo.applyWrites",
                json!({"repo": "alice.example.com", "writes": [{"collection": "app.bsky.feed.post"}]})
            ),
            "Input/writes/0 must be an object which includes the \"$type\" property"
        );
        assert_eq!(
            expect_invalid(
                "com.atproto.repo.applyWrites",
                json!({"repo": "alice.example.com", "writes": ["create"]})
            ),
            "Input/writes/0 must be an object which includes the \"$type\" property"
        );
    }

    #[test]
    fn open_union_accepts_unknown_type_and_validates_known_members() {
        // updateSubjectStatus.subject is an open union: an unrecognized $type passes lexicon
        // validation (the handler's own subject checks still apply downstream).
        expect_valid(
            "com.atproto.admin.updateSubjectStatus",
            json!({"subject": {"$type": "com.example.custom#subject"}}),
        );
        // A recognized member is validated, cross-document ref included.
        assert_eq!(
            expect_invalid(
                "com.atproto.admin.updateSubjectStatus",
                json!({"subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "nope"}})
            ),
            "Input/subject/did must be a valid did"
        );
        // An implicit #main $type matches a bare ref (strongRef).
        assert_eq!(
            expect_invalid(
                "com.atproto.admin.updateSubjectStatus",
                json!({"subject": {
                    "$type": "com.atproto.repo.strongRef",
                    "uri": "at://did:plc:abc123abc123abc123abc123/app.bsky.feed.post/3jui7kd54zh2y",
                }})
            ),
            "Input/subject must have the property \"cid\""
        );
    }

    #[test]
    fn cross_document_ref_is_validated() {
        assert_eq!(
            expect_invalid(
                "com.atproto.admin.updateSubjectStatus",
                json!({
                    "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:abc123abc123abc123abc123"},
                    "takedown": {"ref": "case-1"},
                })
            ),
            "Input/takedown must have the property \"applied\""
        );
    }

    #[test]
    fn array_elements_are_validated_with_indexed_paths() {
        assert_eq!(
            expect_invalid(
                "com.atproto.identity.signPlcOperation",
                json!({"rotationKeys": ["did:key:zQ3valid", 7]})
            ),
            "Input/rotationKeys/1 must be a string"
        );
    }

    #[test]
    fn integer_type_is_enforced() {
        assert_eq!(
            expect_invalid(
                "com.atproto.server.createInviteCode",
                json!({"useCount": "one"})
            ),
            "Input/useCount must be an integer"
        );
        expect_valid(
            "com.atproto.server.createInviteCode",
            json!({"useCount": 1}),
        );
    }

    #[test]
    fn required_integer_with_default_is_satisfied_by_absence() {
        // createInviteCodes requires codeCount but declares `default: 1`; the reference applies
        // the default during validation, so an absent codeCount passes while an absent
        // useCount (required, no default) still fails.
        expect_valid(
            "com.atproto.server.createInviteCodes",
            json!({"useCount": 1}),
        );
        assert_eq!(
            expect_invalid("com.atproto.server.createInviteCodes", json!({})),
            "Input must have the property \"useCount\""
        );
    }

    #[test]
    fn schemas_with_no_required_properties_accept_empty_bodies() {
        expect_valid("com.atproto.server.deactivateAccount", json!({}));
        expect_valid("com.atproto.server.reserveSigningKey", json!({}));
        expect_valid("com.atproto.identity.signPlcOperation", json!({}));
    }
}
