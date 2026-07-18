// pattern: Functional Core
//
// The lexicon registry: the vendored `com.atproto.*` and `app.bsky.*` lexicon documents
// (`crates/pds/lexicons/`, pinned upstream — see the README there) compiled into the binary and
// parsed once, plus three validation entry points:
//
//   * `validate_input` — the single place asserting "this request body conforms to the procedure's
//     declared lexicon input". The reference PDS gets this uniformity from `@atproto/xrpc-server`'s
//     `validateInput` running on every route; Custos historically hand-parsed each body with a
//     bespoke serde struct, so strictness drifted route by route and concealed client bugs.
//     Handlers consume it through the `LexiconInput` axum extractor (`extractor.rs`), or through
//     `validate_procedure_body` where the raw body bytes are also needed for signature verification.
//   * `validate_params` — the query-parameter counterpart: "this GET request's query
//     string conforms to the procedure's declared lexicon `parameters`". Query values are always
//     strings, so `lexicon::params` coerces each declared property to its typed JSON value
//     (`@atproto/xrpc-server`'s `decodeQueryParams` semantics — an empty value decodes to absent,
//     an unparseable integer decodes to `0`, a boolean is `true` only for the literal string
//     "true", an array is repeated query keys) before running the same object-validator required/
//     format/bounds checks an input body uses. Handlers consume it through the `LexiconParams`
//     axum extractor (`params.rs`), or through `validate_procedure_params`/`validate_params_map`
//     for a handler that needs to adjust the raw query before validation (`get_record.rs`'s legacy
//     `did=` alias).
//   * `validate_record` — `assertValidRecord`-parity validation for a repo write: reject an invalid
//     record of a known (vendored) collection by default, honor the `validate` flag, enforce
//     `$type`/collection agreement and the record-key discipline, and report `validationStatus`.
//     The repo-write routes call it via `record_write::write_record` / `apply_writes`.
//   * `validate_output` — the `assertValidXrpcOutput` counterpart: "this serialized response body
//     conforms to the query/procedure's declared lexicon `output`". Outputs are Custos-controlled,
//     so a failure is *our* shape regression (missing required field, wrong type) rather than a
//     client bug — this is drift detection, exercised by the registry tests (there is no lib target,
//     so the black-box `http_suite` can't reach the registry) rather than wired into the serve path.
//
// Scope: input bodies, query parameters, and JSON output bodies of the natively-handled procedures,
// plus the record bodies of the vendored `app.bsky.*` record lexicons.

mod extractor;
mod formats;
mod params;
mod schema;
mod validate;

use std::collections::HashMap;
use std::sync::LazyLock;

use serde_json::Value;

use schema::{LexDef, LexObject, LexRecord, LexSchema, LexXrpcBody};

pub use extractor::{validate_procedure_body, LexiconInput};
pub use params::{parse_raw_query, validate_params_map, LexiconParams};
pub use validate::{RecordValidation, ValidationError};

/// The vendored lexicon documents. Adding a route with a JSON input body means vendoring its
/// document (plus any documents its refs reach) and listing it here; the registry tests fail on
/// unsupported constructs or dangling refs.
static LEXICON_SOURCES: &[&str] = &[
    // `app.bsky.*` record lexicons (+ the object/string/token defs their record schemas reach),
    // vendored so repo writes run `validate`-flag record validation with `assertValidRecord`
    // parity. Only the record-reachable closure is vendored (not the AppView view/output defs).
    include_str!("../../lexicons/app/bsky/actor/profile.json"),
    include_str!("../../lexicons/app/bsky/embed/defs.json"),
    include_str!("../../lexicons/app/bsky/embed/external.json"),
    include_str!("../../lexicons/app/bsky/embed/gallery.json"),
    include_str!("../../lexicons/app/bsky/embed/images.json"),
    include_str!("../../lexicons/app/bsky/embed/record.json"),
    include_str!("../../lexicons/app/bsky/embed/recordWithMedia.json"),
    include_str!("../../lexicons/app/bsky/embed/video.json"),
    include_str!("../../lexicons/app/bsky/feed/like.json"),
    include_str!("../../lexicons/app/bsky/feed/post.json"),
    include_str!("../../lexicons/app/bsky/feed/repost.json"),
    include_str!("../../lexicons/app/bsky/graph/block.json"),
    include_str!("../../lexicons/app/bsky/graph/defs.json"),
    include_str!("../../lexicons/app/bsky/graph/follow.json"),
    include_str!("../../lexicons/app/bsky/graph/list.json"),
    include_str!("../../lexicons/app/bsky/graph/listblock.json"),
    include_str!("../../lexicons/app/bsky/graph/listitem.json"),
    include_str!("../../lexicons/app/bsky/richtext/facet.json"),
    include_str!("../../lexicons/com/atproto/label/defs.json"),
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
    // Query (`type: "query"`, GET) documents, vendored so natively-handled queries run
    // `LexiconParams` validation with `assertValidXrpcParams` parity.
    include_str!("../../lexicons/com/atproto/identity/resolveDid.json"),
    include_str!("../../lexicons/com/atproto/identity/resolveHandle.json"),
    include_str!("../../lexicons/com/atproto/identity/resolveIdentity.json"),
    include_str!("../../lexicons/com/atproto/repo/describeRepo.json"),
    include_str!("../../lexicons/com/atproto/repo/getRecord.json"),
    include_str!("../../lexicons/com/atproto/repo/listMissingBlobs.json"),
    include_str!("../../lexicons/com/atproto/repo/listRecords.json"),
    include_str!("../../lexicons/com/atproto/server/getServiceAuth.json"),
    include_str!("../../lexicons/com/atproto/sync/getBlob.json"),
    include_str!("../../lexicons/com/atproto/sync/getBlocks.json"),
    include_str!("../../lexicons/com/atproto/sync/getLatestCommit.json"),
    include_str!("../../lexicons/com/atproto/sync/getRecord.json"),
    include_str!("../../lexicons/com/atproto/sync/getRepo.json"),
    include_str!("../../lexicons/com/atproto/sync/getRepoStatus.json"),
    include_str!("../../lexicons/com/atproto/sync/listBlobs.json"),
    include_str!("../../lexicons/com/atproto/sync/listRepos.json"),
    // Output-only `defs` documents: the `object` defs the vendored queries'/procedures' `output`
    // schemas reach that no input/record closure already pulled in. Registering outputs makes these
    // validation roots, so `check_refs` requires them.
    include_str!("../../lexicons/com/atproto/identity/defs.json"),
    include_str!("../../lexicons/com/atproto/repo/defs.json"),
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

/// Parsed lexicons, keyed for validation: procedure inputs by NSID, `record` definitions by
/// collection NSID, query/procedure `parameters` by NSID, query/procedure JSON `output` schemas by
/// NSID, and referencable definitions by fully-qualified `lex:<nsid>#<def>` URI.
pub struct Registry {
    inputs: HashMap<String, InputDef>,
    records: HashMap<String, LexRecord>,
    /// Every registered `query` def (even one that declares no `parameters` — stored as an empty
    /// object, so "vendored with no constraints" and "not vendored at all" stay distinguishable
    /// via `params()`'s `Option`) plus any `procedure` that explicitly declares `parameters`.
    params: HashMap<String, LexObject>,
    /// Every query/procedure that declares a JSON `output` schema, keyed by NSID. A non-JSON output
    /// (the sync endpoints' CAR streams, `getBlob`'s `*/*`) carries no schema and so is absent —
    /// there is nothing to shape-check against.
    outputs: HashMap<String, LexSchema>,
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
        // Register a query/procedure's JSON `output` body (if it declares one with a schema),
        // qualifying its refs against the owning document exactly as an input/record schema is.
        fn register_output(
            outputs: &mut HashMap<String, LexSchema>,
            nsid: &str,
            output: Option<LexXrpcBody>,
        ) {
            if let Some(LexXrpcBody {
                schema: Some(mut schema),
                ..
            }) = output
            {
                qualify_refs(&mut schema, nsid);
                outputs.insert(nsid.to_owned(), schema);
            }
        }

        let mut inputs = HashMap::new();
        let mut records = HashMap::new();
        let mut params = HashMap::new();
        let mut outputs = HashMap::new();
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
                        // Params properties are restricted to string/integer/boolean/array-of-
                        // primitive by the parser (`schema::parse_param_property`), so unlike an
                        // input/record schema there is never a `ref`/`union` to qualify here.
                        if let Some(parameters) = procedure.parameters {
                            params.insert(doc.id.clone(), parameters);
                        }
                        register_output(&mut outputs, &doc.id, procedure.output);
                    }
                    LexDef::Query(query) => {
                        if name != "main" {
                            return Err(format!(
                                "{}#{name}: only main query definitions are supported",
                                doc.id
                            ));
                        }
                        let parameters = query.parameters.unwrap_or(LexObject {
                            required: Vec::new(),
                            nullable: Vec::new(),
                            properties: Vec::new(),
                        });
                        params.insert(doc.id.clone(), parameters);
                        register_output(&mut outputs, &doc.id, query.output);
                    }
                    LexDef::Record(mut record) => {
                        if name != "main" {
                            return Err(format!(
                                "{}#{name}: a record must be the `main` definition",
                                doc.id
                            ));
                        }
                        qualify_refs(&mut record.record, &doc.id);
                        records.insert(doc.id.clone(), record);
                    }
                    LexDef::Schema(mut schema) => {
                        qualify_refs(&mut schema, &doc.id);
                        defs.insert(format!("lex:{}#{name}", doc.id), schema);
                    }
                }
            }
        }

        let registry = Registry {
            inputs,
            records,
            params,
            outputs,
            defs,
        };
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
                LexSchema::Array { items, .. } => walk(registry, items),
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
                | LexSchema::Boolean { .. }
                | LexSchema::Integer { .. }
                | LexSchema::Unknown
                | LexSchema::Blob
                | LexSchema::Bytes
                | LexSchema::Token => Ok(()),
            }
        }
        for input in self.inputs.values() {
            if let Some(schema) = &input.schema {
                walk(self, schema)?;
            }
        }
        // Record schemas are validation roots too: a dangling ref reachable from a record body
        // must fail the build the same way an input's does.
        for record in self.records.values() {
            walk(self, &record.record)?;
        }
        // Output schemas are validation roots now as well (`validate_output`): a dangling ref
        // reachable from a served response body must fail the build. This is exactly what pulls the
        // output-only closure (`com.atproto.repo.defs#commitMeta`, `com.atproto.identity.defs#\
        // identityInfo`, the `applyWrites` result unions) into the vendored set — a document whose
        // output refs something un-vendored fails `registry_builds` instead of 500ing at serve time.
        for output in self.outputs.values() {
            walk(self, output)?;
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

    /// The declared `parameters` of a registered query (or a procedure that declares them), if
    /// vendored. `None` means the nsid itself isn't registered at all (a wiring defect); a
    /// registered query with no `parameters` key still yields `Some` (an empty object — every
    /// query string trivially satisfies it).
    pub fn params(&self, nsid: &str) -> Option<&LexObject> {
        self.params.get(nsid)
    }

    /// Assert `value` (an already-coerced query-params object — see `lexicon::params`) conforms
    /// to `nsid`'s declared `parameters`, rooted at `Params` like the reference's
    /// `assertValidXrpcParams`.
    pub fn validate_params(&self, nsid: &str, value: &Value) -> Result<(), ValidationError> {
        let params = self.params(nsid).ok_or_else(|| {
            ValidationError::Lexicon(format!("no lexicon params are vendored for {nsid}"))
        })?;
        validate::validate_params(self, "Params", params, value)
    }

    /// The declared JSON `output` schema of a query/procedure, if its document is vendored and it
    /// returns a JSON body. `None` for a non-JSON output (CAR/blob streams) or an un-vendored nsid.
    ///
    /// Test-only: outputs are Custos-controlled, so this layer is drift *detection* (the registry
    /// tests) rather than a serve-path guard. The production-side value is `check_refs` walking the
    /// output closure at build time (a dangling output ref fails `registry_builds`); the registered
    /// schemas themselves are consumed only from `#[cfg(test)]` code today.
    #[cfg(test)]
    pub fn output(&self, nsid: &str) -> Option<&LexSchema> {
        self.outputs.get(nsid)
    }

    /// Assert `body` conforms to `nsid`'s declared JSON output schema, rooted at `Output` like the
    /// reference's `assertValidXrpcOutput`. Because outputs are Custos-controlled, a failure here is
    /// *our* shape regression, not the client's — this is drift detection, wired into tests rather
    /// than the production serve path (`Lexicon(...)` when the nsid declares no vendored JSON
    /// output, so a caller can tell "not validatable" from "invalid").
    #[cfg(test)]
    pub fn validate_output(&self, nsid: &str, body: &Value) -> Result<(), ValidationError> {
        let schema = self.output(nsid).ok_or_else(|| {
            ValidationError::Lexicon(format!("no lexicon output is vendored for {nsid}"))
        })?;
        validate::validate(self, "Output", schema, body)
    }

    /// Run `assertValidRecord`-parity validation for a repo write, mirroring the reference PDS's
    /// `prepareWrite`/`validateRecord`. `collection` is the write's target NSID, `rkey` its record
    /// key, `record` the record body, and `validate` the request's `validate` flag.
    ///
    /// Returns the per-write `validationStatus` on success (`None` only when `validate: false`,
    /// which skips validation entirely). The reference's decision table:
    ///
    /// | `validate` | lexicon known | outcome |
    /// |---|---|---|
    /// | `Some(false)` | — | `Ok(None)` — skipped |
    /// | `Some(true)` | no | `Err` — `Unknown lexicon type` |
    /// | `Some(true)` | yes | validate; `Err` on failure, else `Valid` |
    /// | `None` | no | `Ok(Some(Unknown))` — unknown collections stay writable |
    /// | `None` | yes | validate; `Err` on failure, else `Valid` |
    ///
    /// A record whose `$type` is present but does not equal `collection` is rejected regardless of
    /// the flag (`prepareWrite` computes `$type` before `validateRecord` runs).
    pub fn validate_record(
        &self,
        collection: &str,
        rkey: &str,
        record: &Value,
        validate: Option<bool>,
    ) -> Result<Option<RecordValidation>, ValidationError> {
        validate::validate_record(self, collection, rkey, record, validate)
    }

    /// The `record` definition for a collection, if one is vendored.
    pub(super) fn record(&self, collection: &str) -> Option<&LexRecord> {
        self.records.get(collection)
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
        LexSchema::Array { items, .. } => qualify_refs(items, base_id),
        LexSchema::Ref { target } => *target = qualify(target, base_id),
        LexSchema::Union { refs, .. } => {
            for r in refs.iter_mut() {
                *r = qualify(r, base_id);
            }
        }
        LexSchema::String { .. }
        | LexSchema::Boolean { .. }
        | LexSchema::Integer { .. }
        | LexSchema::Unknown
        | LexSchema::Blob
        | LexSchema::Bytes
        | LexSchema::Token => {}
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
    use unicode_segmentation::UnicodeSegmentation;

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
        // Every natively-handled GET query this branch converts must be registered, with
        // `parameters` (an empty object counts — `describeRepo` has none it needs beyond `repo`).
        for nsid in [
            "com.atproto.identity.resolveDid",
            "com.atproto.identity.resolveHandle",
            "com.atproto.identity.resolveIdentity",
            "com.atproto.repo.describeRepo",
            "com.atproto.repo.getRecord",
            "com.atproto.repo.listMissingBlobs",
            "com.atproto.repo.listRecords",
            "com.atproto.server.getServiceAuth",
            "com.atproto.sync.getBlob",
            "com.atproto.sync.getBlocks",
            "com.atproto.sync.getLatestCommit",
            "com.atproto.sync.getRecord",
            "com.atproto.sync.getRepo",
            "com.atproto.sync.getRepoStatus",
            "com.atproto.sync.listBlobs",
            "com.atproto.sync.listRepos",
        ] {
            registry
                .params(nsid)
                .unwrap_or_else(|| panic!("{nsid} must have vendored params"));
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

    // ── validate_record (assertValidRecord parity) ───────────────────────────

    const TID: &str = "3jui7kd54zh2y";

    fn record_result(
        collection: &str,
        rkey: &str,
        record: Value,
        validate: Option<bool>,
    ) -> Result<Option<RecordValidation>, String> {
        registry()
            .validate_record(collection, rkey, &record, validate)
            .map_err(|e| match e {
                ValidationError::Invalid(m) => m,
                ValidationError::Lexicon(m) => panic!("unexpected Lexicon error: {m}"),
            })
    }

    fn valid_post() -> Value {
        json!({"text": "hello", "createdAt": "2026-07-17T12:00:00Z"})
    }

    #[test]
    fn valid_known_record_is_valid() {
        assert_eq!(
            record_result("app.bsky.feed.post", TID, valid_post(), None).unwrap(),
            Some(RecordValidation::Valid)
        );
    }

    #[test]
    fn known_record_missing_required_field_is_rejected() {
        // Missing the required `createdAt` (declared after `text`).
        assert_eq!(
            record_result("app.bsky.feed.post", TID, json!({"text": "hi"}), None).unwrap_err(),
            "Invalid app.bsky.feed.post record: Record must have the property \"createdAt\""
        );
    }

    #[test]
    fn max_graphemes_counts_grapheme_clusters_not_bytes() {
        // 301 ASCII chars: within maxLength (3000 bytes) but over maxGraphemes (300).
        let mut record = valid_post();
        record["text"] = json!("a".repeat(301));
        assert_eq!(
            record_result("app.bsky.feed.post", TID, record, None).unwrap_err(),
            "Invalid app.bsky.feed.post record: Record/text must not be longer than 300 graphemes"
        );
        // A single family emoji is one grapheme cluster though it is many bytes/codepoints, so a
        // 300-of-them text passes the grapheme bound (it is the byte bound it would blow, which we
        // keep under here) — proving the counter is grapheme-based, not codepoint- or byte-based.
        let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}"; // 👨‍👩‍👧
        assert_eq!(family.graphemes(true).count(), 1);
    }

    #[test]
    fn record_key_discipline_is_enforced() {
        // app.bsky.feed.post uses `tid`: a non-TID key is rejected.
        assert!(
            record_result("app.bsky.feed.post", "notatid", valid_post(), None)
                .unwrap_err()
                .contains("Invalid record key for app.bsky.feed.post")
        );
        // app.bsky.actor.profile uses `literal:self`: only "self" is accepted.
        let profile = json!({"displayName": "Alice"});
        assert!(
            record_result("app.bsky.actor.profile", "notself", profile.clone(), None)
                .unwrap_err()
                .contains("Invalid record key for app.bsky.actor.profile")
        );
        assert_eq!(
            record_result("app.bsky.actor.profile", "self", profile, None).unwrap(),
            Some(RecordValidation::Valid)
        );
    }

    #[test]
    fn type_mismatch_is_rejected_regardless_of_flag() {
        let mut record = valid_post();
        record["$type"] = json!("app.bsky.feed.like");
        // Even with validate: false, a $type ≠ collection is rejected (prepareWrite computes it
        // before validateRecord runs).
        assert_eq!(
            record_result("app.bsky.feed.post", TID, record, Some(false)).unwrap_err(),
            "Invalid $type: expected app.bsky.feed.post, got app.bsky.feed.like"
        );
    }

    #[test]
    fn validate_flag_decision_table() {
        let bad = json!({"text": "no timestamp"});
        // validate: false skips entirely (no status), even for an invalid known record.
        assert_eq!(
            record_result("app.bsky.feed.post", TID, bad.clone(), Some(false)).unwrap(),
            None
        );
        // validate: true on a known-but-invalid record still rejects.
        assert!(record_result("app.bsky.feed.post", TID, bad, Some(true)).is_err());
        // Unknown collection: default → unknown; validate: true → rejected.
        let unknown = json!({"anything": true});
        assert_eq!(
            record_result("com.example.unknown", "k", unknown.clone(), None).unwrap(),
            Some(RecordValidation::Unknown)
        );
        assert_eq!(
            record_result("com.example.unknown", "k", unknown, Some(true)).unwrap_err(),
            "Unknown lexicon type: com.example.unknown"
        );
    }

    #[test]
    fn embedded_blob_and_nested_refs_validate() {
        // A post with an image embed exercises: union member resolution (embed.images), a nested
        // array of objects (images), a `blob` ref (image), and a cross-document strongRef is not
        // needed here. A well-formed typed blob passes; a malformed one is rejected.
        let with_blob = |blob: Value| {
            json!({
                "text": "look",
                "createdAt": "2026-07-17T12:00:00Z",
                "embed": {
                    "$type": "app.bsky.embed.images",
                    "images": [{
                        "alt": "a cat",
                        "image": blob,
                    }],
                },
            })
        };
        let good_blob = json!({
            "$type": "blob",
            "ref": {"$link": "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a"},
            "mimeType": "image/png",
            "size": 1234,
        });
        assert_eq!(
            record_result("app.bsky.feed.post", TID, with_blob(good_blob), None).unwrap(),
            Some(RecordValidation::Valid)
        );
        // A blob whose ref isn't a CID is rejected, with the nested path.
        let bad_blob =
            json!({"$type": "blob", "ref": {"$link": "not-a-cid"}, "mimeType": "image/png"});
        assert!(
            record_result("app.bsky.feed.post", TID, with_blob(bad_blob), None)
                .unwrap_err()
                .contains("images/0/image must be a blob ref")
        );
    }

    #[test]
    fn like_requires_well_formed_subject() {
        // app.bsky.feed.like: required subject (strongRef) + createdAt; the strongRef's `uri` is an
        // at-uri and `cid` a cid — a bad at-uri is rejected at the nested path.
        let like = |uri: &str| {
            json!({
                "subject": {"uri": uri, "cid": "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a"},
                "createdAt": "2026-07-17T12:00:00Z",
            })
        };
        assert_eq!(
            record_result(
                "app.bsky.feed.like",
                TID,
                like("at://did:plc:abc123abc123abc123abc123/app.bsky.feed.post/3jui7kd54zh2y"),
                None,
            )
            .unwrap(),
            Some(RecordValidation::Valid)
        );
        assert!(
            record_result("app.bsky.feed.like", TID, like("not a uri"), None)
                .unwrap_err()
                .contains("subject/uri must be a valid at-uri")
        );
    }

    // ── validate_params (assertValidXrpcParams parity) ───────────────────────

    fn expect_params_invalid(nsid: &str, value: Value) -> String {
        match registry().validate_params(nsid, &value) {
            Err(ValidationError::Invalid(message)) => message,
            Err(ValidationError::Lexicon(message)) => {
                panic!("expected an Invalid error, got a Lexicon error: {message}")
            }
            Ok(()) => panic!("expected {nsid} to reject {value}"),
        }
    }

    fn expect_params_valid(nsid: &str, value: Value) {
        if let Err(e) = registry().validate_params(nsid, &value) {
            let message = match e {
                ValidationError::Invalid(m) | ValidationError::Lexicon(m) => m,
            };
            panic!("expected {nsid} to accept {value}: {message}");
        }
    }

    #[test]
    fn params_missing_required_property_is_rejected() {
        assert_eq!(
            expect_params_invalid("com.atproto.repo.getRecord", json!({})),
            "Params must have the property \"repo\""
        );
    }

    #[test]
    fn params_string_format_is_enforced() {
        assert_eq!(
            expect_params_invalid(
                "com.atproto.sync.getBlob",
                json!({"did": "not-a-did", "cid": "x"})
            ),
            "Params/did must be a valid did"
        );
        expect_params_valid(
            "com.atproto.sync.getBlob",
            json!({
                "did": "did:plc:abc123abc123abc123abc123",
                "cid": "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a",
            }),
        );
    }

    #[test]
    fn params_integer_bounds_are_enforced() {
        assert_eq!(
            expect_params_invalid(
                "com.atproto.repo.listRecords",
                json!({
                    "repo": "did:plc:abc123abc123abc123abc123",
                    "collection": "app.bsky.feed.post",
                    "limit": 500,
                })
            ),
            "Params/limit can not be greater than 100"
        );
        expect_params_valid(
            "com.atproto.repo.listRecords",
            json!({
                "repo": "did:plc:abc123abc123abc123abc123",
                "collection": "app.bsky.feed.post",
                "limit": 100,
            }),
        );
    }

    #[test]
    fn params_optional_property_absent_is_fine() {
        // listRecords declares `limit`/`cursor`/`reverse` optional: omitting them entirely (not
        // even present as JSON null) must pass.
        expect_params_valid(
            "com.atproto.repo.listRecords",
            json!({
                "repo": "did:plc:abc123abc123abc123abc123",
                "collection": "app.bsky.feed.post",
            }),
        );
    }

    #[test]
    fn params_array_of_primitives_validates_each_element() {
        assert_eq!(
            expect_params_invalid(
                "com.atproto.sync.getBlocks",
                json!({"did": "did:plc:abc123abc123abc123abc123", "cids": ["not-a-cid"]})
            ),
            "Params/cids/0 must be a cid string"
        );
        expect_params_valid(
            "com.atproto.sync.getBlocks",
            json!({
                "did": "did:plc:abc123abc123abc123abc123",
                "cids": ["bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a"],
            }),
        );
    }

    #[test]
    fn params_required_property_missing_reports_first_missing_in_document_order() {
        assert_eq!(
            expect_params_invalid("com.atproto.server.getServiceAuth", json!({})),
            "Params must have the property \"aud\""
        );
        expect_params_valid(
            "com.atproto.server.getServiceAuth",
            json!({"aud": "did:web:api.bsky.app"}),
        );
    }

    // ── validate_output (assertValidXrpcOutput parity) ───────────────────────

    const DID: &str = "did:plc:abc123abc123abc123abc123";
    const CID: &str = "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a";

    fn expect_output_invalid(nsid: &str, value: Value) -> String {
        match registry().validate_output(nsid, &value) {
            Err(ValidationError::Invalid(message)) => message,
            Err(ValidationError::Lexicon(message)) => {
                panic!("expected an Invalid error, got a Lexicon error: {message}")
            }
            Ok(()) => panic!("expected {nsid} to reject {value}"),
        }
    }

    fn expect_output_valid(nsid: &str, value: Value) {
        if let Err(e) = registry().validate_output(nsid, &value) {
            let message = match e {
                ValidationError::Invalid(m) | ValidationError::Lexicon(m) => m,
            };
            panic!("expected {nsid} to accept {value}: {message}");
        }
    }

    #[test]
    fn outputs_are_registered_only_for_json_bodies() {
        let registry = registry();
        // Every vendored endpoint whose lexicon declares a JSON `output` must be registered — the
        // full matrix, so silently dropping one endpoint's output registration fails this test.
        for nsid in [
            "com.atproto.admin.updateSubjectStatus",
            "com.atproto.identity.refreshIdentity",
            "com.atproto.identity.resolveDid",
            "com.atproto.identity.resolveHandle",
            "com.atproto.identity.resolveIdentity",
            "com.atproto.identity.signPlcOperation",
            "com.atproto.repo.applyWrites",
            "com.atproto.repo.createRecord",
            "com.atproto.repo.deleteRecord",
            "com.atproto.repo.describeRepo",
            "com.atproto.repo.getRecord",
            "com.atproto.repo.listMissingBlobs",
            "com.atproto.repo.listRecords",
            "com.atproto.repo.putRecord",
            "com.atproto.server.createAccount",
            "com.atproto.server.createAppPassword",
            "com.atproto.server.createInviteCode",
            "com.atproto.server.createInviteCodes",
            "com.atproto.server.createSession",
            "com.atproto.server.getServiceAuth",
            "com.atproto.server.reserveSigningKey",
            "com.atproto.sync.getLatestCommit",
            "com.atproto.sync.getRepoStatus",
            "com.atproto.sync.listBlobs",
            "com.atproto.sync.listRepos",
        ] {
            registry
                .output(nsid)
                .unwrap_or_else(|| panic!("{nsid} must have a vendored output"));
        }
        // A non-JSON output (CAR/blob streams) carries no schema, so it is deliberately absent —
        // there is nothing to shape-check, and `validate_output` reports it as not-validatable.
        for nsid in [
            "com.atproto.sync.getRepo",
            "com.atproto.sync.getRecord",
            "com.atproto.sync.getBlocks",
            "com.atproto.sync.getBlob",
        ] {
            assert!(
                registry.output(nsid).is_none(),
                "{nsid} streams a non-JSON body and must have no output schema"
            );
            match registry.validate_output(nsid, &json!({})) {
                Err(ValidationError::Lexicon(_)) => {}
                Err(ValidationError::Invalid(m)) => {
                    panic!("{nsid} output should be un-validatable, got Invalid: {m}")
                }
                Ok(()) => panic!("{nsid} output should be un-validatable, got Ok"),
            }
        }
    }

    #[test]
    fn valid_session_output_passes() {
        expect_output_valid(
            "com.atproto.server.createSession",
            json!({
                "accessJwt": "a.b.c",
                "refreshJwt": "d.e.f",
                "handle": "alice.example.com",
                "did": DID,
                "active": true,
            }),
        );
        // createAccount shares the session shape plus an optional `didDoc` (unknown = any object).
        expect_output_valid(
            "com.atproto.server.createAccount",
            json!({
                "accessJwt": "a.b.c",
                "refreshJwt": "d.e.f",
                "handle": "alice.example.com",
                "did": DID,
                "didDoc": {"id": DID},
            }),
        );
    }

    #[test]
    fn output_missing_required_field_reports_document_order() {
        // createSession requires accessJwt, refreshJwt, handle, did in that order.
        assert_eq!(
            expect_output_invalid(
                "com.atproto.server.createSession",
                json!({"accessJwt": "a", "refreshJwt": "r", "handle": "alice.example.com"})
            ),
            "Output must have the property \"did\""
        );
    }

    #[test]
    fn output_wrong_type_is_rejected_with_path() {
        assert_eq!(
            expect_output_invalid(
                "com.atproto.server.createSession",
                json!({
                    "accessJwt": "a",
                    "refreshJwt": "r",
                    "handle": "alice.example.com",
                    "did": DID,
                    "active": "yes",
                })
            ),
            "Output/active must be a boolean"
        );
        // A declared string `format` is enforced on outputs exactly as on inputs.
        assert_eq!(
            expect_output_invalid(
                "com.atproto.identity.resolveHandle",
                json!({"did": "not-a-did"})
            ),
            "Output/did must be a valid did"
        );
    }

    #[test]
    fn output_commit_meta_ref_is_validated() {
        // createRecord's `commit` is a ref to com.atproto.repo.defs#commitMeta (required cid, rev) —
        // an output-only external doc pulled in by this layer.
        expect_output_valid(
            "com.atproto.repo.createRecord",
            json!({
                "uri": format!("at://{DID}/app.bsky.feed.post/3jui7kd54zh2y"),
                "cid": CID,
                "commit": {"cid": CID, "rev": "3jui7kd54zh2y"},
                "validationStatus": "valid",
            }),
        );
        assert_eq!(
            expect_output_invalid(
                "com.atproto.repo.putRecord",
                json!({
                    "uri": format!("at://{DID}/app.bsky.feed.post/3jui7kd54zh2y"),
                    "cid": CID,
                    "commit": {"cid": CID},
                })
            ),
            "Output/commit must have the property \"rev\""
        );
    }

    #[test]
    fn output_apply_writes_result_union_is_closed() {
        // applyWrites' `results` is a closed union of #createResult/#updateResult/#deleteResult.
        expect_output_valid(
            "com.atproto.repo.applyWrites",
            json!({
                "commit": {"cid": CID, "rev": "3jui7kd54zh2y"},
                "results": [
                    {
                        "$type": "com.atproto.repo.applyWrites#createResult",
                        "uri": format!("at://{DID}/app.bsky.feed.post/3jui7kd54zh2y"),
                        "cid": CID,
                        "validationStatus": "valid",
                    },
                    {"$type": "com.atproto.repo.applyWrites#deleteResult"},
                ],
            }),
        );
        assert_eq!(
            expect_output_invalid(
                "com.atproto.repo.applyWrites",
                json!({"results": [{"$type": "com.atproto.repo.applyWrites#upsertResult"}]})
            ),
            "Output/results/0 $type must be one of lex:com.atproto.repo.applyWrites#createResult, \
             lex:com.atproto.repo.applyWrites#updateResult, lex:com.atproto.repo.applyWrites#deleteResult"
        );
    }

    #[test]
    fn output_cross_document_ref_is_validated() {
        // resolveIdentity returns com.atproto.identity.defs#identityInfo (required did/handle/didDoc).
        expect_output_valid(
            "com.atproto.identity.resolveIdentity",
            json!({"did": DID, "handle": "alice.example.com", "didDoc": {"id": DID}}),
        );
        assert_eq!(
            expect_output_invalid(
                "com.atproto.identity.resolveIdentity",
                json!({"did": DID, "handle": "alice.example.com"})
            ),
            "Output must have the property \"didDoc\""
        );
    }

    #[test]
    fn output_known_values_string_is_advisory() {
        // getRepoStatus.status carries `knownValues` — the reference does not enforce it, so an
        // out-of-set value still validates (it is a plain string).
        expect_output_valid(
            "com.atproto.sync.getRepoStatus",
            json!({"did": DID, "active": false, "status": "some-future-status"}),
        );
    }
}
