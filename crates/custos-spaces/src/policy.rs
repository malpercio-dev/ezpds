// pattern: Imperative Shell

//! The space policy: the one `$type`-discriminated object that decides who reads and writes a
//! space this host is the authority for (V079), and its published mirror.
//!
//! [`SpacePolicy`] is closed over the three baseline policies every PDS must support. Each
//! decision point (credential issuance, writer tracking, the member methods, publishing) is a
//! `match` on it; there is no trait or registry until a fourth policy exists. A policy arriving
//! on the wire is *normalized* ([`SpacePolicy::from_lex`]): known fields only, defaults filled,
//! so what is stored is exactly what is enforced, and an unknown `$type` answers
//! `UnsupportedPolicy` rather than being stored unenforced. Mirrors the reference's
//! `space-policy/policy.ts`.
//!
//! **Publishing.** A policy may ask for itself (`publishPolicy`) and its member list
//! (`publishMembers`) to be mirrored into the authority's own repo in the space, as
//! `com.atproto.space.policy/self` and `com.atproto.memberspace.member/<did>` records. The
//! config stays authoritative: the records are written or withdrawn by the `*_record_ops`
//! builders here, inside the same transaction as the config change, and no caller may write
//! those collections directly (`space_record_write` refuses them).

use common::{ApiError, ErrorCode};
use custos_core::space_uri::SpaceRef;
use serde_json::{json, Value};
use sqlx::Sqlite;

use crate::space_record_write::{SpaceWriteAction, SpaceWriteOp};

pub const PERSONALSPACE: &str = "com.atproto.personalspace.policy";
pub const MEMBERSPACE: &str = "com.atproto.memberspace.policy";
pub const MANAGEDSPACE: &str = "com.atproto.managedspace.policy";

/// The published policy record's collection (rkey `self`).
pub const POLICY_COLLECTION: &str = "com.atproto.space.policy";
const POLICY_RKEY: &str = "self";
/// The published member records' collection (rkey = the member's DID).
pub const MEMBER_COLLECTION: &str = "com.atproto.memberspace.member";

/// The collections only this module's builders write, in any repo.
pub const PUBLISHED_COLLECTIONS: [&str; 2] = [POLICY_COLLECTION, MEMBER_COLLECTION];

/// A space's policy, normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpacePolicy {
    /// Only the authority (and the apps it authorizes) reads or writes.
    Personal,
    /// Access by member list, optionally opened to the public.
    Member(MemberPolicy),
    /// Access decided per call by an external managing app (`checkAccess`).
    Managed(ManagedPolicy),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberPolicy {
    pub public_read: bool,
    pub public_write: bool,
    /// `None` admits any app; `Some(vec![])` admits none.
    pub allowed_apps: Option<Vec<String>>,
    pub publish_policy: bool,
    pub publish_members: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedPolicy {
    /// The managing app's `did#serviceId` reference.
    pub managing_app: String,
    pub publish_policy: bool,
}

/// One member's access bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Access {
    pub read: bool,
    pub write: bool,
}

impl SpacePolicy {
    /// Normalize a policy that arrived on the wire (the lexicon layer has already type-checked
    /// the fields of any known `$type`).
    ///
    /// `managingApp` must be a `did#serviceId` reference, as the reference requires: a value no
    /// resolution can turn into an endpoint would refuse every request forever.
    pub fn from_lex(value: &Value) -> Result<Self, ApiError> {
        let policy = Self::parse(value)?;
        if let SpacePolicy::Managed(managed) = &policy {
            if !is_did_service_ref(&managed.managing_app) {
                return Err(ApiError::new(
                    ErrorCode::InvalidRequest,
                    format!(
                        "managingApp must be a did#serviceId reference, got: {}",
                        managed.managing_app
                    ),
                ));
            }
        }
        Ok(policy)
    }

    /// Read a policy back from the `spaces.policy` column. Stored rows were normalized on write,
    /// except a managing app V079 carried over from the old config, which may lack a fragment
    /// (`check_access` falls back to `#atproto_pds` for it).
    pub fn from_stored(json: &str) -> Result<Self, ApiError> {
        let value: Value = serde_json::from_str(json).map_err(|e| {
            ApiError::internal_as(
                e,
                "stored space policy is not JSON",
                "internal server error",
            )
        })?;
        Self::parse(&value)
    }

    fn parse(value: &Value) -> Result<Self, ApiError> {
        let flag = |name: &str| value.get(name).and_then(Value::as_bool).unwrap_or(false);
        match value.get("$type").and_then(Value::as_str).unwrap_or("") {
            PERSONALSPACE => Ok(SpacePolicy::Personal),
            MEMBERSPACE => Ok(SpacePolicy::Member(MemberPolicy {
                public_read: flag("publicRead"),
                public_write: flag("publicWrite"),
                allowed_apps: value
                    .get("allowedApps")
                    .and_then(Value::as_array)
                    .map(|apps| {
                        apps.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    }),
                publish_policy: flag("publishPolicy"),
                publish_members: flag("publishMembers"),
            })),
            MANAGEDSPACE => Ok(SpacePolicy::Managed(ManagedPolicy {
                managing_app: value
                    .get("managingApp")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                publish_policy: flag("publishPolicy"),
            })),
            other => Err(ApiError::new(
                ErrorCode::UnsupportedPolicy,
                format!("Unsupported policy: {other}"),
            )),
        }
    }

    /// The normalized lexicon JSON, `$type` included — what is stored and served.
    pub fn to_json(&self) -> Value {
        match self {
            SpacePolicy::Personal => json!({ "$type": PERSONALSPACE }),
            SpacePolicy::Member(m) => {
                let mut body = json!({
                    "$type": MEMBERSPACE,
                    "publicRead": m.public_read,
                    "publicWrite": m.public_write,
                    "publishPolicy": m.publish_policy,
                    "publishMembers": m.publish_members,
                });
                if let Some(apps) = &m.allowed_apps {
                    body["allowedApps"] = json!(apps);
                }
                body
            }
            SpacePolicy::Managed(m) => json!({
                "$type": MANAGEDSPACE,
                "managingApp": m.managing_app,
                "publishPolicy": m.publish_policy,
            }),
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            SpacePolicy::Personal => PERSONALSPACE,
            SpacePolicy::Member(_) => MEMBERSPACE,
            SpacePolicy::Managed(_) => MANAGEDSPACE,
        }
    }

    /// The member list and the methods that manage it belong to memberspace.
    pub fn require_memberspace(&self) -> Result<&MemberPolicy, ApiError> {
        match self {
            SpacePolicy::Member(m) => Ok(m),
            _ => Err(ApiError::new(
                ErrorCode::PolicyMismatch,
                "Space is not governed by the memberspace policy",
            )),
        }
    }

    fn policy_published(&self) -> bool {
        match self {
            SpacePolicy::Personal => false,
            SpacePolicy::Member(m) => m.publish_policy,
            SpacePolicy::Managed(m) => m.publish_policy,
        }
    }

    fn members_published(&self) -> bool {
        matches!(self, SpacePolicy::Member(m) if m.publish_members)
    }

    /// The app perimeter. Only memberspace restricts apps, matched against the *attested*
    /// client_id, so an app presenting no attestation is never one of the allowed apps.
    pub fn app_authorized(&self, client_id: Option<&str>) -> bool {
        match self {
            SpacePolicy::Member(MemberPolicy {
                allowed_apps: Some(apps),
                ..
            }) => client_id.is_some_and(|id| apps.iter().any(|app| app == id)),
            _ => true,
        }
    }
}

/// A `did#serviceId` reference: a valid DID, `#`, and a non-empty fragment.
fn is_did_service_ref(value: &str) -> bool {
    value.split_once('#').is_some_and(|(did, fragment)| {
        !fragment.is_empty() && custos_core::identity::did::is_valid_did(did)
    })
}

// ── Publishing ───────────────────────────────────────────────────────────────

/// A member's DID as a record key. A record key cannot contain `%`, so a localhost did:web's
/// percent-encoded port is left unencoded (the reference's `didToRecordKey`).
fn did_record_key(did: &str) -> String {
    did.replace("%3A", ":")
}

/// Publish, update, or withdraw the policy record to match `policy`.
pub async fn policy_record_ops(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    space: &SpaceRef,
    policy: &SpacePolicy,
) -> Result<Vec<SpaceWriteOp>, ApiError> {
    if policy.policy_published() {
        let record = json!({ "$type": POLICY_COLLECTION, "policy": policy.to_json() });
        return Ok(vec![put(
            POLICY_COLLECTION,
            POLICY_RKEY.to_string(),
            record,
        )]);
    }
    delete_if_exists(tx, space, POLICY_COLLECTION, POLICY_RKEY.to_string()).await
}

/// Publish, update, or withdraw one member's record to match their entry in the member list;
/// `access` is `None` for a DID that is no longer a member.
pub async fn member_record_ops(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    space: &SpaceRef,
    policy: &SpacePolicy,
    did: &str,
    access: Option<Access>,
) -> Result<Vec<SpaceWriteOp>, ApiError> {
    let rkey = did_record_key(did);
    match access {
        Some(access) if policy.members_published() => {
            let record = json!({
                "$type": MEMBER_COLLECTION,
                "read": access.read,
                "write": access.write,
            });
            Ok(vec![put(MEMBER_COLLECTION, rkey, record)])
        }
        _ => delete_if_exists(tx, space, MEMBER_COLLECTION, rkey).await,
    }
}

/// Publish or withdraw the whole member list when a policy change flips whether it is published.
pub async fn member_list_ops(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    space: &SpaceRef,
    current: &SpacePolicy,
    next: &SpacePolicy,
) -> Result<Vec<SpaceWriteOp>, ApiError> {
    if current.members_published() == next.members_published() {
        return Ok(Vec::new());
    }
    let members = crate::db::spaces::all_members(&mut **tx, &space.uri)
        .await
        .map_err(db_error)?;
    let mut ops = Vec::new();
    for member in members {
        let access = Access {
            read: member.can_read,
            write: member.can_write,
        };
        ops.extend(member_record_ops(tx, space, next, &member.member_did, Some(access)).await?);
    }
    Ok(ops)
}

/// Land the published-record `ops` in the authority's repo inside `tx` (the configuration
/// change's transaction), commit it, then fire the commit's notification fan-out.
pub async fn commit_with_published(
    state: &custos_core::CoreState,
    mut tx: sqlx::Transaction<'_, Sqlite>,
    space: &SpaceRef,
    ops: &[SpaceWriteOp],
) -> Result<(), ApiError> {
    let pending = crate::space_record_write::apply_space_writes_in_tx(
        state,
        &mut tx,
        space,
        &space.authority,
        ops,
    )
    .await?;
    tx.commit().await.map_err(|e| {
        ApiError::internal_as(
            e,
            "failed to commit space configuration",
            "internal server error",
        )
    })?;
    if let Some(pending) = pending {
        pending.announce(state);
    }
    Ok(())
}

fn put(collection: &str, rkey: String, record: Value) -> SpaceWriteOp {
    SpaceWriteOp {
        action: SpaceWriteAction::Put,
        collection: collection.to_string(),
        rkey,
        value: Some(record),
    }
}

async fn delete_if_exists(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    space: &SpaceRef,
    collection: &str,
    rkey: String,
) -> Result<Vec<SpaceWriteOp>, ApiError> {
    let exists = crate::db::space_repos::get_record(
        &mut **tx,
        &space.uri,
        &space.authority,
        collection,
        &rkey,
    )
    .await
    .map_err(db_error)?
    .is_some();
    Ok(if exists {
        vec![SpaceWriteOp {
            action: SpaceWriteAction::Delete,
            collection: collection.to_string(),
            rkey,
            value: None,
        }]
    } else {
        Vec::new()
    })
}

fn db_error(e: sqlx::Error) -> ApiError {
    ApiError::internal_as(e, "failed to read space state", "internal server error")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_fills_defaults_and_drops_unknown_fields() {
        let policy = SpacePolicy::from_lex(&json!({
            "$type": MEMBERSPACE,
            "publicRead": true,
            "somethingNew": 1,
        }))
        .unwrap();
        assert_eq!(
            policy.to_json(),
            json!({
                "$type": MEMBERSPACE,
                "publicRead": true,
                "publicWrite": false,
                "publishPolicy": false,
                "publishMembers": false,
            })
        );
        assert_eq!(
            SpacePolicy::from_lex(&json!({ "$type": PERSONALSPACE, "x": 1 }))
                .unwrap()
                .to_json(),
            json!({ "$type": PERSONALSPACE })
        );
        // The stored form reads back to the same policy.
        let stored = policy.to_json().to_string();
        assert_eq!(SpacePolicy::from_stored(&stored).unwrap(), policy);
    }

    #[test]
    fn unknown_types_and_bad_managing_apps_are_refused() {
        let err = SpacePolicy::from_lex(&json!({ "$type": "com.example.policy" })).unwrap_err();
        assert_eq!(*err.code(), ErrorCode::UnsupportedPolicy);
        for app in ["did:web:app.example", "did:web:app.example#", "not-a-did#x"] {
            let err = SpacePolicy::from_lex(&json!({ "$type": MANAGEDSPACE, "managingApp": app }))
                .unwrap_err();
            assert_eq!(*err.code(), ErrorCode::InvalidRequest, "{app}");
        }
        assert!(SpacePolicy::from_lex(
            &json!({ "$type": MANAGEDSPACE, "managingApp": "did:web:app.example#forum" })
        )
        .is_ok());
    }

    #[test]
    fn only_memberspace_restricts_apps_and_absent_means_any() {
        let member = |apps: Option<Vec<&str>>| {
            SpacePolicy::Member(MemberPolicy {
                public_read: false,
                public_write: false,
                allowed_apps: apps.map(|a| a.into_iter().map(str::to_string).collect()),
                publish_policy: false,
                publish_members: false,
            })
        };
        assert!(member(None).app_authorized(None));
        assert!(!member(Some(vec![])).app_authorized(Some("https://a")));
        assert!(member(Some(vec!["https://a"])).app_authorized(Some("https://a")));
        assert!(!member(Some(vec!["https://a"])).app_authorized(None));
        assert!(SpacePolicy::Personal.app_authorized(None));
        assert_eq!(
            *SpacePolicy::Personal
                .require_memberspace()
                .unwrap_err()
                .code(),
            ErrorCode::PolicyMismatch
        );
    }

    #[test]
    fn member_record_keys_unencode_a_localhost_port() {
        assert_eq!(
            did_record_key("did:web:localhost%3A2583"),
            "did:web:localhost:2583"
        );
        assert_eq!(did_record_key("did:plc:abc"), "did:plc:abc");
    }
}
