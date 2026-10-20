// pattern: Functional Core
//
// The multi-relay pairing document: which relays this device is paired to, and which
// one unqualified operator actions (claim-code mint, self-revoke) target.
// Pure data and invariant-preserving operations only — Keychain persistence lives in
// `keychain::{load_pairings, save_pairings}`, and id generation (UUID) stays with the
// imperative callers in `relay_client`, so every function here is deterministic.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Storage-format version pinned into every persisted document. A future format change
/// bumps this and ships an explicit migration; an unknown version is a load error, never
/// a silent reset (see `keychain::load_pairings`).
pub const PAIRING_DOC_VERSION: u32 = 1;

/// One published notification sender key, as the relay's
/// `GET /v1/admin/notifications/sender-keys` reports it and as it is pinned per pairing.
/// Mirrors the server's wire element exactly, so the response deserializes straight into
/// what gets stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SenderKey {
    /// The instance-scoped key id a sealed payload's envelope names.
    pub kid: i64,
    /// The P-256 `did:key` to verify the seal against.
    pub public_key: String,
}

/// A single relay pairing: the relay this device registered with, the id the relay
/// assigned, the label sent at registration, and the operator-chosen nickname.
///
/// `id` is a locally generated UUID and is the stable handle for every operation —
/// relay-assigned `device_id`s change on re-pair and relay URLs can repeat, so neither
/// is an identity. Serializes camelCase for both the keychain JSON document and IPC.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pairing {
    pub id: String,
    pub nickname: String,
    pub relay_url: String,
    pub device_id: String,
    pub device_label: String,
    /// This relay's pinned notification sender keys — the set sealed operator alerts are
    /// verified against. A compatible addition (serde default, doc version stays 1): a
    /// document written before this field loads as "nothing pinned yet", and the field is
    /// omitted while empty so such documents also round-trip byte-identically. Refreshed
    /// on contact via `relay_client::refresh_sender_keys`; pinned per pairing because
    /// `kid` is an autoincrement column on ONE instance.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notification_sender_keys: Vec<SenderKey>,
    /// Fields written by a build newer than this one, preserved verbatim across
    /// load → mutate → save so running an older build never silently strips a future
    /// compatible addition from the document.
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl Pairing {
    /// A fresh pairing: nothing pinned yet, no fields from a newer build.
    pub fn new(
        id: impl Into<String>,
        nickname: impl Into<String>,
        relay_url: impl Into<String>,
        device_id: impl Into<String>,
        device_label: impl Into<String>,
    ) -> Self {
        Pairing {
            id: id.into(),
            nickname: nickname.into(),
            relay_url: relay_url.into(),
            device_id: device_id.into(),
            device_label: device_label.into(),
            notification_sender_keys: Vec::new(),
            extra: serde_json::Map::new(),
        }
    }
}

/// Returned by id-addressed operations when no pairing has the given id. Mapped to the
/// `NO_SUCH_PAIRING` IPC error code at the relay-client boundary.
#[derive(Debug, PartialEq, Eq)]
pub struct NoSuchPairing;

/// The versioned pairing document persisted as one keychain item.
///
/// Invariant: `active` is always the id of an entry in `pairings`, or `None` (and it is
/// always `None` when the list is empty). All mutation goes through methods that
/// preserve the invariant; the fields stay private so a caller can never construct or
/// edit a document that violates it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingDoc {
    version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active: Option<String>,
    pairings: Vec<Pairing>,
    /// Document-level fields from a newer build, preserved like `Pairing::extra`.
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    extra: serde_json::Map<String, serde_json::Value>,
}

impl PairingDoc {
    /// The document a device has before it ever pairs: current version, no entries.
    pub fn empty() -> Self {
        PairingDoc {
            version: PAIRING_DOC_VERSION,
            active: None,
            pairings: Vec::new(),
            extra: serde_json::Map::new(),
        }
    }

    /// All pairings, in insertion (pairing) order.
    #[allow(dead_code)]
    pub fn pairings(&self) -> &[Pairing] {
        &self.pairings
    }

    /// The id of the active pairing, if one is selected.
    #[allow(dead_code)]
    pub fn active_id(&self) -> Option<&str> {
        self.active.as_deref()
    }

    /// The active pairing itself, if one is selected.
    pub fn active_pairing(&self) -> Option<&Pairing> {
        self.active.as_deref().and_then(|id| self.get(id))
    }

    /// Look up a pairing by its local id.
    pub fn get(&self, id: &str) -> Option<&Pairing> {
        self.pairings.iter().find(|p| p.id == id)
    }

    /// Append a pairing and make it the active one. Duplicate relay URLs are allowed by
    /// design (re-pairing a relay appends a distinct entry); duplicate ids are not —
    /// callers generate a fresh UUID per pairing.
    pub fn append(&mut self, pairing: Pairing) {
        self.active = Some(pairing.id.clone());
        self.pairings.push(pairing);
    }

    /// Select the pairing that unqualified operator actions target. Unknown ids leave
    /// the current selection untouched.
    pub fn set_active(&mut self, id: &str) -> Result<(), NoSuchPairing> {
        if self.get(id).is_none() {
            return Err(NoSuchPairing);
        }
        self.active = Some(id.to_string());
        Ok(())
    }

    /// Replace one pairing's pinned notification sender-key set wholesale.
    ///
    /// Wholesale replacement IS the retire/revoke mechanism: the relay's published set is
    /// the truth, and whatever it no longer publishes must stop verifying here.
    pub fn set_notification_sender_keys(
        &mut self,
        id: &str,
        keys: Vec<SenderKey>,
    ) -> Result<(), NoSuchPairing> {
        let pairing = self
            .pairings
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or(NoSuchPairing)?;
        pairing.notification_sender_keys = keys;
        Ok(())
    }

    /// Update a pairing's operator-chosen nickname. Local-only: nicknames are display
    /// names and never leave the device.
    pub fn rename(&mut self, id: &str, nickname: &str) -> Result<(), NoSuchPairing> {
        let pairing = self
            .pairings
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or(NoSuchPairing)?;
        pairing.nickname = nickname.to_string();
        Ok(())
    }

    /// Remove a pairing, returning it. A sole remaining pairing is always auto-promoted
    /// to active (the choice is unambiguous — even when the selection was already cleared
    /// by an earlier ambiguous removal); when the *active* entry is removed with two or
    /// more remaining, `active` is cleared so the UI must ask for an explicit pick — the
    /// selection never silently lands on another relay.
    pub fn remove(&mut self, id: &str) -> Result<Pairing, NoSuchPairing> {
        let index = self
            .pairings
            .iter()
            .position(|p| p.id == id)
            .ok_or(NoSuchPairing)?;
        let removed = self.pairings.remove(index);
        if self.pairings.len() == 1 {
            self.active = Some(self.pairings[0].id.clone());
        } else if self.active.as_deref() == Some(id) {
            self.active = None;
        }
        Ok(removed)
    }

    /// Validate the invariants of a document that arrived from outside this module
    /// (i.e. was deserialized from the keychain): supported version, unique ids, and an
    /// `active` that references an existing entry. Returns a description of the first
    /// violation, suitable for a fail-loud keychain error.
    pub fn validate(&self) -> Result<(), String> {
        if self.version != PAIRING_DOC_VERSION {
            return Err(format!(
                "unsupported pairing document version {}",
                self.version
            ));
        }
        let mut seen = HashSet::new();
        for pairing in &self.pairings {
            if !seen.insert(pairing.id.as_str()) {
                return Err(format!("duplicate pairing id {}", pairing.id));
            }
        }
        if let Some(active) = self.active.as_deref() {
            if self.get(active).is_none() {
                return Err(format!("active pairing {active} not present in document"));
            }
        }
        Ok(())
    }
}

/// The IPC-facing view of the document: which pairing is active, and every pairing.
/// The storage `version` field stays internal to the keychain layer — the frontend
/// renders state, it never migrates formats.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingsState {
    pub active: Option<String>,
    pub pairings: Vec<Pairing>,
}

impl From<PairingDoc> for PairingsState {
    fn from(doc: PairingDoc) -> Self {
        PairingsState {
            active: doc.active,
            pairings: doc.pairings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairing(id: &str, nickname: &str, relay_url: &str) -> Pairing {
        Pairing::new(
            id,
            nickname,
            relay_url,
            format!("device-for-{id}"),
            "Operator iPhone",
        )
    }

    #[test]
    fn empty_doc_has_no_active_and_no_pairings() {
        let doc = PairingDoc::empty();
        assert_eq!(doc.pairings(), &[]);
        assert_eq!(doc.active_id(), None);
        assert_eq!(doc.active_pairing(), None);
    }

    #[test]
    fn append_makes_the_new_pairing_active_and_keeps_earlier_entries() {
        let mut doc = PairingDoc::empty();
        let pairing_a = pairing("id-a", "First", "https://relay-a.example");
        let pairing_b = pairing("id-b", "Second", "https://relay-b.example");

        doc.append(pairing_a.clone());
        doc.append(pairing_b.clone());

        let pairings = doc.pairings();
        assert_eq!(pairings.len(), 2);
        assert_eq!(pairings[0].id, "id-a");
        assert_eq!(pairings[0].nickname, "First");
        assert_eq!(pairings[0].relay_url, "https://relay-a.example");
        assert_eq!(pairings[0].device_id, "device-for-id-a");
        assert_eq!(pairings[0].device_label, "Operator iPhone");

        assert_eq!(pairings[1].id, "id-b");
        assert_eq!(pairings[1].nickname, "Second");
        assert_eq!(pairings[1].relay_url, "https://relay-b.example");
        assert_eq!(pairings[1].device_id, "device-for-id-b");
        assert_eq!(pairings[1].device_label, "Operator iPhone");

        assert_eq!(doc.active_id(), Some("id-b"));
        assert_eq!(doc.active_pairing().unwrap().id, "id-b");
    }

    #[test]
    fn append_allows_duplicate_relay_urls_under_distinct_ids() {
        let mut doc = PairingDoc::empty();
        let pairing_a = pairing("id-a", "First", "https://relay.example");
        let pairing_b = pairing("id-b", "Second", "https://relay.example");

        doc.append(pairing_a.clone());
        doc.append(pairing_b.clone());

        let pairings = doc.pairings();
        assert_eq!(pairings.len(), 2);
        assert_eq!(pairings[0].id, "id-a");
        assert_eq!(pairings[1].id, "id-b");
        assert_eq!(pairings[0].relay_url, pairings[1].relay_url);

        assert_eq!(doc.get("id-a").unwrap().id, "id-a");
        assert_eq!(doc.get("id-b").unwrap().id, "id-b");
        assert_eq!(doc.active_id(), Some("id-b"));
    }

    #[test]
    fn set_active_switches_selection() {
        let mut doc = PairingDoc::empty();
        doc.append(pairing("id-a", "First", "https://relay-a.example"));
        doc.append(pairing("id-b", "Second", "https://relay-b.example"));

        assert_eq!(doc.active_id(), Some("id-b"));
        doc.set_active("id-a").expect("set active");
        assert_eq!(doc.active_id(), Some("id-a"));
        assert_eq!(doc.active_pairing().unwrap().id, "id-a");
    }

    #[test]
    fn set_active_unknown_id_errors_and_leaves_selection_unchanged() {
        let mut doc = PairingDoc::empty();
        doc.append(pairing("id-a", "First", "https://relay-a.example"));

        let result = doc.set_active("nope");
        assert_eq!(result, Err(NoSuchPairing));
        assert_eq!(doc.active_id(), Some("id-a"));
    }

    #[test]
    fn rename_updates_nickname_and_nothing_else() {
        let mut doc = PairingDoc::empty();
        doc.append(pairing("id-a", "Original", "https://relay-a.example"));

        doc.rename("id-a", "Updated").expect("rename");
        let p = doc.get("id-a").unwrap();
        assert_eq!(p.nickname, "Updated");
        assert_eq!(p.id, "id-a");
        assert_eq!(p.relay_url, "https://relay-a.example");
        assert_eq!(p.device_id, "device-for-id-a");
        assert_eq!(p.device_label, "Operator iPhone");

        let result = doc.rename("unknown", "Nope");
        assert_eq!(result, Err(NoSuchPairing));
    }

    #[test]
    fn removing_the_active_pairing_with_one_remaining_auto_promotes() {
        let mut doc = PairingDoc::empty();
        doc.append(pairing("id-a", "First", "https://relay-a.example"));
        doc.append(pairing("id-b", "Second", "https://relay-b.example"));

        assert_eq!(doc.active_id(), Some("id-b"));
        doc.remove("id-b").expect("remove");
        assert_eq!(doc.active_id(), Some("id-a"));
        assert_eq!(doc.pairings().len(), 1);
    }

    #[test]
    fn removing_the_active_pairing_with_two_or_more_remaining_clears_active() {
        let mut doc = PairingDoc::empty();
        doc.append(pairing("id-a", "First", "https://relay-a.example"));
        doc.append(pairing("id-b", "Second", "https://relay-b.example"));
        doc.append(pairing("id-c", "Third", "https://relay-c.example"));

        assert_eq!(doc.active_id(), Some("id-c"));
        doc.remove("id-c").expect("remove");
        assert_eq!(doc.active_id(), None);
        assert_eq!(doc.pairings().len(), 2);
        assert_eq!(doc.get("id-a").unwrap().id, "id-a");
        assert_eq!(doc.get("id-b").unwrap().id, "id-b");
    }

    #[test]
    fn removing_down_to_one_promotes_even_when_selection_was_cleared() {
        let mut doc = PairingDoc::empty();
        doc.append(pairing("id-a", "First", "https://relay-a.example"));
        doc.append(pairing("id-b", "Second", "https://relay-b.example"));
        doc.append(pairing("id-c", "Third", "https://relay-c.example"));

        // Removing the active entry with two remaining clears the selection…
        doc.remove("id-c").expect("remove");
        assert_eq!(doc.active_id(), None);

        // …but removing down to a single survivor is unambiguous and promotes it.
        doc.remove("id-a").expect("remove");
        assert_eq!(doc.active_id(), Some("id-b"));
        assert_eq!(doc.pairings().len(), 1);
    }

    #[test]
    fn removing_a_non_active_pairing_keeps_the_selection() {
        let mut doc = PairingDoc::empty();
        doc.append(pairing("id-a", "First", "https://relay-a.example"));
        doc.append(pairing("id-b", "Second", "https://relay-b.example"));

        assert_eq!(doc.active_id(), Some("id-b"));
        doc.remove("id-a").expect("remove");
        assert_eq!(doc.active_id(), Some("id-b"));
        assert_eq!(doc.pairings().len(), 1);
    }

    #[test]
    fn removing_the_last_pairing_leaves_an_empty_doc() {
        let mut doc = PairingDoc::empty();
        doc.append(pairing("id-a", "First", "https://relay-a.example"));

        assert_eq!(doc.active_id(), Some("id-a"));
        doc.remove("id-a").expect("remove");
        assert_eq!(doc.pairings(), &[]);
        assert_eq!(doc.active_id(), None);
    }

    #[test]
    fn remove_unknown_id_errors_and_changes_nothing() {
        let mut doc = PairingDoc::empty();
        doc.append(pairing("id-a", "First", "https://relay-a.example"));

        let result = doc.remove("unknown");
        assert_eq!(result, Err(NoSuchPairing));
        assert_eq!(doc.pairings().len(), 1);
        assert_eq!(doc.active_id(), Some("id-a"));
    }

    #[test]
    fn document_serializes_camel_case_and_omits_absent_active() {
        let empty_doc = PairingDoc::empty();
        let value = serde_json::to_value(&empty_doc).expect("serialize");
        assert_eq!(value.get("version").unwrap(), 1);
        assert_eq!(value.get("pairings").unwrap(), &serde_json::json!([]));
        assert_eq!(value.get("active"), None);

        let mut doc_with_entry = PairingDoc::empty();
        doc_with_entry.append(pairing("id-a", "First", "https://relay-a.example"));
        let value = serde_json::to_value(&doc_with_entry).expect("serialize");
        let pairings = value.get("pairings").unwrap().as_array().unwrap();
        assert_eq!(pairings.len(), 1);

        let entry = &pairings[0];
        assert_eq!(entry.get("id").unwrap().as_str().unwrap(), "id-a");
        assert_eq!(entry.get("nickname").unwrap().as_str().unwrap(), "First");
        assert_eq!(
            entry.get("relayUrl").unwrap().as_str().unwrap(),
            "https://relay-a.example"
        );
        assert_eq!(
            entry.get("deviceId").unwrap().as_str().unwrap(),
            "device-for-id-a"
        );
        assert_eq!(
            entry.get("deviceLabel").unwrap().as_str().unwrap(),
            "Operator iPhone"
        );
    }

    #[test]
    fn document_round_trips_through_json() {
        let mut doc = PairingDoc::empty();
        doc.append(pairing("id-a", "First", "https://relay-a.example"));
        doc.append(pairing("id-b", "Second", "https://relay-b.example"));

        let bytes = serde_json::to_vec(&doc).expect("serialize");
        let restored: PairingDoc = serde_json::from_slice(&bytes).expect("deserialize");

        assert_eq!(doc, restored);
    }

    #[test]
    fn notification_sender_keys_round_trip_and_default_empty() {
        let mut doc = PairingDoc::empty();
        doc.append(pairing("id-a", "First", "https://relay-a.example"));
        doc.set_notification_sender_keys(
            "id-a",
            vec![
                SenderKey {
                    kid: 1,
                    public_key: "did:key:zOld".to_string(),
                },
                SenderKey {
                    kid: 2,
                    public_key: "did:key:zNew".to_string(),
                },
            ],
        )
        .expect("set keys");

        let bytes = serde_json::to_vec(&doc).expect("serialize");
        let restored: PairingDoc = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(doc, restored);
        assert_eq!(
            restored.get("id-a").unwrap().notification_sender_keys.len(),
            2
        );

        // The wire spelling is the camelCase [{kid, publicKey}] the relay serves.
        let value = serde_json::to_value(&doc).unwrap();
        assert_eq!(
            value["pairings"][0]["notificationSenderKeys"][0],
            serde_json::json!({"kid": 1, "publicKey": "did:key:zOld"})
        );

        // A pre-notification document (no field at all) loads as "nothing pinned yet"…
        let legacy = r#"{"version":1,"active":"id-a","pairings":[{"id":"id-a","nickname":"A","relayUrl":"https://a","deviceId":"d-a","deviceLabel":"L"}]}"#;
        let legacy_doc: PairingDoc = serde_json::from_str(legacy).expect("legacy parses");
        assert!(legacy_doc
            .get("id-a")
            .unwrap()
            .notification_sender_keys
            .is_empty());
        // …and re-saving it does not invent the field (empty is omitted).
        let resaved = serde_json::to_value(&legacy_doc).unwrap();
        assert!(resaved["pairings"][0]
            .get("notificationSenderKeys")
            .is_none());
    }

    #[test]
    fn set_notification_sender_keys_replaces_wholesale_and_checks_the_id() {
        let mut doc = PairingDoc::empty();
        doc.append(pairing("id-a", "First", "https://relay-a.example"));
        let key = |kid: i64| SenderKey {
            kid,
            public_key: format!("did:key:z{kid}"),
        };

        doc.set_notification_sender_keys("id-a", vec![key(1), key(2)])
            .expect("pin");
        // The relay revoked kid 1: whatever the server no longer publishes must stop
        // verifying here, so the replacement is wholesale.
        doc.set_notification_sender_keys("id-a", vec![key(2)])
            .expect("re-pin");
        assert_eq!(
            doc.get("id-a").unwrap().notification_sender_keys,
            vec![key(2)]
        );

        assert_eq!(
            doc.set_notification_sender_keys("nope", vec![key(3)]),
            Err(NoSuchPairing)
        );
    }

    #[test]
    fn unknown_fields_from_a_newer_build_survive_a_round_trip() {
        // A document written by a future build carries fields this build doesn't know, at
        // both the document and the pairing level. Loading, mutating, and saving with THIS
        // build must preserve them — an app downgrade must never strip a compatible addition.
        let future = r#"{"version":1,"futureDocField":{"a":1},"pairings":[{"id":"id-a","nickname":"A","relayUrl":"https://a","deviceId":"d-a","deviceLabel":"L","futurePairingField":"kept"}]}"#;
        let mut doc: PairingDoc = serde_json::from_str(future).expect("parses");
        doc.validate().expect("valid");
        doc.rename("id-a", "Renamed").expect("mutate");

        let resaved = serde_json::to_value(&doc).expect("serialize");
        assert_eq!(resaved["futureDocField"], serde_json::json!({"a": 1}));
        assert_eq!(resaved["pairings"][0]["futurePairingField"], "kept");
        assert_eq!(resaved["pairings"][0]["nickname"], "Renamed");
    }

    #[test]
    fn validate_rejects_unsupported_version() {
        let json = r#"{"version":2,"pairings":[]}"#;
        let doc: PairingDoc = serde_json::from_str(json).expect("deserialize");
        let result = doc.validate();
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("version 2"));
    }

    #[test]
    fn validate_rejects_dangling_active_reference() {
        let json = r#"{"version":1,"active":"missing-id","pairings":[]}"#;
        let doc: PairingDoc = serde_json::from_str(json).expect("deserialize");
        let result = doc.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("active pairing"));
    }

    #[test]
    fn validate_rejects_duplicate_ids() {
        let json = r#"{"version":1,"pairings":[{"id":"same","nickname":"A","relayUrl":"https://a","deviceId":"d-a","deviceLabel":"L"},{"id":"same","nickname":"B","relayUrl":"https://b","deviceId":"d-b","deviceLabel":"L"}]}"#;
        let doc: PairingDoc = serde_json::from_str(json).expect("deserialize");
        let result = doc.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("duplicate pairing id"));
    }
}
